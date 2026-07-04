/*
 * DarkChain - DKIM2-core Inbound Verifier Milter
 *
 * Implements the inbound verification side of the DKIM2-core profile
 * as defined in draft-moccia-dkim2-deployment-profile.
 *
 * Based on DarkARC by Vittorio Moccia / ITB.it
 *
 * Copyright (c) 2026 Vittorio Moccia / ITB.it
 * Licensed under Apache 2.0 License.
 *
 * ================================================================
 * OPERATING MODE: TRANSITION (log-only)
 * ================================================================
 *
 * This milter currently operates in TRANSITION mode (Phase 2 per
 * draft-moccia-dkim2-deployment-profile §3.6):
 *
 *   - All verification results are logged and injected as
 *     Authentication-Results headers
 *   - No message is ever rejected (always SMFIS_CONTINUE)
 *   - The X-DarkChain-Internal-Status header provides timing
 *     and diagnostic information
 *
 * To switch to ENFORCEMENT mode (Phase 3), the following changes
 * are required — each marked in the code with [ENFORCEMENT]:
 *
 *   1. dc_eom(): return SMFIS_REJECT on dkim2=fail/permerror,
 *      SMFIS_TEMPFAIL on dkim2=temperror.  Per draft §3.5.1,
 *      the 5xx rejection is directed at the connected peer (the
 *      system delivering over this SMTP session), never at the
 *      original envelope sender.  This prevents backscatter.
 *
 *   2. dc_header(): the 128KB DKIM2 header cap (draft §3.2.3)
 *      currently sets chain_broken and continues.  In enforcement
 *      mode this MUST return SMFIS_REJECT immediately without
 *      waiting for dc_eom().
 *
 *   3. dc_eoh(): chain continuity errors (missing DKIM2-Signature
 *      or DKIM2-Sig-mf at a required hop) currently set
 *      chain_broken.  In enforcement mode these SHOULD return
 *      SMFIS_REJECT immediately to avoid processing the body
 *      of a message that will be rejected anyway.
 *
 * FUTURE EVOLUTION:
 *
 *   - Multi-algorithm verification: draft §3.5.3 requires that
 *     if a hop carries signatures with multiple algorithms, ALL
 *     must verify — partial pass is treated as failure.  Current
 *     implementation handles one signature per hop.
 *     See [MULTI-ALGO] markers in the code.
 *
 *   - DNS key h= tag: retired in draft-chuang-dkim2-dns-04.
 *     dc_check_dns_key_hash() kept as dead code.
 *
 *   - Outbound signer: DarkChains (companion milter).
 * ================================================================
 */

#include "../dc_shared.h"
#include <resolv.h>
#include <netdb.h>

/* ================================================================
 * CONFIGURATION
 * ================================================================ */

#define OCONN           "unix:/var/spool/DarkChain/sock"
#define USER            "smmsp"
#define LOGLEVEL        LOG_ERR
#define SYSLOG_FACILITY LOG_DAEMON
#define DEBUG           0
#define ENFORCE         0        /* 0=log only, 1=reject fail/permerror */

/* Header hash exclusion config path */
#define DC_HH_EXCLUDE_CONF  "/etc/DarkChain/hh_exclude.conf"

/* Domain table: the verifier only needs to know which domains are
 * DKIM2-enabled on this host, so it can decide whether to inject a
 * DKIM2-Authentication-Results record. It does NOT need the private keys
 * (it never signs), so it loads only the domain names. The conf file is
 * shared with the signer; a symlink
 *   /etc/DarkChain/domains.conf -> /etc/DarkChains/domains.conf
 * keeps a single source of truth. */
#define DC_DOMAINS_CONF     "/etc/DarkChain/domains.conf"
#define DC_MAX_DOMAINS      64

/* Envelope storage */
#define DC_MAX_RCPT         500     /* Max RCPT TO — aligned with DC_MAX_RT  */

/* ================================================================
 * DATA STRUCTURES (verifier-specific)
 * ================================================================ */

/*
 * context — per-connection private data, set via smfi_setpriv().
 */
struct context
{
   /* --- Connection-level (survive RSET) --- */
   int msg_count;

   /* --- Timing --- */
   struct timespec start_time;
   unsigned long long cpu_ns;
   unsigned long long dns_ns;

   /* --- Header reservoir --- */
   struct header_slot *headers;
   int  header_cnt;
   int  header_capacity;

   /* --- DKIM2 chain state --- */
   int  max_hop;                /* Highest i= seen across all DKIM2 headers */
   int  chain_broken;           /* Flag: structural error detected at parse */

   /* --- Envelope (captured from SMTP session) --- */
   struct dc_envelope envelope;

   /* --- Body hashing (relaxed only) --- */
   EVP_MD_CTX *mdctx_body;
   long long body_size;   /* long long: int would overflow past 2GB */
   int  pending_newlines;
   int  body_has_content;
   int  p_had_space;
   int  is_start_of_line;

   /* --- Header hashing (used in dc_eom for signature verify) --- */
   EVP_MD_CTX *mdctx_header;

   /* --- Verification results (set in dc_eom) --- */
   int  body_integrity;
   int  header_vfy;
   int  envelope_vfy;
   int  chain_vfy;

   /* --- Localhost detection --- */
   int  is_localhost;
   char helo[MAXHOST];

   /* --- DoS: total bytes of DKIM2-specific headers (128KB cap) --- */
   size_t dkim2_header_bytes;

   /* --- Rollback scratch (DC_MAX_SEQ slots) — allocated once per
    *     connection in dc_connect(), reused for every message, freed in
    *     dc_close().  Keeps ~128KB off the stack of dc_rollback_hh(). --- */
   struct header_slot *rb_scratch;
};


/* ================================================================
 * HOP INDEX — built once per verification in dc_eom()
 * ================================================================ */

struct dc_hop_index
{
   struct header_slot *sig;

   struct header_slot *mf;
   struct header_slot *rt[DC_MAX_RT];
   int rt_count;

   struct header_slot *prev_sig[DC_MAX_HOPS];
   int prev_sig_count;

   struct header_slot *mod[DC_MAX_MOD];
   int mod_count;
};


/* ================================================================
 * GLOBAL CONFIGURATION
 * ================================================================ */

const char *pc_oconn = OCONN;
const char *pc_user  = USER;
char  my_hostname[256] = "";

/* ================================================================
 * DOMAIN TABLE (verifier: names only, no keys)
 * ================================================================ */

static char dc_domains[DC_MAX_DOMAINS][256];
static int  dc_domain_count = 0;

/* Load DKIM2-enabled domain names from the shared domains.conf.
 * Line format matches the signer: "domain selector keypath"; we keep
 * only the first field. Missing file is not fatal: a host with no
 * DKIM2 domains (e.g. a list-only domain) simply has an empty table,
 * and the verifier will then inject no DKIM2-AR. */
static int dc_load_domains(const char *conf_path)
{
   FILE *fp = fopen(conf_path, "r");
   if (!fp)
   {
      syslog(LOG_INFO, "DC_MAIN: no domain table at %s (%s) — "
             "DKIM2-AR injection disabled", conf_path, strerror(errno));
      dc_domain_count = 0;
      return 0;
   }

   char line[1024];
   dc_domain_count = 0;

   while (fgets(line, sizeof(line), fp) && dc_domain_count < DC_MAX_DOMAINS)
   {
      char *p = line;
      while (*p == ' ' || *p == '\t') p++;
      if (*p == '#' || *p == '\n' || *p == '\0') continue;

      char dom[256];
      if (sscanf(p, "%255s", dom) != 1) continue;

      securecpy(dc_domains[dc_domain_count], dom, 256);
      syslog(LOG_INFO, "DC_MAIN: DKIM2-enabled domain: %s", dom);
      dc_domain_count++;
   }
   fclose(fp);
   return dc_domain_count;
}

/* Return 1 if the domain of addr is DKIM2-enabled on this host, else 0.
 * Match is exact first, then relaxed (up to 2 leading labels removed),
 * mirroring the signer's lookup_domain_key. */
static int dc_domain_enabled(const char *addr)
{
   if (!addr || !*addr || dc_domain_count == 0) return 0;
   const char *at = strchr(addr, '@');
   const char *domain = at ? at + 1 : addr;

   for (int i = 0; i < dc_domain_count; i++)
      if (strcasecmp(domain, dc_domains[i]) == 0)
         return 1;

   const char *p = domain;
   for (int removed = 0; removed < 2; removed++)
   {
      p = strchr(p, '.');
      if (!p) break;
      p++;
      for (int i = 0; i < dc_domain_count; i++)
         if (strcasecmp(p, dc_domains[i]) == 0)
            return 1;
   }
   return 0;
}


/* ================================================================
 * CALLBACK DECLARATIONS
 * ================================================================ */

static sfsistat dc_connect(SMFICTX *, char *, _SOCK_ADDR *);
static sfsistat dc_helo(SMFICTX *, char *);
static sfsistat dc_envfrom(SMFICTX *, char **);
static sfsistat dc_envrcpt(SMFICTX *, char **);
static sfsistat dc_header(SMFICTX *, char *, char *);
static sfsistat dc_eoh(SMFICTX *);
static sfsistat dc_body(SMFICTX *, u_char *, size_t);
static sfsistat dc_eom(SMFICTX *);
static sfsistat dc_abort(SMFICTX *);
static sfsistat dc_close(SMFICTX *);
static sfsistat dc_negotiate(SMFICTX *,
   unsigned long, unsigned long, unsigned long, unsigned long,
   unsigned long *, unsigned long *, unsigned long *, unsigned long *);
static void dc_cleanup_message(struct context *priv);
static void dc_usage(const char *prog);
void cleanup_and_exit(int sig);


/* ================================================================
 * MILTER DESCRIPTOR
 * ================================================================ */

struct smfiDesc chainmilter = {
   "DarkChain",
   SMFI_VERSION,
   SMFIF_ADDHDRS | SMFIF_CHGHDRS,
   dc_connect,
   dc_helo,
   dc_envfrom,
   dc_envrcpt,
   dc_header,
   dc_eoh,
   dc_body,
   dc_eom,
   dc_abort,
   dc_close,
   NULL,                        /* xxfi_unknown */
   NULL,                        /* xxfi_data    */
   dc_negotiate
};


/* ================================================================
 * DEAD CODE — DNS key h= tag check
 *
 * Per Murray's clarification at IETF 125: the h= tag in DNS key
 * records announces which hashes are approved for use with that key.
 * Wei Chuang retired h=, n=, s= tags in draft-chuang-dkim2-dns-04.
 * Kept for reference.
 * ================================================================ */

static int dc_check_dns_key_hash(const char *d, const char *s, const char *sig_algo)
{
   char query[512];
   unsigned char answer[BIG_BUFFER];
   int len;

   snprintf(query, sizeof(query), "%s._domainkey.%s", s, d);
   len = res_query(query, C_IN, T_TXT, answer, sizeof(answer));
   if (len < 0) return -1;

   ns_msg msg;
   if (ns_initparse(answer, len, &msg) < 0) return -1;
   ns_rr rr;

   for (int i = 0; i < ns_msg_count(msg, ns_s_an); i++)
   {
      if (ns_parserr(&msg, ns_s_an, i, &rr) == 0 && ns_rr_type(rr) == T_TXT)
      {
         const unsigned char *txt = ns_rr_rdata(rr);
         int rdlen = ns_rr_rdlen(rr);

         if (txt && rdlen > 0)
         {
            char full_record[2048] = {0};
            int pos = 0;
            const unsigned char *curr = txt;

            while (curr < txt + rdlen)
            {
               int segment_len = *curr;
               if (pos + segment_len < (int)sizeof(full_record) - 1)
               {
                  memcpy(full_record + pos, curr + 1, segment_len);
                  pos += segment_len;
               }
               curr += segment_len + 1;
            }
            full_record[pos] = '\0';

            char h_tag[128] = "";
            dc_get_tag_str(full_record, "h", h_tag, sizeof(h_tag));

            if (h_tag[0] == '\0')
               return 1; /* h= absent → all algorithms allowed */

            const char *hash_name = NULL;
            if (strstr(sig_algo, "sha256") || sig_algo[0] == '\0')
               hash_name = "sha256";
            else if (strstr(sig_algo, "sha512"))
               hash_name = "sha512";
            else if (strstr(sig_algo, "ed25519"))
               hash_name = "sha256";

            if (!hash_name)
               return 0;

            char h_work[128];
            securecpy(h_work, h_tag, sizeof(h_work));
            char *saveptr = NULL;
            char *token = strtok_r(h_work, ":", &saveptr);
            while (token)
            {
               while (*token == ' ' || *token == '\t') token++;
               if (strcasecmp(token, hash_name) == 0)
                  return 1;
               token = strtok_r(NULL, ":", &saveptr);
            }

            syslog(LOG_NOTICE, "DC_CHECK_DNS_KEY_HASH: DNS key h= tag does not include %s "
                   "(h=%s, key=%s)", hash_name, h_tag, query);
            return 0;
         }
      }
   }

   return -1;
}


/* ================================================================
 * ROLLBACK HH
 * ================================================================ */

/*
 * Rollback DKIM2-Mod at a given hop and compute hh= of the
 * previous state.
 *
 * Applied in REVERSE seq= order (highest seq first) because
 * modifications were applied in ascending order.
 *
 * Returns malloc'd base64 string, or NULL on error. Caller frees.
 */
static char *dc_rollback_hh(struct header_slot *headers, int header_cnt, int hop,
                            struct header_slot *rb_scratch)
{
   /* Off-stack: one instance per worker thread. */
   static __thread struct header_slot *work[MAX_HEADER_COUNT];
   int work_cnt = 0;

   for (int j = 0; j < header_cnt && work_cnt < MAX_HEADER_COUNT; j++)
   {
      if (headers[j].name[0] == '\0') continue;
      if (dc_is_hh_excluded(headers[j].name)) continue;
      work[work_cnt++] = &headers[j];
   }

   /* Find max seq= among Mods at this hop */
   int max_seq = 0;
   for (int j = 0; j < header_cnt; j++)
   {
      if (headers[j].dc_type == DC_HDR_MOD && headers[j].hop == hop)
         if (headers[j].seq > max_seq)
            max_seq = headers[j].seq;
   }

   struct header_slot *rb_slots = rb_scratch;
   int rb_count = 0;
   if (!rb_slots) return NULL;
   memset(rb_slots, 0, DC_MAX_SEQ * sizeof(struct header_slot));

   /* Process in REVERSE seq= order */
   for (int seq = max_seq; seq >= 1; seq--)
   {
      int has_new = 0, has_del = 0;
      struct header_slot *mod_new_fr1 = NULL;
      struct header_slot *mod_del_fr1 = NULL;

      for (int j = 0; j < header_cnt; j++)
      {
         if (headers[j].dc_type != DC_HDR_MOD) continue;
         if (headers[j].hop != hop || headers[j].seq != seq) continue;

         if (headers[j].is_new == 1 && headers[j].fr == 1)
         {
            mod_new_fr1 = &headers[j];
            has_new = 1;
         }
         if (headers[j].is_new == 0 && headers[j].fr == 1)
         {
            mod_del_fr1 = &headers[j];
            has_del = 1;
         }
      }

      char mod_field[MAX_HEADER_NAME] = "";
      struct header_slot *anchor = mod_new_fr1 ? mod_new_fr1 : mod_del_fr1;
      if (!anchor) continue;

      const char *fld = dc_find_tag(anchor->value, "field");
      if (fld)
      {
         int fi = 0;
         while (*fld && *fld != ';' && *fld != ' ' && *fld != '\t'
                && fi < MAX_HEADER_NAME - 1)
            mod_field[fi++] = *fld++;
         mod_field[fi] = '\0';
      }
      if (mod_field[0] == '\0') continue;

      /* ROLLBACK new= → remove the added header from work[] */
      if (has_new && mod_new_fr1)
      {
         const char *nv = dc_find_tag(mod_new_fr1->value, "new");
         int removed = 0;
         if (nv)
         {
            if (*nv == '"') nv++;
            const char *nv_end = strrchr(nv, '"');
            if (!nv_end) nv_end = nv + strlen(nv);

            for (int w = 0; w < work_cnt; w++)
            {
               if (strcasecmp(work[w]->name, mod_field) != 0) continue;

               const char *hv = work[w]->value;
               while (*hv == ' ' || *hv == '\t') hv++;

               const char *np = nv;
               const char *hp = hv;
               int match = 1;
               while (np < nv_end)
               {
                  if (*hp == '\0' || *np != *hp) { match = 0; break; }
                  np++; hp++;
               }

               if (match)
               {
                  for (int k = w; k < work_cnt - 1; k++)
                     work[k] = work[k + 1];
                  work_cnt--;
                  removed = 1;
                  break;
               }
            }
         }
         if (!removed)
            syslog(LOG_WARNING,
                   "DC_ROLLBACK: Cannot find '%s' matching new= to remove "
                   "(i=%d seq=%d)", mod_field, hop, seq);
      }

      /* ROLLBACK del= → reconstruct old value and add it back */
      if (has_del && rb_count < DC_MAX_SEQ)
      {
         char rebuilt_val[BIG_HEADER_VALUE] = "";
         int rv_len = 0;

         for (int f = 1; f <= DC_MAX_FR; f++)
         {
            int found_frame = 0;
            for (int j = 0; j < header_cnt; j++)
            {
               if (headers[j].dc_type != DC_HDR_MOD) continue;
               if (headers[j].hop != hop) continue;
               if (headers[j].seq != seq) continue;
               if (headers[j].is_new != 0) continue;
               if (headers[j].fr != f) continue;

               const char *dv = dc_find_tag(headers[j].value, "del");
               if (!dv) break;

               int quoted = (*dv == '"');
               if (quoted) dv++;

               /* Find end: last " for quoted values, ; for unquoted */
               const char *dv_end;
               if (quoted)
               {
                  dv_end = strrchr(dv, '"');
                  if (!dv_end) dv_end = dv + strlen(dv);
               }
               else
               {
                  dv_end = strchr(dv, ';');
                  if (!dv_end) dv_end = dv + strlen(dv);
               }

               while (dv < dv_end && rv_len < BIG_HEADER_VALUE - 1)
               {
                  rebuilt_val[rv_len++] = *dv++;
               }
               rebuilt_val[rv_len] = '\0';
               found_frame = 1;
               break;
            }
            if (!found_frame) break;
         }

         if (rv_len > 0)
         {
            struct header_slot *rb = &rb_slots[rb_count];
            securecpy(rb->name, mod_field, MAX_HEADER_NAME);
            securecpy(rb->value, rebuilt_val, BIG_HEADER_VALUE);
            rb->dc_type = DC_HDR_OTHER;
            rb->hop = 0;
            rb->used_for_signature = 0;

            if (work_cnt < MAX_HEADER_COUNT)
               work[work_cnt++] = rb;

            rb_count++;
         }
      }
   }

   /* Sort the reconstructed set */
   if (work_cnt > 1)
      qsort(work, work_cnt, sizeof(struct header_slot *), cmp_header_hh);

   /* Reorder duplicate groups using DKIM2-Mod (for hops < target hop) */
   int grp_start = 0;
   while (grp_start < work_cnt)
   {
      int grp_end = grp_start + 1;
      while (grp_end < work_cnt &&
             strcasecmp(work[grp_start]->name, work[grp_end]->name) == 0)
         grp_end++;

      if (grp_end - grp_start > 1)
      {
         static __thread int sort_keys[MAX_HEADER_COUNT];
         for (int g = grp_start; g < grp_end; g++)
         {
            sort_keys[g] = 0;
            for (int m = 0; m < header_cnt; m++)
            {
               if (headers[m].dc_type != DC_HDR_MOD) continue;
               if (headers[m].is_new != 1) continue;
               if (headers[m].fr != 1) continue;
               if (headers[m].hop >= hop) continue;

               const char *mf = dc_find_tag(headers[m].value, "field");
               if (!mf) continue;
               char mfn[MAX_HEADER_NAME] = "";
               int fi = 0;
               while (*mf && *mf != ';' && *mf != ' ' && *mf != '\t'
                      && fi < MAX_HEADER_NAME - 1)
                  mfn[fi++] = *mf++;
               mfn[fi] = '\0';
               if (strcasecmp(mfn, work[g]->name) != 0) continue;

               const char *nv = dc_find_tag(headers[m].value, "new");
               if (!nv) continue;
               if (*nv == '"') nv++;
               const char *nv_end = strrchr(nv, '"');
               if (!nv_end) nv_end = nv + strlen(nv);

               const char *hv = work[g]->value;
               while (*hv == ' ' || *hv == '\t') hv++;

               int match = 1;
               const char *np = nv, *hp = hv;
               while (np < nv_end)
               {
                  if (*hp == '\0' || *np != *hp) { match = 0; break; }
                  np++; hp++;
               }
               if (match) { sort_keys[g] = headers[m].hop; break; }
            }
         }

         for (int i = grp_start; i < grp_end - 1; i++)
            for (int j = i + 1; j < grp_end; j++)
               if (sort_keys[j] < sort_keys[i])
               {
                  struct header_slot *tmp = work[i]; work[i] = work[j]; work[j] = tmp;
                  int tk = sort_keys[i]; sort_keys[i] = sort_keys[j]; sort_keys[j] = tk;
               }

         int zero_end = grp_start;
         while (zero_end < grp_end && sort_keys[zero_end] == 0)
            zero_end++;

         if (zero_end - grp_start > 1 &&
             !dc_is_single_field(work[grp_start]->name))
         {
            qsort(&work[grp_start], zero_end - grp_start,
                  sizeof(struct header_slot *), cmp_canon_value_q);
         }
      }
      grp_start = grp_end;
   }

   /* Hash the reconstructed set */
   EVP_MD_CTX *ctx = EVP_MD_CTX_new();
   if (!ctx) return NULL;
   EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

   char canon_buf[BIG_HEADER_VALUE + MAX_HEADER_NAME + 64];
   for (int i = 0; i < work_cnt; i++)
   {
      int clen = canonicalize_header_relaxed(
         work[i]->name, work[i]->value,
         canon_buf, sizeof(canon_buf), 1);
      if (clen > 0)
         EVP_DigestUpdate(ctx, canon_buf, clen);
   }

   unsigned char hash_bin[EVP_MAX_MD_SIZE];
   unsigned int hash_len = 0;
   EVP_DigestFinal_ex(ctx, hash_bin, &hash_len);
   EVP_MD_CTX_free(ctx);

   return encode_base64_hash(hash_bin, hash_len);
}


/* ================================================================
 * MILTER CALLBACKS
 * ================================================================ */

/* ---- dc_connect ---- */
static sfsistat dc_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr)
{
   struct context *ps = calloc(1, sizeof(struct context));
   if (ps == NULL) return SMFIS_TEMPFAIL;

   smfi_setpriv(ctx, ps);

   ps->mdctx_header = EVP_MD_CTX_new();
   ps->mdctx_body   = EVP_MD_CTX_new();

   if (ps->mdctx_header == NULL || ps->mdctx_body == NULL)
   {
      EVP_MD_CTX_free(ps->mdctx_header);
      EVP_MD_CTX_free(ps->mdctx_body);
      free(ps);
      smfi_setpriv(ctx, NULL);
      return SMFIS_TEMPFAIL;
   }

   EVP_DigestInit_ex(ps->mdctx_header, EVP_sha256(), NULL);
   EVP_DigestInit_ex(ps->mdctx_body,   EVP_sha256(), NULL);

   ps->header_capacity = INITIAL_CAPACITY;
   ps->header_cnt = 0;
   ps->headers = calloc(ps->header_capacity, sizeof(struct header_slot));

   ps->envelope.rcpt_capacity = DC_RCPT_INITIAL;
   ps->envelope.rcpt_count = 0;
   ps->envelope.rcpt_to = calloc(DC_RCPT_INITIAL, DC_MAX_ADDR);

   if (ps->headers == NULL || ps->envelope.rcpt_to == NULL)
   {
      syslog(LOG_ERR, "DC_CONNECT: allocation failed");
      free(ps->headers);
      free(ps->envelope.rcpt_to);
      EVP_MD_CTX_free(ps->mdctx_header);
      EVP_MD_CTX_free(ps->mdctx_body);
      free(ps);
      smfi_setpriv(ctx, NULL);
      return SMFIS_TEMPFAIL;
   }

   /* Rollback scratch — allocated once for the connection, reused per
    * message, freed in dc_close().  Keeps a ~128KB buffer off the stack. */
   ps->rb_scratch = calloc(DC_MAX_SEQ, sizeof(struct header_slot));
   if (ps->rb_scratch == NULL)
   {
      free(ps->headers);
      free(ps->envelope.rcpt_to);
      EVP_MD_CTX_free(ps->mdctx_header);
      EVP_MD_CTX_free(ps->mdctx_body);
      free(ps);
      smfi_setpriv(ctx, NULL);   /* else dc_close would read freed memory */
      return SMFIS_TEMPFAIL;
   }

   ps->is_localhost = 0;
   ps->msg_count = 0;

   /* Localhost detection */
   char *c_addr = smfi_getsymval(ctx, "{client_addr}");

   if (c_addr != NULL)
   {
      if (strncmp(c_addr, "127.", 4) == 0)
         ps->is_localhost = 1;
      else if (strcmp(c_addr, "::1") == 0)
         ps->is_localhost = 1;
      else if (strncasecmp(c_addr, "::ffff:127.", 11) == 0)
         ps->is_localhost = 1;
   }

   if (!ps->is_localhost && hostaddr != NULL)
   {
      if (hostaddr->sa_family == AF_UNIX)
      {
         ps->is_localhost = 1;
      }
      else if (hostaddr->sa_family == AF_INET)
      {
         struct sockaddr_in *sa = (struct sockaddr_in *)hostaddr;
         if ((ntohl(sa->sin_addr.s_addr) >> 24) == 0x7F)
            ps->is_localhost = 1;
      }
      else if (hostaddr->sa_family == AF_INET6)
      {
         struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)hostaddr;
         if (IN6_IS_ADDR_LOOPBACK(&sa6->sin6_addr))
            ps->is_localhost = 1;
         else if (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr))
         {
            if (sa6->sin6_addr.s6_addr[12] == 0x7F)
               ps->is_localhost = 1;
         }
      }
   }

   syslog(LOG_INFO, "DC_CONNECT [%s]: client_addr='%s', is_localhost=%d",
          hostname ? hostname : "unknown",
          c_addr ? c_addr : "NULL",
          ps->is_localhost);

   return SMFIS_CONTINUE;
}


/* ---- dc_helo ---- */
static sfsistat dc_helo(SMFICTX *ctx, char *pc_helohost)
{
   struct context *ps = (struct context *)smfi_getpriv(ctx);
   if (!ps) return SMFIS_ACCEPT;

   securecpy(ps->helo, pc_helohost, sizeof(ps->helo));
   return SMFIS_CONTINUE;
}


/* ---- dc_envfrom ---- */
static sfsistat dc_envfrom(SMFICTX *ctx, char **argv)
{
   struct context *ps = (struct context *)smfi_getpriv(ctx);
   if (!ps) return SMFIS_TEMPFAIL;

   clock_gettime(CLOCK_MONOTONIC, &ps->start_time);

   if (argv[0] != NULL)
   {
      dc_strip_angle_brackets(argv[0], ps->envelope.mail_from,
                              sizeof(ps->envelope.mail_from));
   }
   else
   {
      ps->envelope.mail_from[0] = '\0';
   }

   ps->msg_count++;

   if (ps->msg_count == 1)
   {
      ps->header_cnt = 0;
      ps->max_hop = 0;
      ps->chain_broken = 0;
      ps->dkim2_header_bytes = 0;
      ps->envelope.rcpt_count = 0;
      ps->body_size = 0;
      ps->pending_newlines = 0;
      ps->body_has_content = 0;
      ps->p_had_space = 0;
      ps->is_start_of_line = 0;
      ps->body_integrity = 0;
      ps->header_vfy = 0;
      ps->envelope_vfy = 0;
      ps->chain_vfy = 0;
      ps->cpu_ns = 0;
      ps->dns_ns = 0;
   }
   else
   {
      if (ps->mdctx_body)
      {
         EVP_MD_CTX_reset(ps->mdctx_body);
         EVP_DigestInit_ex(ps->mdctx_body, EVP_sha256(), NULL);
      }
      if (ps->mdctx_header)
      {
         EVP_MD_CTX_reset(ps->mdctx_header);
         EVP_DigestInit_ex(ps->mdctx_header, EVP_sha256(), NULL);
      }

      ps->header_cnt = 0;
      ps->max_hop = 0;
      ps->chain_broken = 0;
      ps->dkim2_header_bytes = 0;
      ps->envelope.rcpt_count = 0;
      ps->body_size = 0;
      ps->pending_newlines = 0;
      ps->body_has_content = 0;
      ps->p_had_space = 0;
      ps->is_start_of_line = 0;
      ps->body_integrity = 0;
      ps->header_vfy = 0;
      ps->envelope_vfy = 0;
      ps->chain_vfy = 0;
      ps->cpu_ns = 0;
      ps->dns_ns = 0;

      if (ps->headers)
      {
         for (int i = 0; i < ps->header_capacity; i++)
         {
            ps->headers[i].name[0] = '\0';
            ps->headers[i].value[0] = '\0';
            ps->headers[i].used_for_signature = 0;
            ps->headers[i].dc_type = DC_HDR_OTHER;
            ps->headers[i].hop = 0;
            ps->headers[i].v = 0;
            ps->headers[i].seq = 0;
            ps->headers[i].fr = 0;
            ps->headers[i].is_new = 0;
         }
      }
   }

   /* Safety: re-allocate resources if freed by dc_abort */
   if (!ps->headers)
   {
      ps->header_capacity = INITIAL_CAPACITY;
      ps->headers = calloc(ps->header_capacity, sizeof(struct header_slot));
      if (!ps->headers) return SMFIS_TEMPFAIL;
   }
   if (!ps->envelope.rcpt_to)
   {
      ps->envelope.rcpt_capacity = DC_RCPT_INITIAL;
      ps->envelope.rcpt_to = calloc(DC_RCPT_INITIAL, DC_MAX_ADDR);
      if (!ps->envelope.rcpt_to) return SMFIS_TEMPFAIL;
   }
   if (!ps->mdctx_body)
   {
      ps->mdctx_body = EVP_MD_CTX_new();
      if (!ps->mdctx_body)
      {
         syslog(LOG_ERR, "DC_ENVFROM: EVP_MD_CTX_new failed (body)");
         return SMFIS_TEMPFAIL;
      }
      EVP_DigestInit_ex(ps->mdctx_body, EVP_sha256(), NULL);
   }
   if (!ps->mdctx_header)
   {
      ps->mdctx_header = EVP_MD_CTX_new();
      if (!ps->mdctx_header)
      {
         syslog(LOG_ERR, "DC_ENVFROM: EVP_MD_CTX_new failed (header)");
         return SMFIS_TEMPFAIL;
      }
      EVP_DigestInit_ex(ps->mdctx_header, EVP_sha256(), NULL);
   }

   return SMFIS_CONTINUE;
}


/* ---- dc_envrcpt ---- */
static sfsistat dc_envrcpt(SMFICTX *ctx, char **args)
{
   struct context *ps = (struct context *)smfi_getpriv(ctx);
   if (!ps) return SMFIS_CONTINUE;

   if (args[0] != NULL)
   {
      if (ps->envelope.rcpt_count >= DC_MAX_RCPT)
         return SMFIS_CONTINUE;

      if (ps->envelope.rcpt_count >= ps->envelope.rcpt_capacity)
      {
         int new_cap = ps->envelope.rcpt_capacity * 2;
         if (new_cap > DC_MAX_RCPT) new_cap = DC_MAX_RCPT;

         char (*new_rt)[DC_MAX_ADDR] = realloc(ps->envelope.rcpt_to,
                                                new_cap * DC_MAX_ADDR);
         if (!new_rt) return SMFIS_TEMPFAIL;

         ps->envelope.rcpt_to = new_rt;
         ps->envelope.rcpt_capacity = new_cap;
      }

      dc_strip_angle_brackets(args[0],
                              ps->envelope.rcpt_to[ps->envelope.rcpt_count],
                              DC_MAX_ADDR);
      ps->envelope.rcpt_count++;
   }

   return SMFIS_CONTINUE;
}


/* ---- dc_header ---- */
static sfsistat dc_header(SMFICTX *ctx, char *headerf, char *headerv)
{
   struct context *ps = (struct context *)smfi_getpriv(ctx);
   if (!ps) return SMFIS_CONTINUE;

   struct timespec cb_start, cb_end;
   clock_gettime(CLOCK_MONOTONIC, &cb_start);

   /* Anti-spoofing: strip our internal status header from external senders */
   if (ps->is_localhost == 0)
   {
      if (strcasecmp(headerf, "X-DarkChain-Internal-Status") == 0)
      {
         smfi_chgheader(ctx, "X-DarkChain-Internal-Status", 1, NULL);
         syslog(LOG_NOTICE, "DC_HEADER: Stripped spoofed internal header from external sender");
         return SMFIS_CONTINUE;
      }
   }

   /* Expand reservoir if needed */
   if (ps->header_cnt >= ps->header_capacity)
   {
      if (ps->header_capacity >= MAX_HEADER_COUNT)
         return SMFIS_CONTINUE;

      int new_cap = ps->header_capacity + INITIAL_CAPACITY;
      struct header_slot *new_ptr = realloc(ps->headers,
                                            new_cap * sizeof(struct header_slot));
      if (new_ptr == NULL)
         return SMFIS_TEMPFAIL;

      ps->headers = new_ptr;
      ps->header_capacity = new_cap;
   }

   struct header_slot *slot = &ps->headers[ps->header_cnt];

   strncpy(slot->name, headerf, MAX_HEADER_NAME - 1);
   slot->name[MAX_HEADER_NAME - 1] = '\0';

   unfold_header(headerv);
   if (strlen(headerv) >= BIG_HEADER_VALUE)
      syslog(LOG_NOTICE,
             "DC_HEADER: header '%s' truncated to %d bytes — "
             "hh= comparison may fail on this message",
             headerf, BIG_HEADER_VALUE - 1);
   strncpy(slot->value, headerv, BIG_HEADER_VALUE - 1);
   slot->value[BIG_HEADER_VALUE - 1] = '\0';

   slot->used_for_signature = 0;
   slot->dc_type = DC_HDR_OTHER;
   slot->hop = 0;
   slot->v = 0;
   slot->seq = 0;
   slot->fr = 0;
   slot->is_new = 0;

   /* ---- Classify DKIM2-* headers ---- */

   if (strncasecmp(headerf, "DKIM2-", 6) == 0)
   {
      size_t hdr_bytes = strlen(headerf) + 2 + strlen(headerv);
      ps->dkim2_header_bytes += hdr_bytes;
      if (ps->dkim2_header_bytes > 131072) /* 128KB */
      {
         ps->chain_broken = 1;
         syslog(LOG_NOTICE, "DC_HEADER: DKIM2 headers exceed 128KB cap (%zu bytes)",
                ps->dkim2_header_bytes);
         ps->header_cnt++;
         clock_gettime(CLOCK_MONOTONIC, &cb_end);
         ps->cpu_ns += diff_ns(cb_start, cb_end);
         return SMFIS_CONTINUE; /* [ENFORCEMENT]: SMFIS_REJECT */
      }

      /* Determine the structural type by name FIRST.  Only the four
       * signed chain headers participate in hop numbering and chain
       * continuity.  Other DKIM2-* headers — notably
       * DKIM2-Authentication-Results, unsigned and injectable by any
       * peer, and unknown future extensions — must not raise max_hop
       * nor set chain_broken: an injected trace header would otherwise
       * poison the chain (permerror on legitimate mail, reject in
       * enforcement mode). */
      int hdr_type = DC_HDR_OTHER;
      if      (strcasecmp(headerf, "DKIM2-Signature") == 0) hdr_type = DC_HDR_SIG;
      else if (strcasecmp(headerf, "DKIM2-Sig-mf") == 0)    hdr_type = DC_HDR_MF;
      else if (strcasecmp(headerf, "DKIM2-Sig-rt") == 0)    hdr_type = DC_HDR_RT;
      else if (strcasecmp(headerf, "DKIM2-Mod") == 0)       hdr_type = DC_HDR_MOD;

      if (hdr_type != DC_HDR_OTHER)
      {
         int hop = dc_get_hop_index(headerv);

         if (hop < 0)
         {
            ps->chain_broken = 1;
            syslog(LOG_NOTICE, "DC_HEADER: DKIM2 header without valid i= tag: %s", headerf);
         }
         else
         {
            slot->hop = hop;
            slot->dc_type = hdr_type;

            if (hop > ps->max_hop)
               ps->max_hop = hop;

            if (hdr_type == DC_HDR_RT)
            {
               slot->v = dc_get_tag_int(headerv, "v");

               if (slot->v > DC_MAX_RT)
               {
                  ps->chain_broken = 1;
                  syslog(LOG_NOTICE, "DC_HEADER: DKIM2-Sig-rt v=%d exceeds limit", slot->v);
               }
            }
            else if (hdr_type == DC_HDR_MOD)
            {
               slot->seq = dc_get_tag_int(headerv, "seq");
               slot->fr  = dc_get_tag_int(headerv, "fr");

               if (slot->seq == 0) slot->seq = 1;
               if (slot->fr == 0)  slot->fr = 1;

               char probe[16] = "";
               dc_get_tag_str(headerv, "new", probe, sizeof(probe));
               slot->is_new = (probe[0] != '\0') ? 1 : 0;

               if (slot->seq > DC_MAX_SEQ || slot->fr > DC_MAX_FR)
               {
                  ps->chain_broken = 1;
                  syslog(LOG_NOTICE, "DC_HEADER: DKIM2-Mod seq=%d fr=%d exceeds limits",
                         slot->seq, slot->fr);
               }
            }
         }
      }
      /* else: non-structural DKIM2-* (e.g. Authentication-Results):
       * stored in the reservoir and counted in the byte cap, but with
       * no effect on hop numbering or chain state. */
   }

   ps->header_cnt++;

   clock_gettime(CLOCK_MONOTONIC, &cb_end);
   ps->cpu_ns += diff_ns(cb_start, cb_end);

   return SMFIS_CONTINUE;
}


/* ---- dc_eoh ---- */
static sfsistat dc_eoh(SMFICTX *ctx)
{
   struct context *ps = (struct context *)smfi_getpriv(ctx);
   if (!ps) return SMFIS_ACCEPT;

   struct timespec cb_start, cb_end;
   clock_gettime(CLOCK_MONOTONIC, &cb_start);

   if (ps->max_hop == 0)
   {
      syslog(LOG_DEBUG, "DC_EOH: No DKIM2 headers found. Skip validation.");
   }
   else
   {
      /* Check chain continuity */
      for (int i = 1; i <= ps->max_hop; i++)
      {
         int found_sig = 0;
         for (int j = 0; j < ps->header_cnt; j++)
         {
            if (ps->headers[j].dc_type == DC_HDR_SIG && ps->headers[j].hop == i)
            {
               found_sig = 1;
               break;
            }
         }
         if (!found_sig)
         {
            ps->chain_broken = 1;
            syslog(LOG_NOTICE, "DC_EOH: Chain gap — no DKIM2-Signature at i=%d", i);
            break;
         }
      }

      /* Each hop must have exactly one DKIM2-Sig-mf */
      for (int i = 1; i <= ps->max_hop; i++)
      {
         int found_mf = 0;
         for (int j = 0; j < ps->header_cnt; j++)
         {
            if (ps->headers[j].dc_type == DC_HDR_MF && ps->headers[j].hop == i)
            {
               found_mf++;
            }
         }
         if (found_mf != 1)
         {
            ps->chain_broken = 1;
            syslog(LOG_NOTICE, "DC_EOH: Expected 1 DKIM2-Sig-mf at i=%d, found %d",
                   i, found_mf);
            break;
         }
      }

      /* Check v= continuity for DKIM2-Sig-rt */
      if (!ps->chain_broken)
      {
         for (int i = 1; i <= ps->max_hop; i++)
         {
            int max_v = 0;
            int rt_count = 0;

            for (int j = 0; j < ps->header_cnt; j++)
            {
               if (ps->headers[j].dc_type == DC_HDR_RT && ps->headers[j].hop == i)
               {
                  rt_count++;
                  if (ps->headers[j].v > max_v)
                     max_v = ps->headers[j].v;
               }
            }

            if (rt_count > 0 && rt_count != max_v)
            {
               ps->chain_broken = 1;
               syslog(LOG_NOTICE,
                      "DC_EOH: DKIM2-Sig-rt gap at i=%d: %d headers but max v=%d",
                      i, rt_count, max_v);
               break;
            }
         }
      }

      /* Check seq= and fr= continuity for DKIM2-Mod */
      if (!ps->chain_broken)
      {
         for (int i = 1; i <= ps->max_hop; i++)
         {
            int max_seq = 0;
            int seq_count = 0;
            int seen_seq[DC_MAX_SEQ + 1];
            memset(seen_seq, 0, sizeof(seen_seq));

            for (int j = 0; j < ps->header_cnt; j++)
            {
               if (ps->headers[j].dc_type == DC_HDR_MOD && ps->headers[j].hop == i)
               {
                  int s = ps->headers[j].seq;
                  if (s > 0 && s <= DC_MAX_SEQ)
                  {
                     if (!seen_seq[s])
                     {
                        seen_seq[s] = 1;
                        seq_count++;
                     }
                     if (s > max_seq) max_seq = s;
                  }
               }
            }

            if (seq_count > 0 && seq_count != max_seq)
            {
               ps->chain_broken = 1;
               syslog(LOG_NOTICE,
                      "DC_EOH: DKIM2-Mod seq= gap at i=%d: %d seqs but max seq=%d",
                      i, seq_count, max_seq);
               break;
            }

            for (int s = 1; s <= max_seq && !ps->chain_broken; s++)
            {
               for (int is_new = 0; is_new <= 1 && !ps->chain_broken; is_new++)
               {
                  int max_fr = 0;
                  int fr_count = 0;

                  for (int j = 0; j < ps->header_cnt; j++)
                  {
                     if (ps->headers[j].dc_type == DC_HDR_MOD &&
                         ps->headers[j].hop == i &&
                         ps->headers[j].seq == s &&
                         ps->headers[j].is_new == is_new)
                     {
                        fr_count++;
                        if (ps->headers[j].fr > max_fr)
                           max_fr = ps->headers[j].fr;
                     }
                  }

                  if (fr_count > 0 && fr_count != max_fr)
                  {
                     ps->chain_broken = 1;
                     syslog(LOG_NOTICE,
                            "DC_EOH: DKIM2-Mod fr= gap at i=%d seq=%d %s: "
                            "%d frames but max fr=%d",
                            i, s, is_new ? "new" : "del", fr_count, max_fr);
                  }
               }
            }
         }
      }
   }

   clock_gettime(CLOCK_MONOTONIC, &cb_end);
   ps->cpu_ns += diff_ns(cb_start, cb_end);

   /* [ENFORCEMENT]: if (ps->chain_broken) return SMFIS_REJECT; */
   return SMFIS_CONTINUE;
}


/* ---- dc_body ---- */
static sfsistat dc_body(SMFICTX *ctx, unsigned char *bodyp, size_t bodylen)
{
   struct context *ps = (struct context *)smfi_getpriv(ctx);
   if (!ps) return SMFIS_CONTINUE;

   struct timespec cb_start, cb_end;
   clock_gettime(CLOCK_MONOTONIC, &cb_start);

   ps->body_size += bodylen;

   register int l_pending   = ps->pending_newlines;
   register int l_had_space  = ps->p_had_space;
   register int l_is_start   = ps->is_start_of_line;
   register int l_has_cont   = ps->body_has_content;

   unsigned char r_buf[BODY_BUF_SIZE];
   size_t r_idx = 0;

   size_t i = 0;
   while (i < bodylen)
   {
      unsigned char c = bodyp[i];

      if (c == '\r') { i++; continue; }

      if (c == '\n')
      {
         l_had_space = 0;
         l_is_start  = 1;
         l_pending++;
         i++;
         continue;
      }

      if (c == ' ' || c == '\t')
      {
         l_had_space = 1;
         i++;
         continue;
      }

      size_t j = i + 1;
      while (j < bodylen &&
             bodyp[j] != '\r' && bodyp[j] != '\n' &&
             bodyp[j] != ' '  && bodyp[j] != '\t')
      {
         j++;
      }
      size_t run = j - i;

      while (l_pending > 0)
      {
         if (r_idx >= BODY_BUF_SIZE - 2)
         {
            EVP_DigestUpdate(ps->mdctx_body, r_buf, r_idx);
            r_idx = 0;
         }
         r_buf[r_idx++] = '\r';
         r_buf[r_idx++] = '\n';
         l_pending--;
         l_has_cont = 1;
      }

      if (l_had_space)
      {
         if (r_idx >= BODY_BUF_SIZE)
         {
            EVP_DigestUpdate(ps->mdctx_body, r_buf, r_idx);
            r_idx = 0;
         }
         r_buf[r_idx++] = ' ';
         l_had_space = 0;
      }

      size_t space_left = BODY_BUF_SIZE - r_idx;
      if (run <= space_left)
      {
         memcpy(r_buf + r_idx, bodyp + i, run);
         r_idx += run;
      }
      else
      {
         memcpy(r_buf + r_idx, bodyp + i, space_left);
         EVP_DigestUpdate(ps->mdctx_body, r_buf, BODY_BUF_SIZE);
         r_idx = 0;
         size_t remaining = run - space_left;
         if (remaining >= BODY_BUF_SIZE)
         {
            EVP_DigestUpdate(ps->mdctx_body, bodyp + i + space_left, remaining);
         }
         else
         {
            memcpy(r_buf, bodyp + i + space_left, remaining);
            r_idx = remaining;
         }
      }

      l_has_cont = 1;
      l_is_start = 0;
      i = j;
   }

   if (r_idx > 0)
   {
      EVP_DigestUpdate(ps->mdctx_body, r_buf, r_idx);
   }

   ps->pending_newlines    = l_pending;
   ps->p_had_space         = l_had_space;
   ps->is_start_of_line    = l_is_start;
   ps->body_has_content    = l_has_cont;

   clock_gettime(CLOCK_MONOTONIC, &cb_end);
   ps->cpu_ns += diff_ns(cb_start, cb_end);

   return SMFIS_CONTINUE;
}


/* ---- dc_eom ---- */
static sfsistat dc_eom(SMFICTX *ctx)
{
   struct context *ps = (struct context *)smfi_getpriv(ctx);
   if (!ps) return SMFIS_CONTINUE;

   struct timespec ts_start, ts_end, ts_dns_start, ts_dns_end;
   clock_gettime(CLOCK_MONOTONIC, &ts_start);

   const char *dkim2_verdict = "none";
   char dkim2_details[512] = "no DKIM2 headers";
   char signing_domain[256] = "";
   EVP_PKEY *pubkey = NULL;

   syslog(LOG_DEBUG, "DC_EOM: localhost =%d", ps->is_localhost);

   /* --- 0. FINALIZE BODY HASH --- */
   if (ps->body_has_content)
   {
      EVP_DigestUpdate(ps->mdctx_body, "\r\n", 2);
   }

   unsigned char body_hash_bin[EVP_MAX_MD_SIZE];
   unsigned int  body_hash_len = 0;

   if (EVP_DigestFinal_ex(ps->mdctx_body, body_hash_bin, &body_hash_len) != 1)
   {
      syslog(LOG_ERR, "DC_EOM: Fatal OpenSSL error in body hash finalization");
      return SMFIS_TEMPFAIL;
   }

   /* --- No chain? --- */
   if (ps->max_hop == 0)
   {
      syslog(LOG_DEBUG, "DC_EOM: No DKIM2 chain present.");
      goto inject_result;
   }

   if (ps->chain_broken)
   {
      dkim2_verdict = "permerror";
      snprintf(dkim2_details, sizeof(dkim2_details), "chain structure broken");
      goto inject_result;
   }

   /* --- 1. BUILD HOP INDEX (single pass) --- */
   struct dc_hop_index idx;
   memset(&idx, 0, sizeof(idx));

   for (int j = 0; j < ps->header_cnt; j++)
   {
      struct header_slot *h = &ps->headers[j];

      if (h->dc_type == DC_HDR_SIG)
      {
         if (h->hop == ps->max_hop)
            idx.sig = h;
         else if (h->hop > 0 && h->hop < ps->max_hop)
         {
            idx.prev_sig[h->hop - 1] = h;
            if (h->hop > idx.prev_sig_count)
               idx.prev_sig_count = h->hop;
         }
      }
      else if (h->dc_type == DC_HDR_MF && h->hop == ps->max_hop)
      {
         idx.mf = h;
      }
      else if (h->dc_type == DC_HDR_RT && h->hop == ps->max_hop)
      {
         if (idx.rt_count < DC_MAX_RT)
            idx.rt[idx.rt_count++] = h;
      }
      else if (h->dc_type == DC_HDR_MOD && h->hop <= ps->max_hop)
      {
         if (idx.mod_count < DC_MAX_MOD)
            idx.mod[idx.mod_count++] = h;
         else if (!ps->chain_broken)
         {
            ps->chain_broken = 1;
            syslog(LOG_NOTICE, "DC_EOM: DKIM2-Mod count exceeds %d", DC_MAX_MOD);
         }
      }
   }

   /* Re-check: the index-building loop above can break the chain
    * (Mod count overflow).  Without this, verification would proceed
    * on a truncated Mod set and yield "fail" instead of the correct
    * "permerror". */
   if (ps->chain_broken)
   {
      dkim2_verdict = "permerror";
      snprintf(dkim2_details, sizeof(dkim2_details),
               "DKIM2-Mod count exceeds %d", DC_MAX_MOD);
      goto inject_result;
   }

   if (!idx.sig)
   {
      dkim2_verdict = "permerror";
      snprintf(dkim2_details, sizeof(dkim2_details),
               "no DKIM2-Signature at i=%d", ps->max_hop);
      goto inject_result;
   }

   if (!idx.mf)
   {
      dkim2_verdict = "permerror";
      snprintf(dkim2_details, sizeof(dkim2_details),
               "no DKIM2-Sig-mf at i=%d", ps->max_hop);
      goto inject_result;
   }

   if (idx.rt_count > 1)
      qsort(idx.rt, idx.rt_count, sizeof(struct header_slot *), cmp_rt_by_v);
   if (idx.mod_count > 1)
      qsort(idx.mod, idx.mod_count, sizeof(struct header_slot *), cmp_mod_canonical);

   /* --- 2. PARSE SIGNATURE TAGS --- */
   char sig_d[256] = "", sig_s[128] = "", sig_a[32] = "";
   char sig_bh[256] = "", sig_b[MAX_PUB_KEY] = "";
   char sig_h[2048] = "", sig_c[64] = "";

   dc_get_tag_str(idx.sig->value, "d",  sig_d,  sizeof(sig_d));
   dc_get_tag_str(idx.sig->value, "s",  sig_s,  sizeof(sig_s));
   dc_get_tag_str(idx.sig->value, "a",  sig_a,  sizeof(sig_a));
   dc_get_tag_str(idx.sig->value, "bh", sig_bh, sizeof(sig_bh));
   dc_get_tag_str(idx.sig->value, "b",  sig_b,  sizeof(sig_b));
   dc_get_tag_str(idx.sig->value, "h",  sig_h,  sizeof(sig_h));
   dc_get_tag_str(idx.sig->value, "c",  sig_c,  sizeof(sig_c));
   strip_whitespace(sig_b);
   strip_whitespace(sig_bh);

   securecpy(signing_domain, sig_d, sizeof(signing_domain));

   if (sig_d[0] == '\0' || sig_s[0] == '\0')
   {
      dkim2_verdict = "permerror";
      snprintf(dkim2_details, sizeof(dkim2_details),
               "missing d= or s= in DKIM2-Signature");
      goto inject_result;
   }
   if (sig_b[0] == '\0' || sig_bh[0] == '\0')
   {
      dkim2_verdict = "permerror";
      snprintf(dkim2_details, sizeof(dkim2_details),
               "missing b= or bh= in DKIM2-Signature");
      goto inject_result;
   }

   int is_ed25519 = (strstr(sig_a, "ed25519") != NULL);

   /* --- 2a. TIMESTAMP CHECK --- */
   {
      char sig_t_str[32] = "";
      dc_get_tag_str(idx.sig->value, "t", sig_t_str, sizeof(sig_t_str));

      if (sig_t_str[0] != '\0')
      {
         long sig_t = atol(sig_t_str);
         time_t now = time(NULL);
         long delta = (long)now - sig_t;

         if (delta < -300)
         {
            dkim2_verdict = "fail";
            snprintf(dkim2_details, sizeof(dkim2_details),
                     "signature timestamp %ld seconds in the future i=%d d=%s",
                     -delta, ps->max_hop, sig_d);
            syslog(LOG_NOTICE, "DC_EOM: Timestamp %ld seconds in the future (max 300)",
                   -delta);
            goto inject_result;
         }

         if (delta > 15 * 86400)
         {
            dkim2_verdict = "fail";
            snprintf(dkim2_details, sizeof(dkim2_details),
                     "signature expired: %ld days old i=%d d=%s",
                     delta / 86400, ps->max_hop, sig_d);
            syslog(LOG_NOTICE, "DC_EOM: Timestamp %ld days old (max 15)",
                   delta / 86400);
            goto inject_result;
         }

         if (DEBUG)
            syslog(LOG_DEBUG, "DC_EOM: Timestamp delta=%ld seconds (ok)", delta);
      }
      else
      {
         syslog(LOG_INFO, "DC_EOM: No t= timestamp in DKIM2-Signature i=%d",
                ps->max_hop);
      }
   }

   /* --- 3. BODY HASH COMPARISON --- */
   {
      unsigned char remote_bh[EVP_MAX_MD_SIZE];
      int remote_bh_len = decode_base64_sig(sig_bh, remote_bh, sizeof(remote_bh));

      if (remote_bh_len != (int)body_hash_len ||
          memcmp(body_hash_bin, remote_bh, body_hash_len) != 0)
      {
         ps->body_integrity = 0;
         dkim2_verdict = "fail";
         snprintf(dkim2_details, sizeof(dkim2_details),
                  "body hash mismatch i=%d d=%s", ps->max_hop, sig_d);
         syslog(LOG_NOTICE, "DC_EOM: Body hash MISMATCH (i=%d d=%s)", ps->max_hop, sig_d);
         goto inject_result;
      }
      ps->body_integrity = 1;
      syslog(LOG_INFO, "DC_EOM: Body hash MATCH (i=%d)", ps->max_hop);
   }

   /* --- 4. DNS KEY LOOKUP --- */
   {
      char dns_key[MAX_PUB_KEY] = "";

      clock_gettime(CLOCK_MONOTONIC, &ts_end);
      ps->cpu_ns += diff_ns(ts_start, ts_end);

      clock_gettime(CLOCK_MONOTONIC, &ts_dns_start);
      int dns_ok = get_dns_arc_pubkey(sig_d, sig_s, dns_key, sizeof(dns_key) - 1);
      clock_gettime(CLOCK_MONOTONIC, &ts_dns_end);
      ps->dns_ns += diff_ns(ts_dns_start, ts_dns_end);

      clock_gettime(CLOCK_MONOTONIC, &ts_start);

      if (dns_ok < 0 || dns_key[0] == '\0')
      {
         dkim2_verdict = "temperror";
         snprintf(dkim2_details, sizeof(dkim2_details),
                  "DNS lookup failed %s._domainkey.%s", sig_s, sig_d);
         syslog(LOG_ERR, "DC_EOM: DNS key not found for %s._domainkey.%s", sig_s, sig_d);
         goto inject_result;
      }

      pubkey = decode_dns_key(dns_key, is_ed25519);
      if (!pubkey)
      {
         dkim2_verdict = "permerror";
         snprintf(dkim2_details, sizeof(dkim2_details),
                  "key decode failed d=%s s=%s", sig_d, sig_s);
         goto inject_result;
      }
   }

   /* --- 5. DECODE SIGNATURE VALUE --- */
   unsigned char sig_binary[512];
   int sig_bin_len = decode_base64_sig(sig_b, sig_binary, sizeof(sig_binary));
   if (sig_bin_len <= 0)
   {
      dkim2_verdict = "permerror";
      snprintf(dkim2_details, sizeof(dkim2_details), "b= base64 decode failed");
      goto cleanup_key;
   }

   /* --- 6. RECONSTRUCT SIGNED HEADER INPUT AND VERIFY --- */
   {
      char h_work[2048];
      char *h_msg_fields[256];
      int h_msg_count = 0;

      if (sig_h[0] != '\0')
      {
         securecpy(h_work, sig_h, sizeof(h_work));
         char *saveptr = NULL;
         char *token = strtok_r(h_work, ":", &saveptr);
         while (token != NULL && h_msg_count < 256)
         {
            while (*token == ' ' || *token == '\t') token++;
            char *end = token + strlen(token) - 1;
            while (end > token && (*end == ' ' || *end == '\t'))
               *end-- = '\0';

            if (*token != '\0')
            {
               if (strncasecmp(token, "DKIM2-", 6) == 0)
               {
                  dkim2_verdict = "permerror";
                  snprintf(dkim2_details, sizeof(dkim2_details),
                           "h= contains DKIM2 header: %s", token);
                  syslog(LOG_NOTICE, "DC_EOM: h= contains DKIM2 header '%s' — permerror",
                         token);
                  goto cleanup_key;
               }
               h_msg_fields[h_msg_count++] = token;
            }
            token = strtok_r(NULL, ":", &saveptr);
         }
      }

      for (int j = 0; j < ps->header_cnt; j++)
         ps->headers[j].used_for_signature = 0;

      char canon_buf[BIG_HEADER_VALUE + MAX_HEADER_NAME + 64];

      char *ed_buf = NULL;
      char *ed_ptr = NULL;
      size_t buf_est = (size_t)(ps->header_cnt + 10) *
                       (BIG_HEADER_VALUE + MAX_HEADER_NAME + 64);

      if (is_ed25519)
      {
         ed_buf = calloc(1, buf_est);
         if (!ed_buf)
         {
            dkim2_verdict = "temperror";
            snprintf(dkim2_details, sizeof(dkim2_details), "memory allocation failed");
            goto cleanup_key;
         }
         ed_ptr = ed_buf;
      }
      else
      {
         EVP_MD_CTX_reset(ps->mdctx_header);
         EVP_DigestInit_ex(ps->mdctx_header, EVP_sha256(), NULL);
      }

      #define FEED_DATA(data, len) do {                                        \
         if (is_ed25519) {                                                     \
            if ((size_t)(ed_ptr - ed_buf) + (size_t)(len) > buf_est) {         \
               syslog(LOG_ERR, "DC_EOM: ed25519 header buffer overflow guard"); \
               free(ed_buf); ed_buf = NULL;                                    \
               dkim2_verdict = "temperror";                                    \
               snprintf(dkim2_details, sizeof(dkim2_details),                  \
                        "header buffer overflow i=%d", ps->max_hop);           \
               goto cleanup_key;                                               \
            }                                                                  \
            memcpy(ed_ptr, (data), (len));                                     \
            ed_ptr += (len);                                                   \
         } else {                                                              \
            EVP_DigestUpdate(ps->mdctx_header, (data), (len));                 \
         }                                                                     \
      } while(0)

      #define FEED_HEADER_SLOT(slot, with_crlf) do {            \
         int clen = canonicalize_header_relaxed(                 \
            (slot)->name, (slot)->value,                         \
            canon_buf, sizeof(canon_buf), (with_crlf));          \
         if (clen > 0)                                          \
            FEED_DATA(canon_buf, (size_t)clen);                 \
      } while(0)

      /* a) Previous DKIM2-Signatures: i=1..N-1, ascending */
      for (int i = 1; i < ps->max_hop; i++)
      {
         if (idx.prev_sig[i - 1])
            FEED_HEADER_SLOT(idx.prev_sig[i - 1], 1);
      }

      /* b) DKIM2-Sig-mf at i=N */
      FEED_HEADER_SLOT(idx.mf, 1);

      /* c) DKIM2-Sig-rt at i=N, sorted by v= */
      for (int r = 0; r < idx.rt_count; r++)
         FEED_HEADER_SLOT(idx.rt[r], 1);

      /* d) DKIM2-Mod with i<=N, canonical order */
      for (int m = 0; m < idx.mod_count; m++)
         FEED_HEADER_SLOT(idx.mod[m], 1);

      /* e) Message headers from h= — bottom-to-top walk */
      for (int i = 0; i < h_msg_count; i++)
      {
         char *target = h_msg_fields[i];
         for (int j = ps->header_cnt - 1; j >= 0; j--)
         {
            if (strcasecmp(ps->headers[j].name, target) == 0 &&
                ps->headers[j].used_for_signature == 0)
            {
               FEED_HEADER_SLOT(&ps->headers[j], 1);
               ps->headers[j].used_for_signature = 1;
               break;
            }
         }
      }

      /* f) Current DKIM2-Signature with b= emptied, NO trailing CRLF */
      {
         int clen = canonicalize_sig_for_verify(
            idx.sig->name, idx.sig->value, canon_buf, sizeof(canon_buf));
         if (clen > 0)
            FEED_DATA(canon_buf, (size_t)clen);
      }

      /* --- Verify --- */
      if (is_ed25519)
      {
         size_t total_len = (size_t)(ed_ptr - ed_buf);

         EVP_MD_CTX *ed_ctx = EVP_MD_CTX_new();
         int result = 0;
         if (ed_ctx &&
             EVP_DigestVerifyInit(ed_ctx, NULL, NULL, NULL, pubkey) == 1)
         {
            result = EVP_DigestVerify(ed_ctx, sig_binary, sig_bin_len,
                                      (unsigned char *)ed_buf, total_len);
         }
         else
         {
            syslog(LOG_ERR, "DC_EOM: EVP_DigestVerifyInit (ed25519) failed");
         }
         if (ed_ctx) EVP_MD_CTX_free(ed_ctx);
         free(ed_buf);
         ed_buf = NULL;

         ps->header_vfy = (result == 1) ? 1 : 0;
      }
      else
      {
         unsigned char m_hash[EVP_MAX_MD_SIZE];
         unsigned int m_hash_len = 0;
         if (EVP_DigestFinal_ex(ps->mdctx_header, m_hash, &m_hash_len) != 1)
         {
            syslog(LOG_ERR, "DC_EOM: EVP_DigestFinal failed for header hash");
            goto cleanup_key;
         }

         EVP_PKEY_CTX *ver_ctx = EVP_PKEY_CTX_new(pubkey, NULL);
         if (ver_ctx &&
             EVP_PKEY_verify_init(ver_ctx) == 1 &&
             EVP_PKEY_CTX_set_rsa_padding(ver_ctx, RSA_PKCS1_PADDING) > 0 &&
             EVP_PKEY_CTX_set_signature_md(ver_ctx, EVP_sha256()) > 0)
         {
            int result = EVP_PKEY_verify(ver_ctx, sig_binary, sig_bin_len,
                                          m_hash, m_hash_len);
            ps->header_vfy = (result == 1) ? 1 : 0;
         }
         else
         {
            syslog(LOG_ERR, "DC_EOM: RSA verify context init failed");
            ps->header_vfy = 0;
         }
         if (ver_ctx) EVP_PKEY_CTX_free(ver_ctx);
      }

      #undef FEED_DATA
      #undef FEED_HEADER_SLOT

      if (ps->header_vfy)
         syslog(LOG_INFO, "DC_EOM: Signature VALID (i=%d d=%s %s)",
                ps->max_hop, sig_d, is_ed25519 ? "Ed25519" : "RSA");
      else
         syslog(LOG_NOTICE, "DC_EOM: Signature FAILED (i=%d d=%s %s)",
                ps->max_hop, sig_d, is_ed25519 ? "Ed25519" : "RSA");
   }

   if (!ps->header_vfy)
   {
      dkim2_verdict = "fail";
      snprintf(dkim2_details, sizeof(dkim2_details),
               "signature verification failed i=%d d=%s", ps->max_hop, sig_d);
      goto cleanup_key;
   }

   /* --- 6b. HEADER HASH (hh=) VERIFICATION --- */
   {
      char sig_hh[256] = "";
      dc_get_tag_str(idx.sig->value, "hh", sig_hh, sizeof(sig_hh));
      strip_whitespace(sig_hh);

      if (sig_hh[0] != '\0')
      {
         char *computed_hh = dc_compute_hh(ps->headers, ps->header_cnt);
         if (computed_hh)
         {
            if (strcmp(sig_hh, computed_hh) == 0)
            {
               syslog(LOG_INFO, "DC_EOM: Header hash (hh=) MATCH (i=%d)",
                      ps->max_hop);
            }
            else
            {
               syslog(LOG_NOTICE,
                      "DC_EOM: Header hash (hh=) MISMATCH (i=%d d=%s) "
                      "sig=[%.32s...] computed=[%.32s...]",
                      ps->max_hop, sig_d, sig_hh, computed_hh);
               dkim2_verdict = "fail";
               snprintf(dkim2_details, sizeof(dkim2_details),
                        "header hash mismatch i=%d d=%s", ps->max_hop, sig_d);
               free(computed_hh);
               goto cleanup_key;
            }
            free(computed_hh);
         }
         else
         {
            /* Allocation failure inside dc_compute_hh: transient
             * condition — do not silently skip the hh= check (which
             * would let an unverified header set pass), signal
             * temperror so the sender retries. */
            syslog(LOG_ERR, "DC_EOM: Failed to compute hh= for comparison");
            dkim2_verdict = "temperror";
            snprintf(dkim2_details, sizeof(dkim2_details),
                     "hh= computation failed i=%d", ps->max_hop);
            goto cleanup_key;
         }
      }
      else
      {
         syslog(LOG_INFO, "DC_EOM: No hh= in DKIM2-Signature i=%d (skipping)",
                ps->max_hop);
      }
   }

   /* --- 6c. ROLLBACK VERIFICATION --- */
   if (ps->max_hop >= 2)
   {
      char prev_hh[256] = "";
      for (int j = 0; j < ps->header_cnt; j++)
      {
         if (ps->headers[j].dc_type == DC_HDR_SIG &&
             ps->headers[j].hop == ps->max_hop - 1)
         {
            dc_get_tag_str(ps->headers[j].value, "hh", prev_hh, sizeof(prev_hh));
            strip_whitespace(prev_hh);
            break;
         }
      }

      if (prev_hh[0] != '\0')
      {
         char *rolled_hh = dc_rollback_hh(ps->headers, ps->header_cnt, ps->max_hop,
                                          ps->rb_scratch);
         if (rolled_hh)
         {
            if (strcmp(prev_hh, rolled_hh) == 0)
            {
               syslog(LOG_INFO,
                      "DC_EOM: Rollback hh= MATCH — hop %d modifications verified",
                      ps->max_hop);
            }
            else
            {
               syslog(LOG_NOTICE,
                      "DC_EOM: Rollback hh= MISMATCH — hop %d lied about modifications "
                      "prev=[%.32s...] rolled=[%.32s...]",
                      ps->max_hop, prev_hh, rolled_hh);
               dkim2_verdict = "fail";
               snprintf(dkim2_details, sizeof(dkim2_details),
                        "rollback hh mismatch i=%d d=%s", ps->max_hop, sig_d);
               free(rolled_hh);
               goto cleanup_key;
            }
            free(rolled_hh);
         }
      }
      else
      {
         syslog(LOG_INFO,
                "DC_EOM: No hh= in DKIM2-Signature i=%d, rollback skipped",
                ps->max_hop - 1);
      }
   }

   /* --- 7. ENVELOPE BINDING VERIFICATION --- */
   {
      ps->envelope_vfy = 0;
      char mf_addr[DC_MAX_ADDR] = "";
      int mf_exact = 0;
      int mf_domain_ok = 0;

      dc_get_addr_tag(idx.mf->value, mf_addr, sizeof(mf_addr));

      if (mf_addr[0] != '\0' && ps->envelope.mail_from[0] != '\0')
      {
         if (dc_addr_match(mf_addr, ps->envelope.mail_from))
         {
            mf_exact = 1;
         }
         else
         {
            syslog(LOG_NOTICE, "DC_EOM: Envelope mf= MISMATCH: signed=[%s] smtp=[%s]",
                   mf_addr, ps->envelope.mail_from);
         }

         if (dc_relaxed_domain_match(sig_d, mf_addr))
         {
            mf_domain_ok = 1;
         }
         else
         {
            syslog(LOG_NOTICE, "DC_EOM: Relaxed domain mismatch: d=%s vs mf=%s",
                   sig_d, mf_addr);
         }

         if (mf_exact && mf_domain_ok)
         {
            ps->envelope_vfy = 1;
            syslog(LOG_INFO, "DC_EOM: Envelope mf= MATCH (exact + domain)");
         }
      }
      else
      {
         /* Null sender (DSN bounce) or empty mf=: skip alignment,
          * set envelope_vfy so rt= check can proceed.
          * RFC 5321 requires <> for bounces — no domain to align.
          */
         ps->envelope_vfy = 1;
         syslog(LOG_INFO, "DC_EOM: Envelope mf= empty (DSN/null sender), alignment skipped");
      }

      int rt_match_count = 0;

      for (int r = 0; r < idx.rt_count; r++)
      {
         char rt_addr[DC_MAX_ADDR] = "";
         dc_get_addr_tag(idx.rt[r]->value, rt_addr, sizeof(rt_addr));

         for (int k = 0; k < ps->envelope.rcpt_count; k++)
         {
            if (dc_addr_match(rt_addr, ps->envelope.rcpt_to[k]))
            {
               rt_match_count++;
               break;
            }
         }
      }

      if (idx.rt_count > 0 && rt_match_count == idx.rt_count && ps->envelope_vfy)
      {
         syslog(LOG_INFO, "DC_EOM: Envelope rt= MATCH (%d/%d)",
                rt_match_count, idx.rt_count);
      }
      else if (idx.rt_count > 0)
      {
         ps->envelope_vfy = 0;
         syslog(LOG_NOTICE, "DC_EOM: Envelope rt= partial/fail (%d/%d matched)",
                rt_match_count, idx.rt_count);
      }
   }

   /* --- OVERALL VERDICT --- */
   if (ps->body_integrity && ps->header_vfy && ps->envelope_vfy)
   {
      dkim2_verdict = "pass";
      snprintf(dkim2_details, sizeof(dkim2_details),
               "i=%d d=%s", ps->max_hop, sig_d);
      ps->chain_vfy = 1;
   }
   else if (ps->body_integrity && ps->header_vfy && !ps->envelope_vfy)
   {
      dkim2_verdict = "fail";
      snprintf(dkim2_details, sizeof(dkim2_details),
               "envelope mismatch i=%d d=%s", ps->max_hop, sig_d);
   }
   else
   {
      dkim2_verdict = "fail";
      snprintf(dkim2_details, sizeof(dkim2_details),
               "verification failed i=%d d=%s", ps->max_hop, sig_d);
   }

cleanup_key:
   if (pubkey)
   {
      EVP_PKEY_free(pubkey);
      pubkey = NULL;
   }

inject_result:

   /* --- 7b. STRIP IMPLAUSIBLE DKIM2-AUTHENTICATION-RESULTS --- */
   /* AR is unsigned trace: any peer can inject it.  max_hop is derived
    * from signed structural headers only (see dc_header), so an injected
    * AR cannot poison the chain — but it must not travel further either:
    * it feeds the signer's Case B downstream.  Legitimate ARs always
    * satisfy 1 <= i= <= max_hop + 1: each emitter writes at its own next
    * hop, and a non-signing forwarder cannot push it beyond max_hop + 1
    * (a second no-key forwarder still sees the same structural max_hop
    * and writes at the same level again).  Strip anything with a
    * missing/invalid i= or i= > max_hop + 1 and log it: an implausible
    * AR is positive evidence of spurious header injection.  Verdict is
    * NOT affected — an unsigned field must never drive the outcome of a
    * cryptographic verification.  External boundary only, like the
    * X-DarkChain-Internal-Status anti-spoofing strip: localhost resubmit
    * sessions (signer Case B/C input) are trusted and never touched.
    * Not gated on dc_domain_enabled: a list-only domain re-emits the
    * message and must not propagate spurious trace either. */
   if (ps->is_localhost == 0)
   {
      int ar_del[MAX_HEADER_COUNT];
      int ar_del_cnt = 0;
      int ar_idx = 0;   /* 1-based per-name occurrence, message order */

      for (int j = 0; j < ps->header_cnt; j++)
      {
         if (strcasecmp(ps->headers[j].name,
                        "DKIM2-Authentication-Results") != 0)
            continue;
         ar_idx++;

         int ar_hop = dc_get_hop_index(ps->headers[j].value);
         if (ar_hop < 0 || ar_hop > ps->max_hop + 1)
         {
            syslog(LOG_NOTICE,
                   "DC_EOM: Stripping implausible DKIM2-Auth-Results "
                   "(occurrence %d, i=%d, max_hop=%d) — spurious injection",
                   ar_idx, ar_hop, ps->max_hop);
            ar_del[ar_del_cnt++] = ar_idx;
         }
      }

      /* Delete highest milter index first: smfi_chgheader indexes
       * occurrences per name and deletions shift later indices. */
      for (int k = ar_del_cnt - 1; k >= 0; k--)
         smfi_chgheader(ctx, "DKIM2-Authentication-Results", ar_del[k], NULL);
   }

   /* --- 8. INJECT DKIM2-AUTHENTICATION-RESULTS --- */
   /* Only inject if this host is DKIM2-enabled for the recipient domain.
    * Inbound MTA sessions are per recipient domain, so rcpt_to[0] is
    * representative. A domain that is not in the table (e.g. a list-only
    * domain like pacedisarmo.org co-hosted with a DKIM2 domain) must NOT
    * inject a DKIM2-AR: the chain begins at the first DKIM2-enabled hop. */
   if (ps->is_localhost == 0 &&
       ps->envelope.rcpt_count > 0 &&
       dc_domain_enabled(ps->envelope.rcpt_to[0]))
   {
      int next_hop = (ps->max_hop > 0) ? ps->max_hop + 1 : 1;

      char ar_string[512];
      snprintf(ar_string, sizeof(ar_string),
               "i=%d; %s; dkim2=%s",
               next_hop, my_hostname, dkim2_verdict);

      smfi_addheader(ctx, "DKIM2-Authentication-Results", ar_string);

      /* Timing header */
      clock_gettime(CLOCK_MONOTONIC, &ts_end);
      ps->cpu_ns += diff_ns(ts_start, ts_end);

      struct timespec now;
      clock_gettime(CLOCK_MONOTONIC, &now);
      unsigned long long total_ns = diff_ns(ps->start_time, now);
      unsigned long long other_ns = (total_ns > (ps->cpu_ns + ps->dns_ns)) ?
         total_ns - (ps->cpu_ns + ps->dns_ns) : 0;

      char cpu_buf[32], dns_buf[32], other_buf[32];
      format_runtime(ps->cpu_ns, cpu_buf, sizeof(cpu_buf));
      format_runtime(ps->dns_ns, dns_buf, sizeof(dns_buf));
      format_runtime(other_ns, other_buf, sizeof(other_buf));

      char h_val[1024];
      char hs_val[128];

      if (ps->body_size < 1024)
         snprintf(hs_val, sizeof(hs_val), "%lld bytes", ps->body_size);
      else if (ps->body_size < 1048576)
         snprintf(hs_val, sizeof(hs_val), "%lld Kbytes", ps->body_size / 1024);
      else
         snprintf(hs_val, sizeof(hs_val), "%lld Mbytes", ps->body_size / 1048576);

      snprintf(h_val, sizeof(h_val), "%s; hops=%d; d=%s; %s; cpu=%s; dns=%s; other=%s",
               dkim2_verdict, next_hop, signing_domain, hs_val,
               cpu_buf, dns_buf, other_buf);

      smfi_addheader(ctx, "X-DarkChain-Internal-Status", h_val);
   }

   /* --- 9. ENFORCEMENT --- */
   if (ENFORCE && ps->is_localhost == 0)
   {
      if (strcmp(dkim2_verdict, "fail") == 0 ||
          strcmp(dkim2_verdict, "permerror") == 0)
      {
         syslog(LOG_NOTICE,
                "DC_EOM: ENFORCE reject — dkim2=%s d=%s",
                dkim2_verdict, signing_domain);
         smfi_setreply(ctx, "550", "5.7.1",
                       "DKIM2 verification failed");
         return SMFIS_REJECT;
      }
      if (strcmp(dkim2_verdict, "temperror") == 0)
      {
         syslog(LOG_NOTICE,
                "DC_EOM: ENFORCE tempfail — dkim2=%s",
                dkim2_verdict);
         smfi_setreply(ctx, "451", "4.7.1",
                       "DKIM2 temporary verification error");
         return SMFIS_TEMPFAIL;
      }
   }

   return SMFIS_CONTINUE;
}


/* ---- dc_abort ---- */
static sfsistat dc_abort(SMFICTX *ctx)
{
   struct context *ps = (struct context *)smfi_getpriv(ctx);
   if (ps != NULL)
   {
      dc_cleanup_message(ps);
   }
   return SMFIS_CONTINUE;
}


/* ---- dc_close ---- */
static sfsistat dc_close(SMFICTX *ctx)
{
   struct context *ps = (struct context *)smfi_getpriv(ctx);
   if (ps != NULL)
   {
      dc_cleanup_message(ps);
      if (ps->rb_scratch)
      {
         free(ps->rb_scratch);
         ps->rb_scratch = NULL;
      }
      smfi_setpriv(ctx, NULL);
      free(ps);
   }
   return SMFIS_CONTINUE;
}


/* ---- dc_negotiate ---- */
static sfsistat dc_negotiate(SMFICTX *ctx,
   unsigned long f0, unsigned long f1,
   unsigned long f2, unsigned long f3,
   unsigned long *pf0, unsigned long *pf1,
   unsigned long *pf2, unsigned long *pf3)
{
   (void)ctx; (void)f0; (void)f1; (void)f2; (void)f3;

   *pf0 = SMFIF_ADDHDRS | SMFIF_CHGHDRS;
   *pf1 = SMFIP_NOUNKNOWN | SMFIP_NODATA;
   *pf2 = 0;
   *pf3 = 0;

   return SMFIS_CONTINUE;
}


/* ---- dc_cleanup_message ---- */
static void dc_cleanup_message(struct context *priv)
{
   if (priv == NULL) return;

   if (priv->headers)
   {
      free(priv->headers);
      priv->headers = NULL;
   }

   if (priv->envelope.rcpt_to)
   {
      free(priv->envelope.rcpt_to);
      priv->envelope.rcpt_to = NULL;
   }
   priv->envelope.rcpt_count = 0;
   priv->envelope.rcpt_capacity = 0;

   if (priv->mdctx_body)
   {
      EVP_MD_CTX_free(priv->mdctx_body);
      priv->mdctx_body = NULL;
   }
   if (priv->mdctx_header)
   {
      EVP_MD_CTX_free(priv->mdctx_header);
      priv->mdctx_header = NULL;
   }

   priv->msg_count = 0;
}


/* ================================================================
 * MAIN
 * ================================================================ */

static void dc_usage(const char *prog)
{
   fprintf(stderr, "usage: %s [-u user] [-p pipe]\n", prog);
   exit(1);
}

void cleanup_and_exit(int sig)
{
   (void)sig;
   static const char msg[] = "Signal received, exiting...\n";
   write(2, msg, sizeof(msg) - 1);
   /* _exit, not exit: exit() runs atexit handlers and flushes stdio,
    * which is not async-signal-safe inside a signal handler. */
   _exit(0);
}

int main(int argc, char *argv[])
{
   tzset();
   openlog("DarkChain", LOG_PID | LOG_NDELAY, SYSLOG_FACILITY);

   /* Get local FQDN at runtime */
   {
      char shortname[256];
      if (gethostname(shortname, sizeof(shortname)) == 0)
      {
         struct addrinfo hints = {0}, *res = NULL;
         hints.ai_flags = AI_CANONNAME;
         hints.ai_family = AF_UNSPEC;
         if (getaddrinfo(shortname, NULL, &hints, &res) == 0 &&
             res && res->ai_canonname)
         {
            securecpy(my_hostname, res->ai_canonname, sizeof(my_hostname));
            freeaddrinfo(res);
         }
         else
         {
            securecpy(my_hostname, shortname, sizeof(my_hostname));
            if (res) freeaddrinfo(res);
         }
      }
      else
         securecpy(my_hostname, "localhost", sizeof(my_hostname));
   }

   /* Load DKIM2-enabled domains: gate DKIM2-AR injection on membership. */
   dc_load_domains(DC_DOMAINS_CONF);

   int i_get = 0, i_ret = 0;
   const char *pc_ofile = NULL;
   bool b_fail = 0;

   while ((i_get = getopt(argc, argv, "p:u:")) != -1)
   {
      switch (i_get)
      {
         case 'p':
            pc_oconn = optarg;
            break;
         case 'u':
            pc_user = optarg;
            break;
         default:
            dc_usage(argv[0]);
      }
   }

   if (!strncmp(pc_oconn, "unix:", 5))
      pc_ofile = pc_oconn + 5;
   else if (!strncmp(pc_oconn, "local:", 6))
      pc_ofile = pc_oconn + 6;
   if (pc_ofile) unlink(pc_ofile);

   if (!getuid())
   {
      struct passwd *pw;
      if ((pw = getpwnam(pc_user)) == NULL)
      {
         fprintf(stderr, "getpwnam: %s: %s\n", pc_user, strerror(errno));
         return 1;
      }
      setgroups(1, &pw->pw_gid);
      if (setegid(pw->pw_gid) || setgid(pw->pw_gid))
      {
         fprintf(stderr, "setgid: %s\n", strerror(errno));
         return 1;
      }
      /* setuid MUST come first: as root it sets ruid/euid/suid at once.
       * The reverse order (seteuid first) drops the effective CAP_SETUID
       * and the subsequent setuid fails with EPERM on Linux. */
      if (setuid(pw->pw_uid) || seteuid(pw->pw_uid))
      {
         fprintf(stderr, "setuid: %s\n", strerror(errno));
         return 1;
      }
   }

   if (smfi_setconn((char *)pc_oconn) != MI_SUCCESS)
   {
      fprintf(stderr, "smfi_setconn: %s: failed\n", pc_oconn);
      b_fail = 1;
   }

   if (!b_fail && smfi_register(chainmilter) != MI_SUCCESS)
   {
      fprintf(stderr, "smfi_register: failed\n");
      goto done;
   }

   if (!b_fail && daemon(0, 0))
   {
      fprintf(stderr, "daemon: %s\n", strerror(errno));
      i_ret = 1;
      goto done;
   }

   /* Setup failed (setconn/register): do not enter smfi_main, which
    * would fail obscurely; exit with a nonzero status instead. */
   if (b_fail)
   {
      i_ret = 1;
      goto done;
   }

   umask(0177);
   signal(SIGPIPE, SIG_IGN);
   signal(SIGTERM, cleanup_and_exit);
   signal(SIGINT,  cleanup_and_exit);

   /* Load header hash exclusion patterns */
   load_hh_excludes(DC_HH_EXCLUDE_CONF);

   syslog(LOG_INFO, "DarkChain inbound verifier starting on %s", pc_oconn);

   i_ret = smfi_main();

   if (i_ret != MI_SUCCESS)
      syslog(LOGLEVEL, "[ERROR] DarkChain terminated due to a fatal error");

done:
   return i_ret;
}
