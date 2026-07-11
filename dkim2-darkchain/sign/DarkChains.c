/*
 * DarkChains - DKIM2-core Outbound Signer Milter
 *
 * Implements the outbound signing side of the DKIM2-core profile
 * as defined in draft-moccia-dkim2-deployment-profile.
 *
 * Based on DarkARCs by Vittorio Moccia / ITB.it
 *
 * Copyright (c) 2026 Vittorio Moccia / ITB.it
 * Licensed under Apache 2.0 License.
 *
 * ================================================================
 * SIGNING LOGIC
 * ================================================================
 *
 * The signer operates ONLY on localhost connections (outbound mail).
 * It reads the hop number from X-DarkChain-Internal-Status (set by
 * the inbound verifier DarkChain) and signs at that hop.
 *
 * If no X-DarkChain-Internal-Status is present (locally originated
 * mail), it signs as i=1.
 *
 * Signed header set (draft §3.2.4):
 *   1. Previous DKIM2-Signatures (i=1..N-1)               + CRLF
 *   2. Our DKIM2-Sig-mf (i=N)                             + CRLF
 *   3. Our DKIM2-Sig-rt (i=N, one per RCPT TO)            + CRLF
 *   4. ALL DKIM2-Mod with i<=N (from previous hops)        + CRLF
 *   5. Message headers listed in h=                        + CRLF
 *   6. Our DKIM2-Signature with b= empty                   NO CRLF
 *
 * NOT signed: Received:, Return-Path:, trace headers.
 *
 * Signing uses buffer accumulation (one-shot) for both RSA and
 * Ed25519, to enable future multi-algorithm support.
 * ================================================================
 */

#include "../dc_shared.h"
#include <netdb.h>
#include <stdint.h>
#include <openssl/hmac.h>

/* ================================================================
 * CONFIGURATION
 * ================================================================ */

#define OCONN           "unix:/var/spool/DarkChains/sock"
/* --- DEFAULT DOMAIN (currently unused — reserved for future relay fallback) --- */
#define DEFAULT_DOMAIN  "itb.it"          /* Fallback for relay signing   */
#define DEFAULT_SELECT  "dkim2"           /* Fallback selector            */
#define DEFAULT_KEYPATH "/etc/DarkChains/default.private"
/* --- END DEFAULT DOMAIN --- */
#define USER            "smmsp"
#define LOGLEVEL        LOG_NOTICE
#define SYSLOG_FACILITY LOG_DAEMON
#define DEBUG           0

/* Parse -l argument to syslog level */
static int parse_loglevel(const char *s)
{
   if (strcasecmp(s, "debug")   == 0) return LOG_DEBUG;
   if (strcasecmp(s, "info")    == 0) return LOG_INFO;
   if (strcasecmp(s, "notice")  == 0) return LOG_NOTICE;
   if (strcasecmp(s, "warning") == 0) return LOG_WARNING;
   if (strcasecmp(s, "err")     == 0) return LOG_ERR;
   if (strcasecmp(s, "error")   == 0) return LOG_ERR;
   return -1;
}
#define ALGORITHM       "rsa-sha256"   /* or "ed25519-sha256" */

#define DC_DOMAINS_CONF "/etc/DarkChains/domains.conf"
#define DC_MAX_DOMAINS  32

/* Optional SRS secret for forward-path rewrite forge-resistance.
 * If the file is absent, SRS addresses are still well-formed and routable
 * but carry no cryptographic forge-resistance (acceptable when inbound
 * bounce SRS is not validated). */
#define DC_SRS_KEY_CONF "/etc/DarkChains/srs.key"

/* h= fields — message headers only, never DKIM2-* */
#define H_FIELDS        "from:to:subject:date:message-id"

/* Header hash exclusion config path */
#define DC_HH_EXCLUDE_CONF  "/etc/DarkChains/hh_exclude.conf"
#define NOLOCALSIGN  0

/* ================================================================
 * DATA STRUCTURES (signer-specific)
 * ================================================================ */

struct context
{
   int msg_count;

   struct header_slot *headers;
   int  header_cnt;
   int  header_capacity;

   /* Hop from verifier */
   char verifier_verdict[32];   /* pass/fail/none                         */
   int  internal_status_count;  /* count of Internal-Status headers seen   */
   int  found_prev_sigs;        /* count of DKIM2-Signature in reservoir  */
   int  max_prev_hop;           /* highest i= seen across ALL DKIM2 headers */

   /* Envelope */
   struct dc_envelope envelope;

   /* Body hash (relaxed) */
   EVP_MD_CTX *mdctx_body;
   long long body_size;   /* long long: int would overflow past 2GB */
   int  pending_newlines;
   int  body_has_content;
   int  p_had_space;
   int  is_start_of_line;

   int  is_localhost;
   int  is_local_delivery;       /* 1 if all RCPT TO are local (no smtp/esmtp) */
   char rcpt_to_orig[DC_MAX_ADDR]; /* RCPT TO pre-virtusertable (argv[0])    */
   char helo[MAXHOST];

   struct timespec start_time;
   unsigned long long cpu_ns;
};


/* ================================================================
 * DOMAIN-KEY TABLE
 * ================================================================ */

struct dc_domain_key
{
   char      domain[256];
   char      selector[128];
   char      keypath[512];
   EVP_PKEY *pkey;
};

static struct dc_domain_key domain_table[DC_MAX_DOMAINS];
static int domain_count = 0;
/* --- DEFAULT DOMAIN (currently unused — reserved for future relay fallback) --- */
static struct dc_domain_key default_dk;  /* Fallback for relay signing */
static int default_dk_loaded = 0;
/* --- END DEFAULT DOMAIN --- */


/* ================================================================
 * GLOBALS
 * ================================================================ */

const char *pc_oconn = OCONN;
const char *pc_user  = USER;
char  my_hostname[256] = "";


/* ================================================================
 * SRS (forward-path rewrite) — canonical SRS0 form
 * ================================================================ */

static unsigned char srs_secret[256];
static size_t        srs_secret_len = 0;

/* RFC 4648 base32 alphabet, address-safe (no '=' which is the SRS sep) */
static const char SRS_B32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static void load_srs_secret(const char *path)
{
   FILE *fp = fopen(path, "r");
   if (!fp)
   {
      syslog(LOG_INFO,
             "DCS_MAIN: no SRS key at %s — SRS forge-resistance disabled", path);
      return;
   }
   size_t n = fread(srs_secret, 1, sizeof(srs_secret), fp);
   fclose(fp);
   while (n > 0 && (srs_secret[n - 1] == '\n' || srs_secret[n - 1] == '\r' ||
                    srs_secret[n - 1] == ' '  || srs_secret[n - 1] == '\t'))
      n--;
   srs_secret_len = n;
   syslog(LOG_INFO, "DCS_MAIN: loaded SRS key (%zu bytes)", srs_secret_len);
}

/* Emit out_chars base32 symbols from the bit stream of in[] */
static void srs_base32(const unsigned char *in, size_t inlen,
                       char *out, size_t out_chars)
{
   size_t bits = 0, oi = 0;
   uint32_t buf = 0;
   for (size_t i = 0; i < inlen && oi < out_chars; i++)
   {
      buf = (buf << 8) | in[i];
      bits += 8;
      while (bits >= 5 && oi < out_chars)
      {
         bits -= 5;
         out[oi++] = SRS_B32[(buf >> bits) & 0x1f];
      }
   }
   while (oi < out_chars) out[oi++] = SRS_B32[0];
   out[oi] = '\0';
}


/* ================================================================
 * FORWARD DECLARATIONS
 * ================================================================ */

static sfsistat dcs_connect(SMFICTX *, char *, _SOCK_ADDR *);
static sfsistat dcs_helo(SMFICTX *, char *);
static sfsistat dcs_envfrom(SMFICTX *, char **);
static sfsistat dcs_envrcpt(SMFICTX *, char **);
static sfsistat dcs_header(SMFICTX *, char *, char *);
static sfsistat dcs_eoh(SMFICTX *);
static sfsistat dcs_body(SMFICTX *, u_char *, size_t);
static sfsistat dcs_eom(SMFICTX *);
static sfsistat dcs_abort(SMFICTX *);
static sfsistat dcs_close(SMFICTX *);
static sfsistat dcs_negotiate(SMFICTX *,
   unsigned long, unsigned long, unsigned long, unsigned long,
   unsigned long *, unsigned long *, unsigned long *, unsigned long *);

struct smfiDesc chainsmilter = {
   "DarkChains",
   SMFI_VERSION,
   SMFIF_ADDHDRS | SMFIF_CHGHDRS | SMFIF_CHGFROM,
   dcs_connect, dcs_helo, dcs_envfrom, dcs_envrcpt,
   dcs_header, dcs_eoh, dcs_body, dcs_eom,
   dcs_abort, dcs_close,
   NULL, NULL, dcs_negotiate
};


/* ================================================================
 * DOMAIN TABLE
 * ================================================================ */

static int load_domain_table(const char *conf_path)
{
   FILE *fp = fopen(conf_path, "r");
   if (!fp) { syslog(LOG_ERR, "DCS_MAIN: Cannot open %s: %s", conf_path, strerror(errno)); return -1; }

   char line[1024];
   domain_count = 0;

   while (fgets(line, sizeof(line), fp) && domain_count < DC_MAX_DOMAINS)
   {
      char *p = line;
      while (*p == ' ' || *p == '\t') p++;
      if (*p == '#' || *p == '\n' || *p == '\0') continue;

      char dom[256], sel[128], path[512];
      if (sscanf(p, "%255s %127s %511s", dom, sel, path) != 3) continue;

      EVP_PKEY *pkey = load_private_key(path);
      if (!pkey) continue;

      securecpy(domain_table[domain_count].domain, dom, 256);
      securecpy(domain_table[domain_count].selector, sel, 128);
      securecpy(domain_table[domain_count].keypath, path, 512);
      domain_table[domain_count].pkey = pkey;

      syslog(LOG_INFO, "DCS_MAIN: Loaded key for %s (selector=%s, bits=%d)",
             dom, sel, EVP_PKEY_bits(pkey));
      domain_count++;
   }
   fclose(fp);
   return domain_count;
}

static struct dc_domain_key *lookup_domain_key(const char *mail_from)
{
   if (!mail_from || !*mail_from) return NULL;
   const char *at = strchr(mail_from, '@');
   const char *domain = at ? at + 1 : mail_from;

   for (int i = 0; i < domain_count; i++)
      if (strcasecmp(domain, domain_table[i].domain) == 0)
         return &domain_table[i];

   /* Relaxed: remove up to 2 labels */
   const char *p = domain;
   for (int removed = 0; removed < 2; removed++)
   {
      p = strchr(p, '.');
      if (!p) break;
      p++;
      for (int i = 0; i < domain_count; i++)
         if (strcasecmp(p, domain_table[i].domain) == 0)
            return &domain_table[i];
   }
   return NULL;
}


/* ================================================================
 * MILTER CALLBACKS
 * ================================================================ */

/* ---- dcs_connect ---- */
static sfsistat dcs_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr)
{
   struct context *ps = calloc(1, sizeof(struct context));
   if (!ps) return SMFIS_TEMPFAIL;
   smfi_setpriv(ctx, ps);

   ps->mdctx_body = EVP_MD_CTX_new();
   if (!ps->mdctx_body)
   {
      free(ps);
      smfi_setpriv(ctx, NULL);
      return SMFIS_TEMPFAIL;
   }
   EVP_DigestInit_ex(ps->mdctx_body, EVP_sha256(), NULL);

   ps->header_capacity = INITIAL_CAPACITY;
   ps->headers = calloc(ps->header_capacity, sizeof(struct header_slot));

   ps->envelope.rcpt_capacity = DC_RCPT_INITIAL;
   ps->envelope.rcpt_to = calloc(DC_RCPT_INITIAL, DC_MAX_ADDR);

   if (!ps->headers || !ps->envelope.rcpt_to)
   {
      syslog(LOG_ERR, "DCS_CONNECT: allocation failed");
      EVP_MD_CTX_free(ps->mdctx_body);
      free(ps->headers);
      free(ps->envelope.rcpt_to);
      free(ps);
      smfi_setpriv(ctx, NULL);
      return SMFIS_TEMPFAIL;
   }

   ps->is_localhost = 0;

   /* Localhost detection */
   char *c_addr = smfi_getsymval(ctx, "{client_addr}");
   if (c_addr)
   {
      if (strncmp(c_addr, "127.", 4) == 0 ||
          strcmp(c_addr, "::1") == 0 ||
          strncasecmp(c_addr, "::ffff:127.", 11) == 0)
         ps->is_localhost = 1;
   }
   if (!ps->is_localhost && hostaddr)
   {
      if (hostaddr->sa_family == AF_UNIX)
         ps->is_localhost = 1;
      else if (hostaddr->sa_family == AF_INET)
      {
         struct sockaddr_in *sa = (struct sockaddr_in *)hostaddr;
         if ((ntohl(sa->sin_addr.s_addr) >> 24) == 0x7F) ps->is_localhost = 1;
      }
      else if (hostaddr->sa_family == AF_INET6)
      {
         struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)hostaddr;
         if (IN6_IS_ADDR_LOOPBACK(&sa6->sin6_addr)) ps->is_localhost = 1;
         else if (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr))
            if (sa6->sin6_addr.s6_addr[12] == 0x7F) ps->is_localhost = 1;
      }
   }

   syslog(LOG_INFO, "DCS_CONNECT [%s]: client_addr='%s', is_localhost=%d",
          hostname ? hostname : "unknown", c_addr ? c_addr : "NULL", ps->is_localhost);

   return SMFIS_CONTINUE;
}

/* ---- dcs_helo ---- */
static sfsistat dcs_helo(SMFICTX *ctx, char *helo)
{
   struct context *ps = (struct context *)smfi_getpriv(ctx);
   if (!ps) return SMFIS_ACCEPT;
   securecpy(ps->helo, helo, sizeof(ps->helo));
   return SMFIS_CONTINUE;
}

/* ---- dcs_envfrom ---- */
static sfsistat dcs_envfrom(SMFICTX *ctx, char **argv)
{
   struct context *ps = (struct context *)smfi_getpriv(ctx);
   if (!ps) return SMFIS_TEMPFAIL;

   clock_gettime(CLOCK_MONOTONIC, &ps->start_time);

   if (argv[0])
      dc_strip_angle_brackets(argv[0], ps->envelope.mail_from, sizeof(ps->envelope.mail_from));
   else
      ps->envelope.mail_from[0] = '\0';

   ps->msg_count++;
   ps->header_cnt = 0;
   ps->verifier_verdict[0] = '\0';
   ps->internal_status_count = 0;
   ps->found_prev_sigs = 0;
   ps->max_prev_hop = 0;
   ps->is_local_delivery = 1;   /* assume local until smtp/esmtp rcpt seen */
   ps->rcpt_to_orig[0] = '\0';
   ps->envelope.rcpt_count = 0;
   ps->body_size = 0;
   ps->pending_newlines = 0;
   ps->body_has_content = 0;
   ps->p_had_space = 0;
   ps->is_start_of_line = 0;
   ps->cpu_ns = 0;

   if (ps->mdctx_body)
   {
      EVP_MD_CTX_reset(ps->mdctx_body);
      EVP_DigestInit_ex(ps->mdctx_body, EVP_sha256(), NULL);
   }

   if (ps->headers)
      memset(ps->headers, 0, ps->header_capacity * sizeof(struct header_slot));

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
         syslog(LOG_ERR, "DCS_ENVFROM: EVP_MD_CTX_new failed");
         return SMFIS_TEMPFAIL;
      }
      EVP_DigestInit_ex(ps->mdctx_body, EVP_sha256(), NULL);
   }

   return SMFIS_CONTINUE;
}

/* ---- dcs_envrcpt ---- */
static sfsistat dcs_envrcpt(SMFICTX *ctx, char **argv)
{
   struct context *ps = (struct context *)smfi_getpriv(ctx);
   if (!ps) return SMFIS_CONTINUE;

   /* Sendmail macros: {rcpt_addr} contains the resolved address
    * (post-alias, post-virtusertable). argv[0] is the original
    * RCPT TO from the SMTP wire.  For forwarding, we need the
    * resolved address so that rt= matches the next hop's RCPT TO.
    *
    * Save argv[0] (pre-virtusertable) for domain key lookup —
    * in forwarding, the original RCPT TO domain may be in our table
    * while the resolved domain is not.
    */
   if (ps->rcpt_to_orig[0] == '\0' && argv[0])
      dc_strip_angle_brackets(argv[0], ps->rcpt_to_orig, sizeof(ps->rcpt_to_orig));

   const char *rcpt_addr = smfi_getsymval(ctx, "{rcpt_addr}");
   const char *rcpt_host = smfi_getsymval(ctx, "{rcpt_host}");
   const char *effective_rcpt = argv[0];  /* fallback */


   /* Always check rcpt_mailer to track local vs remote delivery */
   const char *mailer = smfi_getsymval(ctx, "{rcpt_mailer}");
   if (mailer != NULL)
   {
      syslog(LOG_DEBUG, "DCS_ENVRCPT: rcpt_mailer for %s is %s", argv[0], mailer);

      if (strcmp(mailer, "smtp") == 0 || strcmp(mailer, "esmtp") == 0)
      {
         /* At least one remote recipient → not purely local */
         ps->is_local_delivery = 0;
      }
      else if (NOLOCALSIGN)
      {
         return SMFIS_ACCEPT;  /* Skip signing for local delivery */
      }
   }


   /* If rcpt_addr contains '@', it's a full resolved address — use it */
   char resolved_addr[512] = "";
   if (rcpt_addr && strchr(rcpt_addr, '@'))
   {
      securecpy(resolved_addr, rcpt_addr, sizeof(resolved_addr));
      effective_rcpt = resolved_addr;
   }
   else if (rcpt_addr && rcpt_addr[0] && rcpt_host && rcpt_host[0])
   {
      /* rcpt_addr is local part only (e.g. "vincenzo"), add host */
      char host_clean[256];
      securecpy(host_clean, rcpt_host, sizeof(host_clean));
      /* Remove trailing dot from rcpt_host if present */
      int hlen = strlen(host_clean);
      if (hlen > 0 && host_clean[hlen - 1] == '.')
         host_clean[hlen - 1] = '\0';
      snprintf(resolved_addr, sizeof(resolved_addr), "%s@%s",
               rcpt_addr, host_clean);
      effective_rcpt = resolved_addr;
   }

   syslog(LOG_DEBUG, "DCS_ENVRCPT: argv='%s' resolved='%s'",
          argv[0] ? argv[0] : "NULL", effective_rcpt);

   if (effective_rcpt && ps->envelope.rcpt_count < DC_MAX_RT)
   {
      if (ps->envelope.rcpt_count >= ps->envelope.rcpt_capacity)
      {
         int new_cap = ps->envelope.rcpt_capacity * 2;
         if (new_cap > DC_MAX_RT) new_cap = DC_MAX_RT;
         char (*new_rt)[DC_MAX_ADDR] = realloc(ps->envelope.rcpt_to, new_cap * DC_MAX_ADDR);
         if (!new_rt) return SMFIS_TEMPFAIL;
         ps->envelope.rcpt_to = new_rt;
         ps->envelope.rcpt_capacity = new_cap;
      }
      dc_strip_angle_brackets(effective_rcpt,
                              ps->envelope.rcpt_to[ps->envelope.rcpt_count],
                              DC_MAX_ADDR);
      ps->envelope.rcpt_count++;
   }
   return SMFIS_CONTINUE;
}

/* ---- dcs_header ---- */
static sfsistat dcs_header(SMFICTX *ctx, char *headerf, char *headerv)
{
   struct context *ps = (struct context *)smfi_getpriv(ctx);
   if (!ps) return SMFIS_CONTINUE;

   /* Detect X-DarkChain-Internal-Status from the verifier.
    * Multiple instances = possible injection attack → permerror.
    */
   if (strcasecmp(headerf, "X-DarkChain-Internal-Status") == 0)
   {
      ps->internal_status_count++;
      if (ps->internal_status_count > 1)
      {
         securecpy(ps->verifier_verdict, "permerror", sizeof(ps->verifier_verdict));
         syslog(LOG_WARNING,
                "DCS_HEADER: Multiple X-DarkChain-Internal-Status detected "
                "(%d) — possible injection, forcing permerror",
                ps->internal_status_count);
         return SMFIS_CONTINUE;
      }

      char tmp[256];
      securecpy(tmp, headerv, sizeof(tmp));
      char *semi = strchr(tmp, ';');
      if (semi) *semi = '\0';
      trim(tmp);
      securecpy(ps->verifier_verdict, tmp, sizeof(ps->verifier_verdict));

      syslog(LOG_INFO, "DCS_HEADER: Verifier status: verdict=%s",
             ps->verifier_verdict);
      return SMFIS_CONTINUE;  /* Don't store this in reservoir */
   }

   /* Expand reservoir if needed */
   if (ps->header_cnt >= ps->header_capacity)
   {
      if (ps->header_capacity >= MAX_HEADER_COUNT)
         return SMFIS_CONTINUE;
      int new_cap = ps->header_capacity + INITIAL_CAPACITY;
      struct header_slot *new_ptr = realloc(ps->headers, new_cap * sizeof(struct header_slot));
      if (!new_ptr) return SMFIS_TEMPFAIL;
      ps->headers = new_ptr;
      ps->header_capacity = new_cap;
   }

   struct header_slot *slot = &ps->headers[ps->header_cnt];
   strncpy(slot->name, headerf, MAX_HEADER_NAME - 1);
   slot->name[MAX_HEADER_NAME - 1] = '\0';
   unfold_header(headerv);
   if (strlen(headerv) >= BIG_HEADER_VALUE)
      syslog(LOG_NOTICE,
             "DCS_HEADER: header '%s' truncated to %d bytes — "
             "hh= will be computed on the truncated value",
             headerf, BIG_HEADER_VALUE - 1);
   strncpy(slot->value, headerv, BIG_HEADER_VALUE - 1);
   slot->value[BIG_HEADER_VALUE - 1] = '\0';
   slot->used_for_signature = 0;
   slot->dc_type = DC_HDR_OTHER;
   slot->hop = 0;
   slot->seq = 0;
   slot->fr = 0;
   slot->is_new = 0;

   /* Classify DKIM2 headers */
   if (strncasecmp(headerf, "DKIM2-", 6) == 0)
   {
      int hop = dc_get_hop_index(headerv);
      if (hop > 0)
      {
         slot->hop = hop;

         if (strcasecmp(headerf, "DKIM2-Signature") == 0)
         {
            slot->dc_type = DC_HDR_SIG;
            ps->found_prev_sigs++;
            if (hop > ps->max_prev_hop)
               ps->max_prev_hop = hop;
         }
         else if (strcasecmp(headerf, "DKIM2-Mod") == 0)
         {
            slot->dc_type = DC_HDR_MOD;
            if (hop > ps->max_prev_hop)
               ps->max_prev_hop = hop;
            /* dc_get_tag_int, like the verifier: missing, non-numeric
             * or negative values normalize to 0 (then to 1 below);
             * raw atoi would let negatives through. */
            slot->seq = dc_get_tag_int(headerv, "seq");
            slot->fr  = dc_get_tag_int(headerv, "fr");
            const char *v = dc_find_tag(headerv, "new");
            slot->is_new = (v != NULL) ? 1 : 0;

            if (slot->seq == 0) slot->seq = 1;
            if (slot->fr == 0)  slot->fr = 1;
         }
      }
   }

   ps->header_cnt++;
   return SMFIS_CONTINUE;
}

/* ---- dcs_eoh ---- */
static sfsistat dcs_eoh(SMFICTX *ctx)
{
   struct context *ps = (struct context *)smfi_getpriv(ctx);
   if (!ps) return SMFIS_ACCEPT;

   if (ps->verifier_verdict[0] != '\0' && ps->found_prev_sigs > 0 &&
       ps->max_prev_hop != ps->found_prev_sigs)
   {
      syslog(LOG_NOTICE,
             "DCS_EOH: Hop mismatch: max_prev_hop=%d but sigs=%d",
             ps->max_prev_hop, ps->found_prev_sigs);
   }

   return SMFIS_CONTINUE;
}

/* ---- dcs_body ---- */
static sfsistat dcs_body(SMFICTX *ctx, unsigned char *bodyp, size_t bodylen)
{
   struct context *ps = (struct context *)smfi_getpriv(ctx);
   if (!ps) return SMFIS_CONTINUE;

   ps->body_size += bodylen;

   register int l_pending  = ps->pending_newlines;
   register int l_had_space = ps->p_had_space;
   register int l_is_start  = ps->is_start_of_line;
   register int l_has_cont  = ps->body_has_content;

   unsigned char r_buf[BODY_BUF_SIZE];
   size_t r_idx = 0;

   size_t i = 0;
   while (i < bodylen)
   {
      unsigned char c = bodyp[i];
      if (c == '\r') { i++; continue; }
      if (c == '\n')
      {
         l_had_space = 0; l_is_start = 1; l_pending++; i++;
         continue;
      }
      if (c == ' ' || c == '\t') { l_had_space = 1; i++; continue; }

      size_t j = i + 1;
      while (j < bodylen && bodyp[j] != '\r' && bodyp[j] != '\n' &&
             bodyp[j] != ' ' && bodyp[j] != '\t') j++;
      size_t run = j - i;

      while (l_pending > 0)
      {
         if (r_idx >= BODY_BUF_SIZE - 2)
         { EVP_DigestUpdate(ps->mdctx_body, r_buf, r_idx); r_idx = 0; }
         r_buf[r_idx++] = '\r'; r_buf[r_idx++] = '\n'; l_pending--;
         l_has_cont = 1;
      }
      if (l_had_space)
      {
         if (r_idx >= BODY_BUF_SIZE)
         { EVP_DigestUpdate(ps->mdctx_body, r_buf, r_idx); r_idx = 0; }
         r_buf[r_idx++] = ' '; l_had_space = 0;
      }

      size_t space_left = BODY_BUF_SIZE - r_idx;
      if (run <= space_left)
      {
         memcpy(r_buf + r_idx, bodyp + i, run); r_idx += run;
      }
      else
      {
         memcpy(r_buf + r_idx, bodyp + i, space_left);
         EVP_DigestUpdate(ps->mdctx_body, r_buf, BODY_BUF_SIZE); r_idx = 0;
         size_t rem = run - space_left;
         if (rem >= BODY_BUF_SIZE)
            EVP_DigestUpdate(ps->mdctx_body, bodyp + i + space_left, rem);
         else
         { memcpy(r_buf, bodyp + i + space_left, rem); r_idx = rem; }
      }
      l_has_cont = 1; l_is_start = 0; i = j;
   }
   if (r_idx > 0) EVP_DigestUpdate(ps->mdctx_body, r_buf, r_idx);

   ps->pending_newlines = l_pending;
   ps->p_had_space      = l_had_space;
   ps->is_start_of_line = l_is_start;
   ps->body_has_content = l_has_cont;

   return SMFIS_CONTINUE;
}


/* ---- dcs_eom ---- */
static sfsistat dcs_eom(SMFICTX *ctx)
{
   struct context *ps = (struct context *)smfi_getpriv(ctx);
   if (!ps) return SMFIS_CONTINUE;

   /* Always strip X-DarkChain-Internal-Status — ALL occurrences.
    * internal_status_count > 1 means injection (verdict already forced
    * to permerror in dcs_header); the surviving copies must not leak
    * downstream either.  Delete highest index first: smfi_chgheader
    * indexes occurrences per name and deletions shift later indices. */
   for (int is_k = ps->internal_status_count; is_k >= 1; is_k--)
      smfi_chgheader(ctx, "X-DarkChain-Internal-Status", is_k, NULL);

   struct timespec ts_start, ts_end;
   clock_gettime(CLOCK_MONOTONIC, &ts_start);

   /* Outer gate: skip if external, no previous DKIM2 chain,
    * AND no verifier processing (verdict empty).
    * If the verifier ran (verdict is set, even "none"), proceed.
    */
   if (ps->is_localhost == 0 && ps->max_prev_hop == 0 &&
       ps->verifier_verdict[0] == '\0')
   {
      syslog(LOG_DEBUG, "DCS_EOM: Not localhost, no prev DKIM2, no verifier. Skip.");
      return SMFIS_CONTINUE;
   }

   int N;
   int generate_auth_result = 0;
   char auth_result_value[512] = "";

   if (ps->verifier_verdict[0] != '\0')
   /* Postfix patch */
   // && ps->is_localhost == 0) 
   {
      /* Case A: verifier-processed inbound/relay */
      N = ps->found_prev_sigs + 1;
      generate_auth_result = 0;
      syslog(LOG_INFO, "DCS_EOM: Case A — i=%d (verdict=%s, sigs=%d)",
             N, ps->verifier_verdict, ps->found_prev_sigs);
   }
   else if (ps->verifier_verdict[0] == '\0' && ps->is_localhost == 1 && ps->max_prev_hop > 0)
   {
      /* Case B: local mailing list signing after DKIM-Mod.
       * N = (highest DKIM2-Signature i=) + 1.  We derive this from
       * dc_max_sig_hop() — the authoritative signature-only index — rather
       * than from found_prev_sigs (a count) or max_prev_hop (a max over
       * signatures AND Mods, which sits at N when the list's Mod is present).
       * The verifier's chain-continuity check did not run on this post-list
       * path, so dc_max_sig_hop() does its own lightweight contiguity pass
       * and returns -1 on a gap; per the spec a gap means the chain is
       * unsigned, so we do not add a signature certifying a broken chain.
       */
      int max_sig = dc_max_sig_hop(ps->headers, ps->header_cnt);
      if (max_sig < 0)
      {
         syslog(LOG_NOTICE,
                "DCS_EOM: Case B — broken DKIM2-Signature chain; not signing");
         return SMFIS_CONTINUE;
      }
      N = max_sig + 1;
      generate_auth_result = 1;

      /* Verdict: propagate from the DKIM2-Authentication-Results of the
       * PREVIOUS hop, i.e. at i = N-1.  In Case B the prior AR was emitted
       * by the previous hop's verifier or signer, depending on geometry:
       * in full attestation mode (deployment profile Case 2) by the
       * pre-list signer at its own signing level (N-1); in the two-hop
       * mode (Case 1) by our own inbound verifier at max_hop+1 = N-1.
       * The list manager then added a DKIM2-Mod at level N.  The anchor
       * must be N-1, NOT max_prev_hop (which equals N when that Mod is
       * present) and NOT the highest i= among AR records (an unsigned,
       * injectable field).
       * N-1 derives from found_prev_sigs (signed chain), so a peer cannot
       * hijack selection by injecting an AR at an arbitrary i=.
       * The inbound verifier additionally strips ARs with i= > max_hop+1
       * at the external boundary, so implausible injected ARs never reach
       * this code on a DarkChain-fronted host.
       *
       *   - no AR at N-1            -> "none"   (legitimate in transition:
       *                                          a prior hop may not emit AR)
       *   - all AR at N-1 agree     -> that verdict
       *   - AR at N-1 disagree      -> "fail"   (chain error or injection;
       *                                          must not propagate a good verdict)
       *
       * "Disagreement" means differing dkim2= values at the same level.
       * Duplicate identical verdicts are not a disagreement.
       */
      const int prev_hop = N - 1;
      const char *prev_verdict = NULL;   /* NULL == not seen yet */
      int verdict_conflict = 0;
      int ar_seen = 0;

      for (int j = 0; j < ps->header_cnt; j++)
      {
         if (strcasecmp(ps->headers[j].name,
                        "DKIM2-Authentication-Results") != 0)
            continue;

         if (dc_get_hop_index(ps->headers[j].value) != prev_hop)
            continue;

         ar_seen++;

         /* Normalize this record's dkim2= to a canonical verdict.
          * AR present for this hop but no/unrecognized dkim2= -> "none".
          */
         const char *v = "none";
         const char *dv = dc_find_tag(ps->headers[j].value, "dkim2");
         if (dv)
         {
            if (strncasecmp(dv, "fail", 4) == 0)           v = "fail";
            else if (strncasecmp(dv, "temperror", 9) == 0) v = "temperror";
            else if (strncasecmp(dv, "permerror", 9) == 0) v = "permerror";
            else if (strncasecmp(dv, "none", 4) == 0)      v = "none";
            else if (strncasecmp(dv, "pass", 4) == 0)      v = "pass";
            else                                           v = "none";
         }

         if (prev_verdict == NULL)
            prev_verdict = v;
         else if (strcmp(prev_verdict, v) != 0)
            verdict_conflict = 1;
      }

      if (ar_seen == 0)
         prev_verdict = "none";
      else if (verdict_conflict)
      {
         syslog(LOG_NOTICE,
                "DCS_EOM: Case B — conflicting DKIM2-Auth-Results at i=%d; "
                "propagating fail", prev_hop);
         prev_verdict = "fail";
      }

      snprintf(auth_result_value, sizeof(auth_result_value),
               "i=%d; %s; dkim2=%s", N, my_hostname, prev_verdict);
      syslog(LOG_INFO,
             "DCS_EOM: Case B — sigs=%d, prev_verdict=%s. Signing as i=%d",
             ps->found_prev_sigs, prev_verdict, N);
   }
   else
   {
      /* Case C: locally originated mail */
      N = 1;
      generate_auth_result = 1;
      snprintf(auth_result_value, sizeof(auth_result_value),
               "i=1; %s; dkim2=none", my_hostname);
      syslog(LOG_INFO, "DCS_EOM: Case C — local mail, i=1");
   }

   /* Broken chain: if the verifier reported fail or permerror,
    * the chain is compromised — don't extend it with a new signature.
    * Internal-Status was already stripped above.
    */
   if (strcmp(ps->verifier_verdict, "fail") == 0 ||
       strcmp(ps->verifier_verdict, "permerror") == 0)
   {
      syslog(LOG_NOTICE, "DCS_EOM: Verifier verdict=%s — chain broken, skip signing",
             ps->verifier_verdict);
      return SMFIS_CONTINUE;
   }

   /* Domain lookup: try sender domain first (outbound), then
    * original RCPT TO pre-virtusertable (forwarding), then
    * resolved RCPT TO (inbound from external).
    */
   struct dc_domain_key *dk = lookup_domain_key(ps->envelope.mail_from);
   if (!dk && ps->rcpt_to_orig[0] != '\0')
   {
      /* Forwarding: original RCPT TO domain may be ours even though
       * the resolved address points elsewhere.
       */
      dk = lookup_domain_key(ps->rcpt_to_orig);
      if (dk)
         syslog(LOG_INFO, "DCS_EOM: Using original RCPT TO domain d=%s",
                dk->domain);
   }
   if (!dk && ps->envelope.rcpt_count > 0)
   {
      /* Inbound: try resolved recipient domain. */
      dk = lookup_domain_key(ps->envelope.rcpt_to[0]);
      if (dk)
         syslog(LOG_INFO, "DCS_EOM: Sender domain not in table, "
                "signing with recipient domain d=%s", dk->domain);
   }
   if (!dk && ps->envelope.mail_from[0] == '\0')
   {
      /* DSN/null sender: the bounce is generated by this MTA.
       * Sign with the MTA's own domain (from Sendmail macro 'j').
       * lookup_domain_key applies relaxed match:
       * dns.itb.it → itb.it → found in table.
       */
      const char *myhostname = smfi_getsymval(ctx, "j");
      if (myhostname)
         dk = lookup_domain_key(myhostname);
      if (dk)
         syslog(LOG_INFO, "DCS_EOM: DSN/null-sender, signing with MTA domain d=%s",
                dk->domain);
   }
   if (!dk)
   {
      syslog(LOG_NOTICE, "DCS_EOM: No key for '%s' (sender or recipient). Skip.",
             ps->envelope.mail_from);
      return SMFIS_CONTINUE;
   }

   /* ---- ENVELOPE REWRITING FOR RELAY ----
    *
    * When relaying (N > 1), d= (signing domain) may differ from the
    * MAIL FROM domain.  This causes envelope binding failure at the
    * next hop because d= and mf= domains don't match.
    *
    * Fix: rewrite MAIL FROM to an SRS-like address:
    *   SRS0=HHH=TT=origdomain=localpart@signing_domain
    *
    * where HHH is a short hash for verification and TT is a timestamp.
    * Uses smfi_chgfrom() which is available in Sendmail 8.14+.
    * On Postfix (which doesn't support chgfrom), logs a warning.
    *
    * Skip for local delivery — no need to rewrite the envelope
    * when the message is not leaving this server.
    *
    * Gate on !is_local_delivery only (not N > 1): a single-hop forward of
    * external mail (N = 1) via virtusertable also needs mf/d alignment. This
    * relies on is_local_delivery being set to 0 ONLY when a remote mailer
    * (smtp/esmtp) is seen — i.e. destination is certainly external. A "local"
    * mailer (final local mailbox, or an alias not yet expanded) keeps
    * is_local_delivery=1 and is deliberately NOT rewritten: we must never
    * SRS-rewrite the envelope of a message being delivered to a local mailbox.
    */
   if (!ps->is_local_delivery)
   {
      /* Extract domain from current MAIL FROM */
      const char *at = strchr(ps->envelope.mail_from, '@');
      const char *mf_domain = at ? at + 1 : "";

      if (mf_domain[0] != '\0' && strcasecmp(mf_domain, dk->domain) != 0)
      {
         /* Domains differ — need rewriting */
         char localpart[DC_MAX_ADDR] = "";
         if (at)
         {
            int lp_len = (int)(at - ps->envelope.mail_from);
            if (lp_len > (int)sizeof(localpart) - 1)
               lp_len = sizeof(localpart) - 1;
            memcpy(localpart, ps->envelope.mail_from, lp_len);
            localpart[lp_len] = '\0';
         }

         /* Canonical SRS0 forward-path rewrite:
          *   SRS0=HHH=TT=origdomain=localpart@signing_domain
          *
          * TT  = days-since-epoch mod 1024, 2 base32 chars.
          * HHH = HMAC-SHA1(secret, TT || origdomain || localpart) truncated
          *       to 4 base32 chars.  With no configured secret the HMAC key
          *       is empty: the address stays well-formed and routable but
          *       carries no forge-resistance (fine when inbound bounce SRS
          *       is not cryptographically validated). */
         unsigned int days = (unsigned int)(time(NULL) / 86400) % 1024;
         char tt[3];
         tt[0] = SRS_B32[(days >> 5) & 0x1f];
         tt[1] = SRS_B32[days & 0x1f];
         tt[2] = '\0';

         char mac_input[DC_MAX_ADDR * 2];
         int mac_in_len = snprintf(mac_input, sizeof(mac_input), "%s%s%s",
                                   tt, mf_domain, localpart);
         if (mac_in_len < 0) mac_in_len = 0;
         if (mac_in_len > (int)sizeof(mac_input) - 1)
            mac_in_len = (int)sizeof(mac_input) - 1;

         unsigned char mac[EVP_MAX_MD_SIZE];
         unsigned int  mac_len = 0;
         char hhh[5] = "AAAA";
         if (HMAC(EVP_sha1(), srs_secret, (int)srs_secret_len,
                  (unsigned char *)mac_input, (size_t)mac_in_len,
                  mac, &mac_len))
         {
            srs_base32(mac, mac_len, hhh, 4);
         }

         char new_mailfrom[1024];
         int nm_len = snprintf(new_mailfrom, sizeof(new_mailfrom),
                  "SRS0=%s=%s=%s=%s@%s",
                  hhh, tt, mf_domain, localpart, dk->domain);

         /* The rewritten address must fit in envelope.mail_from
          * (DC_MAX_ADDR), which feeds the signed mf= header.  A silent
          * truncation there would make mf= diverge from the actual
          * envelope and guarantee a fail at the next hop. */
         if (nm_len < 0 || nm_len >= (int)sizeof(new_mailfrom) ||
             nm_len >= DC_MAX_ADDR)
         {
            syslog(LOG_NOTICE,
                   "DCS_EOM: SRS rewrite skipped: rewritten address too long "
                   "(%d bytes, max %d). Keeping original envelope.",
                   nm_len, DC_MAX_ADDR - 1);
            /* Continue with original envelope — mf= won't align with d= */
         }
         else
         {
            syslog(LOG_INFO, "DCS_EOM: Relay rewriting MAIL FROM: '%s' -> '%s'",
                   ps->envelope.mail_from, new_mailfrom);

            if (smfi_chgfrom(ctx, new_mailfrom, NULL) == MI_FAILURE)
            {
               syslog(LOG_WARNING,
                      "DCS_EOM: smfi_chgfrom not supported by MTA. "
                      "Configure SRS at MTA level for forwarding.");
               /* Continue with original envelope — mf= won't align with d= */
            }
            else
            {
               /* Update our copy of MAIL FROM for mf= header */
               securecpy(ps->envelope.mail_from, new_mailfrom,
                         sizeof(ps->envelope.mail_from));
            }
         }
      }
   }

   /* ---- 1. FINALIZE BODY HASH ---- */
   if (ps->body_has_content)
      EVP_DigestUpdate(ps->mdctx_body, "\r\n", 2);

   unsigned char body_hash_bin[EVP_MAX_MD_SIZE];
   unsigned int body_hash_len = 0;
   if (EVP_DigestFinal_ex(ps->mdctx_body, body_hash_bin, &body_hash_len) != 1)
   {
      syslog(LOG_ERR, "DCS_EOM: EVP_DigestFinal body hash failed");
      return SMFIS_TEMPFAIL;
   }
   char *bh_b64 = encode_base64_hash(body_hash_bin, body_hash_len);
   if (!bh_b64) return SMFIS_TEMPFAIL;

   /* ---- 2. BUILD DKIM2-Sig-mf ---- */
   char mf_value[512];
   snprintf(mf_value, sizeof(mf_value), "i=%d; addr=%s", N, ps->envelope.mail_from);

   /* ---- 3. BUILD DKIM2-Sig-rt (BCC-aware) ----
    *
    * Only include RCPT TO addresses that appear in To: or Cc: headers.
    * Recipients not visible in those headers are BCC and MUST NOT
    * appear in DKIM2-Sig-rt to prevent BCC disclosure.
    */

   /* Step 3a: Extract visible addresses from To: and Cc: headers */
   char visible_addrs[DC_MAX_EXTRACTED][DC_MAX_ADDR];
   int  visible_count = 0;

   for (int j = 0; j < ps->header_cnt && visible_count < DC_MAX_EXTRACTED; j++)
   {
      if (strcasecmp(ps->headers[j].name, "To") == 0 ||
          strcasecmp(ps->headers[j].name, "Cc") == 0)
      {
         int n = dc_extract_addresses(ps->headers[j].value,
                    &visible_addrs[visible_count],
                    DC_MAX_EXTRACTED - visible_count);
         visible_count += n;
      }
   }

   syslog(LOG_DEBUG, "DCS_EOM: Extracted %d visible recipients from To:/Cc:",
          visible_count);

   /* Step 3b: Filter RCPT TO against visible addresses */
   int rt_count = 0;
   int rt_indices[DC_MAX_RT];  /* indices into rcpt_to for visible recipients */

   for (int r = 0; r < ps->envelope.rcpt_count && rt_count < DC_MAX_RT; r++)
   {
      int is_visible = 0;
      for (int v = 0; v < visible_count; v++)
      {
         if (dc_addr_match(ps->envelope.rcpt_to[r], visible_addrs[v]))
         {
            is_visible = 1;
            break;
         }
      }

      if (is_visible)
      {
         rt_indices[rt_count++] = r;
      }
      else
      {
         syslog(LOG_DEBUG, "DCS_EOM: BCC recipient excluded from rt=: %s",
                ps->envelope.rcpt_to[r]);
      }
   }

   /* If no visible recipients found (all BCC, or empty To/Cc),
    * include all RCPT TO — we can't determine visibility.
    */
   if (rt_count == 0 && ps->envelope.rcpt_count > 0)
   {
      syslog(LOG_NOTICE, "DCS_EOM: No visible recipients matched. "
             "Including all %d RCPT TO in rt=.", ps->envelope.rcpt_count);
      rt_count = ps->envelope.rcpt_count;
      if (rt_count > DC_MAX_RT) rt_count = DC_MAX_RT;
      for (int r = 0; r < rt_count; r++)
         rt_indices[r] = r;
   }

   /* Step 3c: Build DKIM2-Sig-rt headers */
   char (*rt_values)[512] = NULL;
   if (rt_count > 0)
   {
      rt_values = calloc(rt_count, 512);
      if (!rt_values) { free(bh_b64); return SMFIS_TEMPFAIL; }
      for (int r = 0; r < rt_count; r++)
         snprintf(rt_values[r], 512, "i=%d; v=%d; addr=%s",
                  N, r + 1, ps->envelope.rcpt_to[rt_indices[r]]);
   }

   /* ---- 4. COMPUTE HEADER HASH (hh=) ---- */
   char *hh_b64 = dc_compute_hh(ps->headers, ps->header_cnt);
   if (!hh_b64)
   {
      syslog(LOG_ERR, "DCS_EOM: Failed to compute hh=");
      free(bh_b64); if (rt_values) free(rt_values);
      return SMFIS_TEMPFAIL;
   }

   /* ---- 5. BUILD DKIM2-Signature (without b=) ---- */
   long t_stamp = (long)time(NULL);
   char sig_value_no_b[2048];
   snprintf(sig_value_no_b, sizeof(sig_value_no_b),
            "i=%d; a=%s; c=relaxed/relaxed; d=%s; s=%s; t=%ld; h=%s; bh=%s; hh=%s; b=",
            N, ALGORITHM, dk->domain, dk->selector, t_stamp, H_FIELDS, bh_b64, hh_b64);

   /* ---- 6. ACCUMULATE SIGNING INPUT ---- */
   size_t buf_est = (size_t)(ps->header_cnt + rt_count + 10)
                    * (BIG_HEADER_VALUE + MAX_HEADER_NAME + 64);
   char *sign_buf = calloc(1, buf_est);
   if (!sign_buf) { free(bh_b64); free(hh_b64); if (rt_values) free(rt_values); return SMFIS_TEMPFAIL; }
   char *bp = sign_buf;
   char canon_buf[BIG_HEADER_VALUE + MAX_HEADER_NAME + 64];

   #define APPEND_CANON(hname, hvalue, crlf) do {                          \
      int _cl = canonicalize_header_relaxed((hname), (hvalue),             \
                canon_buf, sizeof(canon_buf), (crlf));                     \
      if (_cl > 0) {                                                       \
         if ((size_t)(bp - sign_buf) + (size_t)_cl > buf_est) {            \
            syslog(LOG_ERR, "DCS_EOM: sign buffer overflow guard");        \
            free(sign_buf); free(bh_b64); free(hh_b64);                    \
            if (rt_values) free(rt_values);                                \
            return SMFIS_TEMPFAIL;                                         \
         }                                                                 \
         memcpy(bp, canon_buf, _cl); bp += _cl;                            \
      }                                                                    \
   } while(0)

   /* a) Previous DKIM2-Signatures i=1..N-1 ascending */
   for (int i = 1; i < N; i++)
      for (int j = 0; j < ps->header_cnt; j++)
         if (ps->headers[j].dc_type == DC_HDR_SIG && ps->headers[j].hop == i)
         { APPEND_CANON(ps->headers[j].name, ps->headers[j].value, 1); break; }

   /* b) Our DKIM2-Sig-mf */
   APPEND_CANON("DKIM2-Sig-mf", mf_value, 1);

   /* c) Our DKIM2-Sig-rt */
   for (int r = 0; r < rt_count; r++)
      APPEND_CANON("DKIM2-Sig-rt", rt_values[r], 1);

   /* d) ALL DKIM2-Mod with i<=N, canonical order */
   {
      struct header_slot *mod_ptrs[DC_MAX_MOD];
      int mod_count = 0;
      for (int j = 0; j < ps->header_cnt; j++)
         if (ps->headers[j].dc_type == DC_HDR_MOD && ps->headers[j].hop <= N)
            if (mod_count < DC_MAX_MOD)
               mod_ptrs[mod_count++] = &ps->headers[j];
      if (mod_count > 1)
         qsort(mod_ptrs, mod_count, sizeof(struct header_slot *), cmp_mod_canonical);
      for (int m = 0; m < mod_count; m++)
         APPEND_CANON(mod_ptrs[m]->name, mod_ptrs[m]->value, 1);
   }

   /* e) Message headers from h=, bottom-to-top */
   {
      char h_work[2048];
      securecpy(h_work, H_FIELDS, sizeof(h_work));
      char *h_fields[256]; int h_count = 0;
      char *saveptr = NULL;
      char *token = strtok_r(h_work, ":", &saveptr);
      while (token && h_count < 256)
      {
         while (*token == ' ' || *token == '\t') token++;
         char *end = token + strlen(token) - 1;
         while (end > token && (*end == ' ' || *end == '\t')) *end-- = '\0';
         if (*token) h_fields[h_count++] = token;
         token = strtok_r(NULL, ":", &saveptr);
      }
      for (int j = 0; j < ps->header_cnt; j++)
         ps->headers[j].used_for_signature = 0;
      for (int i = 0; i < h_count; i++)
         for (int j = ps->header_cnt - 1; j >= 0; j--)
            if (strcasecmp(ps->headers[j].name, h_fields[i]) == 0 &&
                !ps->headers[j].used_for_signature)
            { APPEND_CANON(ps->headers[j].name, ps->headers[j].value, 1);
              ps->headers[j].used_for_signature = 1; break; }
   }

   /* f) Our DKIM2-Signature with b= empty, NO CRLF */
   APPEND_CANON("DKIM2-Signature", sig_value_no_b, 0);
   #undef APPEND_CANON

   size_t sign_len = (size_t)(bp - sign_buf);

   /* ---- 6. SIGN ---- */
   int is_ed25519 = (strstr(ALGORITHM, "ed25519") != NULL);
   char *b64_signature = NULL;

   if (is_ed25519)
   {
      EVP_MD_CTX *sctx = EVP_MD_CTX_new();
      if (!sctx)
      {
         syslog(LOG_ERR, "DCS_EOM: EVP_MD_CTX_new failed (Ed25519)");
         free(sign_buf); free(bh_b64); free(hh_b64); if (rt_values) free(rt_values);
         return SMFIS_TEMPFAIL;
      }
      if (EVP_DigestSignInit(sctx, NULL, NULL, NULL, dk->pkey) != 1)
      {
         syslog(LOG_ERR, "DCS_EOM: DigestSignInit Ed25519 failed");
         EVP_MD_CTX_free(sctx);
         free(sign_buf); free(bh_b64); free(hh_b64); if (rt_values) free(rt_values);
         return SMFIS_TEMPFAIL;
      }
      size_t sig_len = 0;
      if (EVP_DigestSign(sctx, NULL, &sig_len, (unsigned char *)sign_buf, sign_len) != 1
          || sig_len == 0)
      {
         syslog(LOG_ERR, "DCS_EOM: DigestSign Ed25519 sizing failed");
         EVP_MD_CTX_free(sctx);
         free(sign_buf); free(bh_b64); free(hh_b64); if (rt_values) free(rt_values);
         return SMFIS_TEMPFAIL;
      }
      unsigned char *sig_raw = malloc(sig_len);
      if (!sig_raw)
      {
         syslog(LOG_ERR, "DCS_EOM: malloc(sig_len) failed (Ed25519)");
         EVP_MD_CTX_free(sctx);
         free(sign_buf); free(bh_b64); free(hh_b64); if (rt_values) free(rt_values);
         return SMFIS_TEMPFAIL;
      }
      if (EVP_DigestSign(sctx, sig_raw, &sig_len, (unsigned char *)sign_buf, sign_len) != 1)
      {
         syslog(LOG_ERR, "DCS_EOM: DigestSign Ed25519 failed");
         EVP_MD_CTX_free(sctx); free(sig_raw);
         free(sign_buf); free(bh_b64); free(hh_b64); if (rt_values) free(rt_values);
         return SMFIS_TEMPFAIL;
      }
      EVP_MD_CTX_free(sctx);
      b64_signature = encode_base64_hash(sig_raw, sig_len);
      free(sig_raw);
   }
   else
   {
      EVP_MD_CTX *sctx = EVP_MD_CTX_new();
      if (!sctx)
      {
         syslog(LOG_ERR, "DCS_EOM: EVP_MD_CTX_new failed (RSA)");
         free(sign_buf); free(bh_b64); free(hh_b64); if (rt_values) free(rt_values);
         return SMFIS_TEMPFAIL;
      }
      if (EVP_DigestSignInit(sctx, NULL, EVP_sha256(), NULL, dk->pkey) != 1)
      {
         unsigned long err = ERR_get_error();
         char err_buf[256];
         ERR_error_string_n(err, err_buf, sizeof(err_buf));
         syslog(LOG_ERR, "DCS_EOM: DigestSignInit RSA failed: %s", err_buf);
         EVP_MD_CTX_free(sctx);
         free(sign_buf); free(bh_b64); free(hh_b64); if (rt_values) free(rt_values);
         return SMFIS_TEMPFAIL;
      }
      EVP_DigestSignUpdate(sctx, sign_buf, sign_len);
      size_t sig_len = 0;
      if (EVP_DigestSignFinal(sctx, NULL, &sig_len) != 1 || sig_len == 0)
      {
         syslog(LOG_ERR, "DCS_EOM: DigestSignFinal RSA sizing failed");
         EVP_MD_CTX_free(sctx);
         free(sign_buf); free(bh_b64); free(hh_b64); if (rt_values) free(rt_values);
         return SMFIS_TEMPFAIL;
      }
      unsigned char *sig_raw = malloc(sig_len);
      if (!sig_raw)
      {
         syslog(LOG_ERR, "DCS_EOM: malloc(sig_len) failed (RSA)");
         EVP_MD_CTX_free(sctx);
         free(sign_buf); free(bh_b64); free(hh_b64); if (rt_values) free(rt_values);
         return SMFIS_TEMPFAIL;
      }
      if (EVP_DigestSignFinal(sctx, sig_raw, &sig_len) != 1)
      {
         syslog(LOG_ERR, "DCS_EOM: DigestSignFinal RSA failed");
         EVP_MD_CTX_free(sctx); free(sig_raw);
         free(sign_buf); free(bh_b64); free(hh_b64); if (rt_values) free(rt_values);
         return SMFIS_TEMPFAIL;
      }
      EVP_MD_CTX_free(sctx);
      b64_signature = encode_base64_hash(sig_raw, sig_len);
      free(sig_raw);
   }
   free(sign_buf);

   if (!b64_signature)
   {
      syslog(LOG_ERR, "DCS_EOM: Signature encoding failed");
      free(bh_b64); free(hh_b64); if (rt_values) free(rt_values);
      return SMFIS_TEMPFAIL;
   }

   /* DKIM2-Authentication-Results (only for locally originated, Case 2) */
   if (generate_auth_result)
   {
      smfi_addheader(ctx, "DKIM2-Authentication-Results", auth_result_value);
   }

   char sig_full[4096];
   snprintf(sig_full, sizeof(sig_full), "%s%s", sig_value_no_b, b64_signature);
   smfi_addheader(ctx, "DKIM2-Signature", sig_full);
   smfi_addheader(ctx, "DKIM2-Sig-mf", mf_value);
   for (int r = 0; r < rt_count; r++)
   {
      smfi_addheader(ctx, "DKIM2-Sig-rt", rt_values[r]);
   }

   char xsigned[100] = "";
   snprintf (xsigned, sizeof(xsigned), "DarkChain 0.7 i=%d", N);
   smfi_addheader(ctx, "X-Signed", xsigned);

   /* Timing */
   clock_gettime(CLOCK_MONOTONIC, &ts_end);
   ps->cpu_ns += diff_ns(ts_start, ts_end);
   char cpu_buf[32];
   format_runtime(ps->cpu_ns, cpu_buf, sizeof(cpu_buf));

   char hs_val[128];
   if (ps->body_size < 1024)
      snprintf(hs_val, sizeof(hs_val), "%lld bytes", ps->body_size);
   else if (ps->body_size < 1048576)
      snprintf(hs_val, sizeof(hs_val), "%lld Kbytes", ps->body_size / 1024);
   else
      snprintf(hs_val, sizeof(hs_val), "%lld Mbytes", ps->body_size / 1048576);

   syslog(LOG_INFO, "DCS_EOM: Signed i=%d d=%s s=%s %s; %s; cpu=%s",
          N, dk->domain, dk->selector, ALGORITHM, hs_val, cpu_buf);

   free(bh_b64);
   free(hh_b64);
   free(b64_signature);
   if (rt_values) free(rt_values);

   return SMFIS_CONTINUE;
}


/* ---- dcs_abort / dcs_close ---- */
static sfsistat dcs_abort(SMFICTX *ctx)
{
   struct context *ps = (struct context *)smfi_getpriv(ctx);
   if (ps)
   {
      if (ps->mdctx_body) { EVP_MD_CTX_reset(ps->mdctx_body); }
   }
   return SMFIS_CONTINUE;
}

static sfsistat dcs_close(SMFICTX *ctx)
{
   struct context *ps = (struct context *)smfi_getpriv(ctx);
   if (ps)
   {
      if (ps->headers) { free(ps->headers); ps->headers = NULL; }
      if (ps->envelope.rcpt_to) { free(ps->envelope.rcpt_to); ps->envelope.rcpt_to = NULL; }
      if (ps->mdctx_body) { EVP_MD_CTX_free(ps->mdctx_body); ps->mdctx_body = NULL; }
      smfi_setpriv(ctx, NULL);
      free(ps);
   }
   return SMFIS_CONTINUE;
}

static sfsistat dcs_negotiate(SMFICTX *ctx,
   unsigned long f0, unsigned long f1,
   unsigned long f2, unsigned long f3,
   unsigned long *pf0, unsigned long *pf1,
   unsigned long *pf2, unsigned long *pf3)
{
   (void)ctx; (void)f0; (void)f1; (void)f2; (void)f3;
   *pf0 = SMFIF_ADDHDRS | SMFIF_CHGHDRS | SMFIF_CHGFROM;
   *pf1 = SMFIP_NOUNKNOWN | SMFIP_NODATA;
   *pf2 = 0;
   *pf3 = 0;
   return SMFIS_CONTINUE;
}


/* ================================================================
 * MAIN
 * ================================================================ */

static void dcs_usage(const char *prog)
{
   fprintf(stderr, "usage: %s [-u user] [-p socket] [-l level] [-m umask] [-f] [-L]\n"
                   "  -u user    Run as user (default: smmsp)\n"
                   "  -p socket  Milter socket (default: unix:/var/spool/DarkChains/sock)\n"
                   "  -l level   Log level: debug|info|notice|warning|err (default: notice)\n"
                   "  -m umask   Socket umask in octal (default: 0177)\n"
                   "  -f         Run in foreground (no daemon)\n"
                   "  -L         Log to stderr (in addition to syslog)\n", prog);
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

   int i_get = 0, i_ret = 0;
   const char *pc_ofile = NULL;
   bool b_fail = 0;
   int loglevel = LOGLEVEL;
   int foreground = 0;
   int log_stderr = 0;
   mode_t sock_umask = 0177;

   while ((i_get = getopt(argc, argv, "p:u:l:m:fLh")) != -1)
   {
      switch (i_get)
      {
         case 'p': pc_oconn = optarg; break;
         case 'u': pc_user = optarg; break;
         case 'l':
         {
            int lv = parse_loglevel(optarg);
            if (lv < 0)
            {
               fprintf(stderr, "Invalid loglevel: %s "
                       "(use debug|info|notice|warning|err)\n", optarg);
               return 1;
            }
            loglevel = lv;
            break;
         }
         case 'm': sock_umask = (mode_t)strtol(optarg, NULL, 8); break;
         case 'f': foreground = 1; break;
         case 'L': log_stderr = 1; break;
         default: dcs_usage(argv[0]);
      }
   }

   /* Open syslog with optional stderr mirroring */
   {
      int log_flags = LOG_PID | LOG_NDELAY;
      if (log_stderr) log_flags |= LOG_PERROR;
      openlog("DarkChains", log_flags, SYSLOG_FACILITY);
   }
   setlogmask(LOG_UPTO(loglevel));

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

   if (!strncmp(pc_oconn, "unix:", 5))
      pc_ofile = pc_oconn + 5;
   else if (!strncmp(pc_oconn, "local:", 6))
      pc_ofile = pc_oconn + 6;

   /* Load domain-key table at startup */
   int n_domains = load_domain_table(DC_DOMAINS_CONF);
   if (n_domains <= 0)
   {
      fprintf(stderr, "Fatal: no domains loaded from %s\n", DC_DOMAINS_CONF);
      return 1;
   }
   syslog(LOG_INFO, "DCS_MAIN: Loaded %d domain(s) from %s", n_domains, DC_DOMAINS_CONF);

   /* --- DEFAULT DOMAIN loading (currently unused — reserved for future relay fallback) --- */
   default_dk.pkey = load_private_key(DEFAULT_KEYPATH);
   if (default_dk.pkey)
   {
      securecpy(default_dk.domain, DEFAULT_DOMAIN, sizeof(default_dk.domain));
      securecpy(default_dk.selector, DEFAULT_SELECT, sizeof(default_dk.selector));
      securecpy(default_dk.keypath, DEFAULT_KEYPATH, sizeof(default_dk.keypath));
      default_dk_loaded = 1;
      syslog(LOG_INFO, "DCS_MAIN: Default relay key loaded: d=%s s=%s",
             DEFAULT_DOMAIN, DEFAULT_SELECT);
   }
   else
   {
      syslog(LOG_NOTICE, "DCS_MAIN: No default relay key at %s — relay signing disabled",
             DEFAULT_KEYPATH);
   }
   /* --- END DEFAULT DOMAIN loading --- */

   /* Load header hash exclusion patterns */
   load_hh_excludes(DC_HH_EXCLUDE_CONF);

   /* Load optional SRS secret (forward-path forge-resistance) */
   load_srs_secret(DC_SRS_KEY_CONF);

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

   if (!b_fail && smfi_register(chainsmilter) != MI_SUCCESS)
   {
      fprintf(stderr, "smfi_register: failed\n");
      goto done;
   }

   if (!b_fail && !foreground && daemon(0, 0))
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

   umask(sock_umask);
   signal(SIGPIPE, SIG_IGN);
   signal(SIGTERM, cleanup_and_exit);
   signal(SIGINT,  cleanup_and_exit);

   syslog(LOG_INFO, "DarkChains outbound signer starting on %s", pc_oconn);

   i_ret = smfi_main();

   if (i_ret != MI_SUCCESS)
      syslog(LOG_ERR, "[ERROR] DarkChains terminated due to a fatal error");

done:
   return i_ret;
}
