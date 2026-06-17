/*
 * DarkARC - ARC (RFC 8617) Verification Milter
 *
 * Verifies ARC chains (ARC-Seal, ARC-Message-Signature,
 * ARC-Authentication-Results) on inbound mail.
 *
 * Copyright (c) 2026 Vittorio Moccia / ITB.it
 * Licensed under the PolyForm Noncommercial License 1.0.0.
 * https://polyformproject.org/licenses/noncommercial/1.0.0/
 *
 * Shared utility code is provided by libdark (MIT), linked separately.
 */
/* dark_common.h pulls in libmilter, OpenSSL and shared system headers. */
#include <resolv.h>
#include "dark_common.h"
// maximum line length (1000 characters)
// Header: RFC 5322 recommends not exceeding 998 characters per line.
/* DarkARC-specific constants (shared ones come from dark_common.h) */
#define MAX_HEADER_COUNT  800
#define MAX_CAPACITY 200
#define MY_DOMAIN "dns.itb.it"
#define DEBUG 0
#define OCONN           "unix:/var/spool/DarkARC/sock"
#define USER            "smmsp"
#define SDUSER          "smmsp"
#define LOGLEVEL        LOG_ERR
#define MAX_DKIM_RESULTS 4

/* Syslog facility */
#define SYSLOG_FACILITY	LOG_DAEMON

static sfsistat da_connect(SMFICTX *, char *, _SOCK_ADDR *);
static sfsistat da_helo(SMFICTX *, char *);
static sfsistat da_envfrom(SMFICTX *, char **);
static sfsistat da_envrcpt(SMFICTX *, char **);
static sfsistat da_header(SMFICTX *, char *, char *);
static sfsistat da_eoh(SMFICTX *);
static sfsistat da_body(SMFICTX *, u_char *, size_t);
static sfsistat da_eom(SMFICTX *);
static sfsistat da_abort(SMFICTX *);
static sfsistat da_close(SMFICTX *);

struct auth_data
{
    char result[24];      // pass, fail, timeout, etc.
    char identifier[128]; // the associated domain
};

typedef struct
{
   char cv[16];                 // cv= tag (AS only): result of the previous hop
   char a_alg_AMS[32];
   char a_alg_AS[32];
   char b_sign_AS[MAX_PUB_KEY];
   char b_sign_AMS[MAX_PUB_KEY];
   char bh_bodyhash[256];
   char c_canonic_AMS[64];
   char d_domain_AMS[256];
   char d_domain_AS[256];
   char h_signfields[2048];
   char s_arcselector_AMS[128];
   char s_arcselector_AS[128];
} arc_params_t;

struct header_slot
{
    char name[MAX_HEADER_NAME];
    char value[BIG_HEADER_VALUE];
    int used_for_signature;        // Flag to remember whether this slot has already been used (useful for duplicates)
    int arc_index;                 // if this is an ARC field, stores its index
};

// Private structure for each email session
struct context
{
    int msg_count;
    struct timespec start_time;
    unsigned long long cpu_ns; // Pure computation time (Hash, Canonicalization, RSA)
    unsigned long long dns_ns; // DNS wait time (TXT query ARC/DKIM)
    unsigned long long net_ns; // DNS wait time (TXT query ARC/DKIM)
    struct header_slot *headers; // Pointer to the dynamic array
    int body_size;
    arc_params_t params;
    int header_cnt;              // How many slots are currently used
    int header_capacity;         // Capacity of the current allocation
    int found_arc;
    int i_hdr_relaxed;
    int i_body_relaxed;
    int h_num_fields;            // number of fields to hash or buffer for signature verification
    char last_arc_d[256];
    int body_integrity;
    int is_start_of_line;
    int header_vfy;
    int seal_vfy;
    int is_localhost;
    char spf_res[24], spf_id[128];
    char dkim_results_buf[1024];
    char dmarc_res[24], dmarc_id[128];
    struct auth_data spf, dkim, dmarc;
    EVP_MD_CTX *mdctx_header;           // Digest context for the header
    EVP_MD_CTX *mdctx_body_simple;      // Digest context for the body
    EVP_MD_CTX *mdctx_body_relaxed;     // Digest context for the body
    char helo[MAXHOST];
    unsigned char body_hash[EVP_MAX_MD_SIZE]; // Where the result lands (32 bytes for SHA256)
    unsigned int body_hash_len;
    int p_had_space;
    int pending_newlines_relaxed;
    int body_has_content_relaxed;
    int pending_newlines_simple;
    int body_has_content_simple;
};


    const char *pc_oconn = OCONN;
    const char *pc_user = USER;
    const char my_hostname[]=MY_DOMAIN;


struct smfiDesc arcmilter = {
    "DarkARC",
    SMFI_VERSION,             /* Version (important!) */
    SMFIF_ADDHDRS|SMFIF_CHGHDRS, /* Flags: needed to add our verification header */
    da_connect,               /* Here you can log the sender server IP */
    da_helo,                  /* Often null, unless checking the hostname */
    da_envfrom,               /* FUNDAMENTAL: Initialize the priv struct and the OpenSSL hash here */
    da_envrcpt,               /* Here you check if the recipient belongs to your mailing list */
    da_header,                /* Fills the array with ALL headers */
    da_eoh,                   /* End of headers: by now we know the highest i value */
    da_body,                  /* The workhorse: computes SHA256 hash over 50 MB chunks */
    da_eom,                   /* The Brain: DNS lookup, RSA verify and verdict */
    da_abort,                 /* Emergency cleanup if the connection drops */
    da_close                  /* Final memory cleanup (free, etc.) */
};


typedef struct
{
    char name[64];
    char value[1024];
} saved_header_t;

static void da_usage(const char *);
void cleanup_and_exit(int sig);
void reset_arc (arc_params_t *);
EVP_PKEY* load_public_key_from_base64(const char *);
int get_arc_index(const char *);
void parse_arc_header(const char *, const char *, arc_params_t *);
int canonicalize_arc_ms_for_verify(const char *, const char *,
                                    char *, size_t);
int verify_arc_chain (struct context *);
void get_results_from_auth_headers(struct context *);
void extract_auth_detail(const char *, const char *, const char *, char *, char *);
static void feed_header_to_digest(EVP_MD_CTX *, struct context *,
                                  int , bool , bool );
const char* extract_and_move_p(const char *, const char *, const char *, char *, char *);
void cleanup_message(struct context *priv);

void reset_arc (arc_params_t *params)
{
   params->cv[0]='\0';
   params->d_domain_AMS[0]='\0';
   params->d_domain_AS[0]='\0';
   params->a_alg_AS[0]='\0';
   params->a_alg_AMS[0]='\0';
   params->b_sign_AS[0]='\0';
   params->b_sign_AMS[0]='\0';
   params->bh_bodyhash[0]='\0';
   params->c_canonic_AMS[0]='\0';
   params->h_signfields[0]='\0';
   params->s_arcselector_AMS[0]='\0';
   params->s_arcselector_AS[0]='\0';

}




// no longer used
EVP_PKEY* load_public_key_from_base64(const char* base64_pem_key)
{
    BIO* bio = BIO_new_mem_buf(base64_pem_key, -1);
    if (bio == NULL)
    {
        return NULL;
    }

    // PEM_read_bio_PUBKEY automatically decodes the Base64 PEM
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);

    BIO_free(bio); // Free the BIO, but not the pkey
    return pkey;
}


// Returns the public key string extracted from the TXT record
// d = domain, s = selector
// Strip whitespace (essential for "relaxed" canonicalization)

// extract the ARC index from an ARC header line
int get_arc_index(const char *header_value)
{
   if (!header_value) return -1;

   // Look for the substring "i="
   const char *p = strstr(header_value, "i=");
   if (!p) return -1;

   // Skip "i=" and read the number
   p += 2;
   int index = atoi(p);

   return (index > 0) ? index : -1;
}


/* Removes ALL whitespace anywhere in the string, not just leading/trailing */
void parse_arc_header(const char *header_f, const char *header_value, arc_params_t *params)
{
   char buf[BIG_BUFFER];
   securecpy(buf, header_value, sizeof(buf));
   // buf[sizeof(buf) - 1] = '\0';

   int is_AS  = (strcasecmp(header_f, "ARC-Seal") == 0);
   int is_AMS = (strcasecmp(header_f, "ARC-Message-Signature") == 0);

   char *saveptr;
   char *token = strtok_r(buf, ";", &saveptr);
   while (token != NULL)
   {
      trim(token);
      char *eq = strchr(token, '=');
      if (eq)
      {
         *eq = '\0';
         char *key = token;
         char *val = eq + 1;
         trim(key);
         trim(val);

         if (strcmp(key, "d") == 0)
         {
            if (is_AMS) securecpy(params->d_domain_AMS, val, sizeof(params->d_domain_AMS));
            else if (is_AS) securecpy (params->d_domain_AS, val, sizeof(params->d_domain_AS));
         }
         else if (strcmp(key, "s") == 0)
         {
            if (is_AMS) securecpy(params->s_arcselector_AMS, val, sizeof(params->s_arcselector_AMS));
            else if (is_AS) securecpy(params->s_arcselector_AS, val, sizeof(params->s_arcselector_AS));
         }
         else if (strcmp(key, "a") == 0)
         {
            if (is_AMS) securecpy(params->a_alg_AMS, val, sizeof(params->a_alg_AMS));
            else if (is_AS) securecpy(params->a_alg_AS, val, sizeof(params->a_alg_AS));
         }
         else if (strcmp(key, "b") == 0)
         {
            /* Base64: full strip of all whitespace including internal folding */
            strip_whitespace(val);
            if (is_AMS) securecpy(params->b_sign_AMS, val, sizeof(params->b_sign_AMS));
            else if (is_AS) securecpy(params->b_sign_AS, val, sizeof(params->b_sign_AS));
         }
         else if (strcmp(key, "bh") == 0)
         {
            /* Same treatment: it is Base64 */
            strip_whitespace(val);
            securecpy(params->bh_bodyhash, val, sizeof(params->bh_bodyhash));
         }
         else if (strcmp(key, "c") == 0)
         {
            securecpy(params->c_canonic_AMS, val, sizeof(params->c_canonic_AMS));
         }
         else if (strcmp(key, "cv") == 0)
         {
            securecpy(params->cv, val, sizeof(params->cv));
         }
         else if (strcmp(key, "h") == 0)
         {
            securecpy(params->h_signfields, val, sizeof(params->h_signfields));
         }
      }
      token = strtok_r(NULL, ";", &saveptr);
   }
}

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
/*
 * Relaxed canonicalization of a header (RFC 6376 §3.4.2, also applicable to ARC).
 *
 * - Name:  all lowercase, no spaces
 * - Separator: ':'
 * - Value: leading trim, every WSP sequence (including folding CRLF+WSP) -> single SP
 * - Trailing trim (trailing WSP before the final CRLF)
 * - Terminated by CRLF
 *
 * For ARC-Message-Signature, pass the value with b= already trimmed (just "b=")
 * before calling this function, or use the variant below.
 */

/*
 * ARC-specific variant: zeroes the b= tag value before canonicalizing.
 * Useful for verifying the most recent ARC-Message-Signature (RFC 8617 §5.1.1).
 *
 * Operates on a copy of the value; the original is not modified.
 */


int canonicalize_arc_ms_for_verify(const char *name, const char *value,
                                    char *out, size_t out_max)
{
    char buf[8192];
    size_t vlen = strlen(value);
    if (vlen >= sizeof(buf)) return -1;
    memcpy(buf, value, vlen + 1);

    /* First unfold, then look for b= */
    unfold_header(buf);

    char *p = buf;
    while (*p)
    {
        char *found = strstr(p, "b=");
        if (!found) break;

        // Guard against matching bh=
        if (found > buf && *(found - 1) == 'h')
        {
            p = found + 2;
            continue;
        }

        char *val_start = found + 2;
        char *val_end = val_start;

        // Find the end of the b= value
        while (*val_end && *val_end != ';' && *val_end != '\r' && *val_end != '\n')
            val_end++;

        if (*val_end == ';')
        {
            // Semicolon found: shift everything that follows (other tags)
            memmove(val_start, val_end, strlen(val_end) + 1);
        }
        else
        {
            // No ';': truncate unconditionally
            *val_start = '\0';
        }
        break;
    }
    return canonicalize_header_relaxed(name, buf, out, out_max, 0);
}


/**
 * Prepare a header for Relaxed canonicalization.
 * Writes the result into 'out'.
 *
 * Relaxed Header Canonicalization:
 * Tolerates minor in-transit changes (added spaces, case changes).
 * Rules:
 *   - Convert header name to lowercase (e.g. Subject -> subject).
 *   - Remove leading and trailing whitespace from the value.
 *   - Collapse all internal sequences of spaces/tabs to a single space.
 *   - Keep the : between name and value; do not add spaces after it.
 *   - Terminate with \r\n.
 */
/*
 * Hard rule of RFC 6376 (DKIM/ARC):
 * 2. If canonicalization is "simple"
 * Be a "photographer": change nothing.
 *   Name:       Exactly as received (e.g. Subject).
 *   Separator:  The character : followed by a single space.
 *   Value:      Exactly as received (including any folding).
 *   Terminator: Always \r\n.
 * Example:
 *   Original:       Subject: Coffee Break
 *   String to hash: Subject: Coffee Break\r\n
 */

sfsistat da_header(SMFICTX *ctx, char *headerf, char *headerv)
{
   struct context *ps_context;
   ps_context = (struct context *)smfi_getpriv(ctx);
   int indice_ARC;

   struct timespec cb_start, cb_end;
   clock_gettime(CLOCK_MONOTONIC, &cb_start);



   if (ps_context->is_localhost == 0)
   {
      if (strcasecmp(headerf, "X-ARC-Internal-Status") == 0)
      {
         // An outsider is trying to spoof us! Remove the header.
         // Calling smfi_chgheader with NULL deletes the header.
         // NOTE: the index (1) refers to the header instance.
         smfi_chgheader(ctx, "X-ARC-Internal-Status", 1, NULL);
         syslog(LOG_NOTICE, "DA_HEADER: Removed spoofed ghost header from outside");
         return SMFIS_CONTINUE;
      }
   }
   // If current maximum capacity reached, expand
   if (ps_context->header_cnt >= ps_context->header_capacity)
   {
      // 1. DoS protection: reservoir full, stop saving
      // (or error out if paranoid, but better to silently drop the excess)
      if (ps_context->header_capacity >= MAX_HEADER_COUNT)
      {
         return SMFIS_CONTINUE;
      }
      int new_capacity = ps_context->header_capacity + MAX_CAPACITY ;
      struct header_slot *new_ptr = realloc(ps_context->headers, new_capacity * sizeof(struct header_slot));
      if (new_ptr == NULL)
      {
         // If RAM truly runs out, decide here:
         // Either drop the header (continue) or return temporary error
         return SMFIS_TEMPFAIL;
      }
      ps_context->headers = new_ptr;
      ps_context->header_capacity = new_capacity;
   }

   struct header_slot *slot = &ps_context->headers[ps_context->header_cnt];
   strncpy(slot->name, headerf, MAX_HEADER_NAME - 1);
   slot->name[MAX_HEADER_NAME - 1] = '\0'; // Safety

   unfold_header (headerv);
   strncpy(slot->value, headerv, BIG_HEADER_VALUE - 1);
   slot->value[BIG_HEADER_VALUE - 1] = '\0'; // Safety
   slot->used_for_signature = 0; // Reset the flag


   // intercept ARC-Seal/Signature on the fly to save their indices

   if (strncasecmp(headerf, "ARC-", 4) == 0)
   {
      indice_ARC=get_arc_index(headerv);
      if (indice_ARC>ps_context->found_arc)
      {

         ps_context->params.cv[0]='\0';
         ps_context->params.d_domain_AMS[0]='\0';
         ps_context->params.d_domain_AS[0]='\0';
         ps_context->params.a_alg_AS[0]='\0';
         ps_context->params.a_alg_AMS[0]='\0';
         ps_context->params.b_sign_AS[0]='\0';
         ps_context->params.b_sign_AMS[0]='\0';
         ps_context->params.bh_bodyhash[0]='\0';
         ps_context->params.c_canonic_AMS[0]='\0';
         ps_context->params.h_signfields[0]='\0';
         ps_context->params.s_arcselector_AMS[0]='\0';
         ps_context->params.s_arcselector_AS[0]='\0';

         // reset_arc (&ps_context->params);
         ps_context->found_arc=indice_ARC;
         parse_arc_header (headerf, headerv, &(ps_context->params));
      }
      else if (indice_ARC==ps_context->found_arc)
      {
         parse_arc_header (headerf, headerv, &(ps_context->params));
      }
      slot->arc_index=indice_ARC;

   }
   ps_context->header_cnt++;
   clock_gettime(CLOCK_MONOTONIC, &cb_end);
   ps_context->cpu_ns += diff_ns(cb_start, cb_end);

   return SMFIS_CONTINUE;
}


sfsistat da_body(SMFICTX *ctx, unsigned char *bodyp, size_t bodylen)
{
   struct context *ps = (struct context *)smfi_getpriv(ctx);
   if (!ps) return SMFIS_CONTINUE;

   struct timespec cb_start, cb_end;
   clock_gettime(CLOCK_MONOTONIC, &cb_start);

   ps->body_size += bodylen;



   //    syslog(LOG_DEBUG, "DA_BODY: bodylen=%zu", bodylen);

   // --- SHADOWING: load state from struct into CPU registers ---
   register int l_pending_s   = ps->pending_newlines_simple;
   register int l_pending_r   = ps->pending_newlines_relaxed;
   register int l_had_space   = ps->p_had_space;
   register int l_is_start    = ps->is_start_of_line;
   register int l_has_cont_s  = ps->body_has_content_simple;
   register int l_has_cont_r  = ps->body_has_content_relaxed;

   // Local stack buffers
   unsigned char s_buf[BODY_BUF_SIZE];
   unsigned char r_buf[BODY_BUF_SIZE];
   size_t s_idx = 0, r_idx = 0;

   if (ps->i_body_relaxed == 0)
   {
      /* ----------------------------------------------------------------
      * SIMPLE branch optimized with memcpy for normal blocks
      * ---------------------------------------------------------------- */
      size_t i = 0;
      while (i < bodylen)
      {
         unsigned char c = bodyp[i];

         if (c == '\r') { i++; continue; }

         if (c == '\n')
         {
            l_pending_s++;
            i++;
            continue;
         }

         // Normal char: find how many consecutive ones have no \r or \n
         size_t j = i + 1;
         while (j < bodylen && bodyp[j] != '\r' && bodyp[j] != '\n')
         j++;
         size_t run = j - i;

         // Flush pending newlines
         while (l_pending_s > 0)
         {
            if (s_idx >= BODY_BUF_SIZE - 2)
            {
               EVP_DigestUpdate(ps->mdctx_body_simple, s_buf, s_idx);
               s_idx = 0;
            }
            s_buf[s_idx++] = '\r';
            s_buf[s_idx++] = '\n';
            l_pending_s--;
         }

         // Copy the block with memcpy
         size_t space_left = BODY_BUF_SIZE - s_idx;
         if (run <= space_left)
         {
            memcpy(s_buf + s_idx, bodyp + i, run);
            s_idx += run;
         }
         else
         {
            // block does not fit: fill buffer and flush
            memcpy(s_buf + s_idx, bodyp + i, space_left);
            EVP_DigestUpdate(ps->mdctx_body_simple, s_buf, BODY_BUF_SIZE);
            s_idx = 0;
            size_t remaining = run - space_left;
            if (remaining >= BODY_BUF_SIZE)
            {
               // huge block: pass directly to EVP without copying
               EVP_DigestUpdate(ps->mdctx_body_simple, bodyp + i + space_left, remaining);
            }
            else
            {
               memcpy(s_buf, bodyp + i + space_left, remaining);
               s_idx = remaining;
            }
         }

         l_has_cont_s = 1;
         i = j; // salta al prossimo carattere speciale
      }

      // Final flush of chunk for Simple
      if (s_idx > 0)
      {
         EVP_DigestUpdate(ps->mdctx_body_simple, s_buf, s_idx);
         s_idx = 0;
      }
   }
   else
   {
      /* ----------------------------------------------------------------
      * RELAXED branch optimized with memcpy for normal blocks
      * ---------------------------------------------------------------- */
      size_t i = 0;
      while (i < bodylen)
      {
         unsigned char c = bodyp[i];

         if (c == '\r') { i++; continue; }

         if (c == '\n')
         {
            l_had_space = 0;
            l_is_start  = 1;
            l_pending_r++;
            i++;
            continue;
         }

         if (c == ' ' || c == '\t')
         {
            l_had_space = 1;
            i++;
            continue;
         }

         // Normal char: find how many consecutive ones have no special chars
         size_t j = i + 1;
         while (j < bodylen &&
         bodyp[j] != '\r' && bodyp[j] != '\n' &&
         bodyp[j] != ' '  && bodyp[j] != '\t')
         {
            j++;
         }
         size_t run = j - i;

         // Flush pending newlines
         while (l_pending_r > 0)
         {
            if (r_idx >= BODY_BUF_SIZE - 2)
            {
               EVP_DigestUpdate(ps->mdctx_body_relaxed, r_buf, r_idx);
               r_idx = 0;
            }
            r_buf[r_idx++] = '\r';
            r_buf[r_idx++] = '\n';
            l_pending_r--;
            l_has_cont_r = 1;
         }

         // Handle compressed whitespace
         if (l_had_space)
         {
            if (r_idx >= BODY_BUF_SIZE)
            {
               EVP_DigestUpdate(ps->mdctx_body_relaxed, r_buf, r_idx);
               r_idx = 0;
            }
            r_buf[r_idx++] = ' ';
            l_had_space = 0;
         }

         // Copy the block with memcpy
         size_t space_left = BODY_BUF_SIZE - r_idx;
         if (run <= space_left)
         {
            memcpy(r_buf + r_idx, bodyp + i, run);
            r_idx += run;
         }
         else
         {
            // block does not fit: fill buffer and flush
            memcpy(r_buf + r_idx, bodyp + i, space_left);
            EVP_DigestUpdate(ps->mdctx_body_relaxed, r_buf, BODY_BUF_SIZE);
            r_idx = 0;
            size_t remaining = run - space_left;
            if (remaining >= BODY_BUF_SIZE)
            {
               // huge block: pass directly to EVP without copying
               EVP_DigestUpdate(ps->mdctx_body_relaxed, bodyp + i + space_left, remaining);
            }
            else
            {
               memcpy(r_buf, bodyp + i + space_left, remaining);
               r_idx = remaining;
            }
         }

         l_has_cont_r = 1;
         l_is_start   = 0;
         i = j; // salta al prossimo carattere speciale
      }

      // Final flush of chunk for Relaxed
      if (r_idx > 0)
      {
         EVP_DigestUpdate(ps->mdctx_body_relaxed, r_buf, r_idx);
         r_idx = 0;
      }
   }

   // --- RESTORE: save state from registers back to struct ---
   ps->pending_newlines_simple   = l_pending_s;
   ps->pending_newlines_relaxed  = l_pending_r;
   ps->p_had_space               = l_had_space;
   ps->is_start_of_line          = l_is_start;
   ps->body_has_content_simple   = l_has_cont_s;
   ps->body_has_content_relaxed  = l_has_cont_r;

   clock_gettime(CLOCK_MONOTONIC, &cb_end); // <--- END
   ps->cpu_ns += diff_ns(cb_start, cb_end);

   return SMFIS_CONTINUE;
}



// Update the SHA-256 hash in real time.
// If using "Relaxed" canonicalization, you cannot hash the chunk directly.
// You need a small state machine that cleans each chunk before EVP_DigestUpdate:
//   - Detect whether the chunk ends with \r.
//   - Discard trailing whitespace on each line.
//   - Handle trailing blank lines (remove or normalize).
/* "Relaxed" logic:
      - Space/tab: do not hash immediately (increment pending_spaces).
      - \r or \n: discard pending_spaces and hash the newline.
      - Other char: hash pending_spaces then the character.

      For now, use the "Simple" version (brute-force hash of whatever arrives)
      just to verify the mechanism works.
*/




// From DNS string to EVP_PKEY object
// DNS keys have no PEM headers; they are raw DER encoded in Base64.
// Use a BIO chain to decode on the fly.

// From b= string to binary
// The AMS signature is Base64. Convert it to a byte array.

// End of message
sfsistat da_eom(SMFICTX *ctx)
{

   /*
   * EVP_DigestVerify to verify the RSA signature (b= field of AMS)
   * using the public key from DNS domain d (AMS) with selector s.
   */
   struct timespec ts_start, ts_end;
   clock_gettime(CLOCK_MONOTONIC, &ts_start);
   struct context *ps_context;
   ps_context = (struct context *)smfi_getpriv(ctx);
   syslog(LOG_DEBUG, "DA_EOM: run with localhost=%d", ps_context->is_localhost);

   // --- 1. SELECT CANONICALIZATION BRANCH ---
   // Convenience pointers to avoid duplicating finalization code
   EVP_MD_CTX *target_ctx;

   // Look for "/relaxed" in the c= tag (es. "relaxed/relaxed" o "simple/relaxed")
   //if (ps_context->params.c_canonic_AMS[0] != '\0' &&
   //    strstr(ps_context->params.c_canonic_AMS, "/relaxed") != NULL)

   if (ps_context->i_hdr_relaxed)
   {
      target_ctx = ps_context->mdctx_body_relaxed;
      //    p_has_content = &ps_context->body_has_content_relaxed;
   }
   else
   {
      // Default ARC: Simple or genuinely simple
      target_ctx = ps_context->mdctx_body_simple;
      //    p_has_content = &ps_context->body_has_content_simple;
   }

   // --- 2. CLOSE THE BODY ---
   // If there was content, RFC requires the last line to end with CRLF.
   // Note: pending newlines accumulated in da_body are discarded here (Trim).
   // RFC 6376 (Sections 3.4.3 and 3.4.4)
   // if (*p_has_content) {
   if ((ps_context->i_hdr_relaxed) &&
   (ps_context->body_has_content_relaxed))
   {
      EVP_DigestUpdate(ps_context->mdctx_body_relaxed, "\r\n", 2);
   }

   if ((ps_context->i_hdr_relaxed==0) &&
   (ps_context->body_has_content_simple))
   {
      EVP_DigestUpdate(ps_context->mdctx_body_simple, "\r\n", 2);
   }


   ps_context->body_integrity = 0; // Default: not intact

   // --- 3. FINALIZE THE HASH ---
   unsigned char calcolato_bin[EVP_MAX_MD_SIZE];
   unsigned int calcolato_len = 0;


   // Always run Final, even if the body is empty (the null hash exists!)
   if (EVP_DigestFinal_ex(target_ctx, calcolato_bin, &calcolato_len) != 1)
   {
      syslog(LOG_ERR, "DA_EOM: Fatal OpenSSL error in EVP_DigestFinal");
      return SMFIS_TEMPFAIL;
   }

   // --- 4. COMPARE WITH THE DECLARED BH ---

   if (ps_context->params.bh_bodyhash[0] != '\0')
   {
      unsigned char remote_bin[EVP_MAX_MD_SIZE];

      int remote_len = decode_base64_sig(ps_context->params.bh_bodyhash, remote_bin, sizeof(remote_bin));

      if (remote_len != 32)
      {
         syslog(LOG_WARNING, "DA_EOM: Invalid bh hash (length %d instead of 32)", remote_len);
         // Likely a transmission error or a SHA512 hash (which would be 64 bytes)
      }

      if (remote_len == (int)calcolato_len && memcmp(calcolato_bin, remote_bin, calcolato_len) == 0)
      {
         syslog(LOG_INFO, "DA_EOM: Body Hash MATCH");
         ps_context->body_integrity = 1;
      }
      else
      {
         ps_context->body_integrity = 0;
         syslog(LOG_NOTICE, "DA_EOM: Body Hash MISMATCH! (Attenzione: body alterato)");
      }
   }


   //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> Phase 2: VERIFY b= OF AMS >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
   // Phase 2: verify the AMS b= signature (RSA)
   //  the ARC-Message-Signature header itself must also be hashed, with b= tag empty.
   //    bool b_header_relaxed=
   //      ((ps_context->params.c_canonic_AMS[0] != '\0') &&
   //        (strstr(ps_context->params.c_canonic_AMS, "relaxed/") != NULL));

   char ams_header_to_hash[MAX_HEADER_NAME+BIG_HEADER_VALUE];
   unsigned char firma_binaria[512]; // Buffer for raw signature bytes
   memset  (ams_header_to_hash, 0, sizeof (ams_header_to_hash));
   // add the latest ARC AMS header at the current i
   for (int j = ps_context->header_cnt - 1; j >= 0; j--)
   {
      if ((strcasecmp(ps_context->headers[j].name, "ARC-Message-Signature") == 0 ) &&
      (ps_context->headers[j].arc_index==ps_context->found_arc))
      {
         if ( ps_context->i_hdr_relaxed)
         {

            canonicalize_arc_ms_for_verify (ps_context->headers[j].name,
            ps_context->headers[j].value, ams_header_to_hash,
            sizeof(ams_header_to_hash));

         }
         else
         {
            // Simple canonicalization
            // 1. Name identical to original
            // 2. Keep original spaces
            snprintf(ams_header_to_hash, sizeof(ams_header_to_hash)-1, "%s: %s\r\n",
            ps_context->headers[j].name, ps_context->headers[j].value);
         }
         if (DEBUG)
         syslog (LOG_DEBUG, "DA_EOM: LAST Hashed Header [%s]", ams_header_to_hash);


         EVP_DigestUpdate(ps_context->mdctx_header, ams_header_to_hash, strlen(ams_header_to_hash));
         break;
      }
   }


   // 1. Finalize the hash (32 binary bytes of SHA256)
   unsigned char m_hash[32];
   unsigned int m_hash_len = sizeof(m_hash);

   // 2. Retrieve the key from DNS
   char ca_dns_key[MAX_PUB_KEY];
   memset(ca_dns_key, 0, sizeof(ca_dns_key));

   EVP_PKEY *current_pubkey = NULL;

   clock_gettime(CLOCK_MONOTONIC, &ts_end);
   ps_context->cpu_ns += diff_ns(ts_start, ts_end);

   clock_gettime(CLOCK_MONOTONIC, &ts_start);

   int esito=get_dns_arc_pubkey(ps_context->params.d_domain_AMS, ps_context->params.s_arcselector_AMS,
   ca_dns_key, MAX_PUB_KEY - 1);
   clock_gettime(CLOCK_MONOTONIC, &ts_end);
   ps_context->dns_ns += diff_ns(ts_start, ts_end);

   clock_gettime(CLOCK_MONOTONIC, &ts_start);

   if (esito)
   {

      if (strstr(ps_context->params.a_alg_AMS, "rsa")!=NULL)
      {
         current_pubkey = decode_dns_key(ca_dns_key, 0);


         // STEP 2: b= signature string (Base64) -> binary
         int firma_bin_len = decode_base64_sig(ps_context->params.b_sign_AMS,
         firma_binaria, sizeof(firma_binaria));


         syslog(LOG_DEBUG, "DA_EOM: ca_dns_key=[%s]", ca_dns_key);
         syslog(LOG_DEBUG, "DA_EOM: current_pubkey=%p", (void*)current_pubkey);
         if (current_pubkey)
         {
            int pkey_type = EVP_PKEY_id(current_pubkey);
            syslog(LOG_DEBUG, "DA_EOM: pkey_type=%d (ED25519=%d RSA=%d)",
            pkey_type, EVP_PKEY_ED25519, EVP_PKEY_RSA);
         }
         syslog(LOG_DEBUG, "DA_EOM: firma_bin_len=%d", firma_bin_len);

         ps_context->header_vfy=0;

         if (current_pubkey != NULL && firma_bin_len > 0)
         {

            if (EVP_DigestFinal_ex(ps_context->mdctx_header, m_hash, &m_hash_len) != 1)
            {
               syslog(LOG_ERR, "DA_EOM: Fatal error in EVP_DigestFinal_ex");
               if (current_pubkey) EVP_PKEY_free(current_pubkey);
               return SMFIS_TEMPFAIL;
            }

            // After EVP_DigestFinal_ex, log the computed hash
            char hex_hash[256] = {0};
            for (unsigned int i = 0; i < m_hash_len; i++)
            sprintf(hex_hash + i*2, "%02x", m_hash[i]);

            if (DEBUG)
            syslog(LOG_DEBUG, "DA_EOM: calculated hash header: %s", hex_hash);

            // Also log the first bytes of the decoded signature
            char hex_sig[64] = {0};
            int preview = firma_bin_len < 16 ? firma_bin_len : 16;
            for (int i = 0; i < preview; i++)
            sprintf(hex_sig + i*2, "%02x", firma_binaria[i]);
            if (DEBUG)
            syslog(LOG_DEBUG, "DA_EOM: binary signature (first 16 bytes): %s", hex_sig);


            // 3. Cryptographic verification
            EVP_PKEY_CTX *ver_ctx = EVP_PKEY_CTX_new(current_pubkey, NULL);
            if (ver_ctx != NULL
                && EVP_PKEY_verify_init(ver_ctx) == 1
                && EVP_PKEY_CTX_set_rsa_padding(ver_ctx, RSA_PKCS1_PADDING) > 0
                && EVP_PKEY_CTX_set_signature_md(ver_ctx, EVP_sha256()) > 0)
            {
               // Binary comparison: signature vs hash
               int result = EVP_PKEY_verify(ver_ctx, firma_binaria, firma_bin_len,
               m_hash, m_hash_len);

               if (result == 1)
               {
                  ps_context->header_vfy=1;
                  syslog(LOG_INFO, "DA_EOM: bh - Valid signature!");
               }
               else if (result == 0)
               {
                  ps_context->header_vfy=0;
                  syslog(LOG_NOTICE, "DA_EOM: bh - Signature failed (mismatch)!");
               }
               else
               {
                  ps_context->header_vfy=0;
                  syslog(LOG_ERR, "DA_EOM: bh - Error during cryptographic verification");
               }
            }
            else
            {
               ps_context->header_vfy=0;
               syslog(LOG_ERR, "DA_EOM: bh - Unable to initialize RSA verification context");
            }
            if (ver_ctx) EVP_PKEY_CTX_free(ver_ctx);
         }
      }
      else if (strstr(ps_context->params.a_alg_AMS, "ed25519")!=NULL)
      {
         // STEP 1: DNS string (Base64) -> EVP_PKEY object
         current_pubkey = decode_dns_key(ca_dns_key, 1);


         // STEP 2: b= signature string (Base64) -> binary
         int firma_bin_len = decode_base64_sig(ps_context->params.b_sign_AMS,
         firma_binaria, sizeof(firma_binaria));
         ps_context->header_vfy=0;

         if (current_pubkey != NULL && firma_bin_len > 0)
         {
            char h_work_copy[BIG_HEADER_VALUE+1];
            securecpy(h_work_copy, ps_context->params.h_signfields, sizeof(h_work_copy));
            // Create the verification context
            // 1. Full context reset (equivalent to just after EVP_MD_CTX_new)
            EVP_MD_CTX_reset(ps_context->mdctx_header);
            // - For RSA: configures SHA256 and padding automatically (if specified)
            // - For Ed25519: ignores the digest parameter and uses internal setup
            int init_res = 0;
            int pkey_type = EVP_PKEY_id(current_pubkey);

            if (pkey_type == EVP_PKEY_ED25519)
            {
               // Ed25519 does NOT want an external SHA256 digest
               init_res = EVP_DigestVerifyInit(ps_context->mdctx_header, NULL, NULL, NULL, current_pubkey);
            }
            else
            {
               // deallocate
               ps_context->header_vfy = 0;

            }

            if (init_res == 1)
            {
               char *h_fields[MAX_CAPACITY];
               int h_count = ps_context->h_num_fields;
               char *saveptr;
               char *token;
               char h_work_copy[BIG_HEADER_VALUE+1];
               securecpy(h_work_copy, ps_context->params.h_signfields, sizeof(h_work_copy));

               size_t buf_size = (BIG_HEADER_VALUE + 64) * (h_count + 1);
               char *pc_header_to_verify = calloc(1, buf_size);
               char *p_ptr = pc_header_to_verify; // Cursor to avoid slow strcat
               if (!pc_header_to_verify)
               {
                  if (current_pubkey) EVP_PKEY_free(current_pubkey);
                  return SMFIS_TEMPFAIL;
               }
               // 1. Split the h= fields
               token = strtok_r(h_work_copy, ":", &saveptr);
               while (token != NULL && h_count < 128)
               {
                  h_fields[h_count++] = token;
                  token = strtok_r(NULL, ":", &saveptr);
               }

               for (int i=0; i< ps_context->header_cnt; i++)
               {
                  ps_context->headers[i].used_for_signature = 0;
               }

               // 2. Header reconstruction loop for h= fields
               for (int i = 0; i < h_count; i++)
               {
                  char *target_name = h_fields[i];
                  for (int j = ps_context->header_cnt - 1; j >= 0; j--)
                  {
                     if (strcasecmp(ps_context->headers[j].name, target_name) == 0 &&
                     ps_context->headers[j].used_for_signature == 0)
                     {
                        char canon_buf[BIG_HEADER_VALUE + MAX_HEADER_NAME + 64];
                        if (ps_context->i_hdr_relaxed)
                        {
                           canonicalize_header_relaxed(ps_context->headers[j].name,
                           ps_context->headers[j].value, canon_buf, sizeof(canon_buf), 1);
                        }
                        else
                        {
                           snprintf(canon_buf, sizeof(canon_buf), "%s: %s\r\n",
                           ps_context->headers[j].name, ps_context->headers[j].value);
                        }
                        // Copy into the mega-buffer and advance the pointer
                        size_t len = strlen(canon_buf);
                        memcpy(p_ptr, canon_buf, len);
                        p_ptr += len;

                        ps_context->headers[j].used_for_signature = 1;
                        break;
                     }
                  }
               }

               // --- 3. THE MISSING PIECE: Add the AMS itself ---
               // Find the current AMS, canonicalize it, strip b= and append it
               for (int j = 0; j < ps_context->header_cnt; j++)
               {
                  if (strcasecmp(ps_context->headers[j].name, "ARC-Message-Signature") == 0 &&
                  ps_context->headers[j].arc_index == ps_context->found_arc)
                  {
                     char ams_canon[BIG_HEADER_VALUE + 128];
                     if (ps_context->i_hdr_relaxed)
                     {
                        canonicalize_arc_ms_for_verify(ps_context->headers[j].name,
                        ps_context->headers[j].value, ams_canon, sizeof(ams_canon));
                        // unfold (ams_canon);
                     }
                     else
                     {
                        snprintf(ams_canon, sizeof(ams_canon), "%s: %s",
                        ps_context->headers[j].name, ps_context->headers[j].value);    // da VERIFICARE !!!!!!!!!
                     }

                     // Essential: strip the b= tag before verifying
                     // prepare_header_for_hash(ams_canon);
                     size_t len = strlen(ams_canon);
                     memcpy(p_ptr, ams_canon, len);
                     p_ptr += len;
                     break;
                  }
               }
               // 4. FINAL VERIFICATION
               size_t total_len = p_ptr - pc_header_to_verify;

               int result = EVP_DigestVerify(ps_context->mdctx_header, firma_binaria, firma_bin_len,
               (unsigned char*)pc_header_to_verify, total_len);

               free(pc_header_to_verify);
               if (result == 1)
               {
                  ps_context->header_vfy = 1;
                  syslog(LOG_INFO, "DA_EOM: AMS - Valid signature (%s)!", (pkey_type == EVP_PKEY_RSA ? "RSA" : "Ed25519"));
               }
               else
               {
                  ps_context->header_vfy = 0;
                  syslog(LOG_NOTICE, "DA_EOM: AMS - Signature failed!");
               }
            }
         }
      }
   }
   else
   {
      syslog(LOG_ERR, "DA_EOM - Public key not found in DNS");
   }

   //>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

   // 1. EXTRACTION (what you will use at the end)
   // firma_binaria = decode_base64(ps_context->params.b_sign_AS);

   // 2. BUILD THE HASH (the "body" of the seal)
   // EVP_DigestUpdate(AAR_header);
   // EVP_DigestUpdate(AMS_header);
   // if (i > 1) EVP_DigestUpdate(AS_header_precedente);

   // AND FINALLY...
   // canonicalize_header_relaxed(AS_header_corrente, buffer);
   // prepare_header_for_hash(buffer); // This function strips the value after b=
   // EVP_DigestUpdate(ps_context->mdctx_header, buffer, strlen(buffer));

   // 3. VERIFY
   // EVP_DigestFinal_ex(...);
   // EVP_PKEY_verify(ctx, firma_binaria, ...);

   // char as_header_to_hash[MAX_HEADER_NAME+MAX_HEADER_VALUE];

   bool is_ed_AS = (ps_context->params.a_alg_AS[0] != '\0' &&
   strstr(ps_context->params.a_alg_AS, "ed25519") != NULL);

   EVP_PKEY *as_pubkey = NULL;
   bool as_key_is_borrowed = false;

   if (strcmp(ps_context->params.d_domain_AMS, ps_context->params.d_domain_AS) == 0 &&
   strcmp(ps_context->params.s_arcselector_AMS, ps_context->params.s_arcselector_AS) == 0)
   {
      as_pubkey = current_pubkey; // current_pubkey is the AMS key
      as_key_is_borrowed = true;
   }
   else
   {
      char ca_dns_key_as[MAX_PUB_KEY];

      clock_gettime(CLOCK_MONOTONIC, &ts_end);
      ps_context->cpu_ns += diff_ns(ts_start, ts_end);

      clock_gettime(CLOCK_MONOTONIC, &ts_start);

      int esito=get_dns_arc_pubkey(ps_context->params.d_domain_AS, ps_context->params.s_arcselector_AS,
      ca_dns_key_as, sizeof(ca_dns_key_as) - 1);
      clock_gettime(CLOCK_MONOTONIC, &ts_end);
      ps_context->dns_ns += diff_ns(ts_start, ts_end);
      clock_gettime(CLOCK_MONOTONIC, &ts_start);

      if (esito)
      {
         as_pubkey = decode_dns_key(ca_dns_key_as, is_ed_AS);
         as_key_is_borrowed = false;
      }
   }

   if (as_pubkey != NULL)
   {
      int pkey_type = EVP_PKEY_id(as_pubkey);
      bool b_header_relaxed_AS = true;
      int N = ps_context->found_arc;

      // Decode AS signature
      unsigned char signature[512];
      int sig_len = decode_base64_sig(ps_context->params.b_sign_AS,
      signature, sizeof(signature));

      if (pkey_type == EVP_PKEY_ED25519)
      {
         // Ed25519: ONE-SHOT — accumulate everything in a buffer, then EVP_DigestVerify
         size_t buf_size = (BIG_HEADER_VALUE + 128) * (N * 3 + 1);
         char *pc_as_buf = calloc(1, buf_size);
         if (!pc_as_buf)
         {
            if (!as_key_is_borrowed && as_pubkey) EVP_PKEY_free(as_pubkey);
            if (current_pubkey) EVP_PKEY_free(current_pubkey);
            return SMFIS_TEMPFAIL;
         }
         char *p_ptr = pc_as_buf;

         for (int lvl = 1; lvl <= N; lvl++)
         {
            // AAR
            for (int j = 0; j < ps_context->header_cnt; j++)
            {
               if (strcasecmp(ps_context->headers[j].name, "ARC-Authentication-Results") == 0 &&
               ps_context->headers[j].arc_index == lvl)
               {
                  char canon[BIG_HEADER_VALUE + 128];
                  canonicalize_header_relaxed(ps_context->headers[j].name,
                  ps_context->headers[j].value, canon, sizeof(canon), 1);
                  size_t len = strlen(canon);
                  memcpy(p_ptr, canon, len); p_ptr += len;
                  break;
               }
            }
            // AMS
            for (int j = 0; j < ps_context->header_cnt; j++)
            {
               if (strcasecmp(ps_context->headers[j].name, "ARC-Message-Signature") == 0 &&
               ps_context->headers[j].arc_index == lvl)
               {
                  char canon[BIG_HEADER_VALUE + 128];
                  canonicalize_header_relaxed(ps_context->headers[j].name,
                  ps_context->headers[j].value, canon, sizeof(canon), 1);
                  size_t len = strlen(canon);
                  memcpy(p_ptr, canon, len); p_ptr += len;
                  break;
               }
            }
            // AS — zero out b= only for the current level N
            for (int j = 0; j < ps_context->header_cnt; j++)
            {
               if (strcasecmp(ps_context->headers[j].name, "ARC-Seal") == 0 &&
               ps_context->headers[j].arc_index == lvl)
               {
                  char canon[BIG_HEADER_VALUE + 128];
                  canonicalize_arc_ms_for_verify(ps_context->headers[j].name,
                  ps_context->headers[j].value, canon, sizeof(canon));
                  // zero b= only for the last level
                  // (for earlier levels the signature is already in the value)
                  if (lvl < N)
                  {
                     // earlier levels: leave b= intact
                     // reconstruct without zeroing
                     char canon2[BIG_HEADER_VALUE + 128];
                     canonicalize_header_relaxed(ps_context->headers[j].name,
                     ps_context->headers[j].value, canon2, sizeof(canon2), 1);
                     size_t len = strlen(canon2);
                     memcpy(p_ptr, canon2, len); p_ptr += len;
                  }
                  else
                  {
                     // level N: b= empty (canonicalize_arc_ms_for_verify already handles this)
                     size_t len = strlen(canon);
                     memcpy(p_ptr, canon, len); p_ptr += len;
                  }
                  break;
               }
            }
         }

         size_t total = p_ptr - pc_as_buf;
         EVP_MD_CTX *as_vctx = EVP_MD_CTX_new();
         EVP_DigestVerifyInit(as_vctx, NULL, NULL, NULL, as_pubkey);
         int res = EVP_DigestVerify(as_vctx, signature, sig_len,
         (unsigned char*)pc_as_buf, total);
         EVP_MD_CTX_free(as_vctx);
         free(pc_as_buf);

         ps_context->seal_vfy = (res == 1) ? 1 : 0;
         syslog(LOG_INFO, "DA_EOM: ARC-Seal (i=%d): %s (Ed25519)", N,
         (res == 1) ? "VALID" : "INVALID");
      }
      else
      {
         // RSA: unchanged path with Update/Final
         EVP_MD_CTX *as_vctx = EVP_MD_CTX_new();
         EVP_DigestVerifyInit(as_vctx, NULL, EVP_sha256(), NULL, as_pubkey);

         for (int lvl = 1; lvl <= N; lvl++)
         {
            for (int j = 0; j < ps_context->header_cnt; j++)
            {
               if (strcasecmp(ps_context->headers[j].name, "ARC-Authentication-Results") == 0 &&
               ps_context->headers[j].arc_index == lvl)
               {
                  feed_header_to_digest(as_vctx, ps_context, j, b_header_relaxed_AS, false);
                  break;
               }
            }
            for (int j = 0; j < ps_context->header_cnt; j++)
            {
               if (strcasecmp(ps_context->headers[j].name, "ARC-Message-Signature") == 0 &&
               ps_context->headers[j].arc_index == lvl)
               {
                  feed_header_to_digest(as_vctx, ps_context, j, b_header_relaxed_AS, false);
                  break;
               }
            }
            for (int j = 0; j < ps_context->header_cnt; j++)
            {
               if (strcasecmp(ps_context->headers[j].name, "ARC-Seal") == 0 &&
               ps_context->headers[j].arc_index == lvl)
               {
                  feed_header_to_digest(as_vctx, ps_context, j, b_header_relaxed_AS, (lvl == N));
                  break;
               }
            }
         }

         unsigned char sig2[512];
         int sig2_len = decode_base64_sig(ps_context->params.b_sign_AS, sig2, sizeof(sig2));
         int res = EVP_DigestVerifyFinal(as_vctx, sig2, sig2_len);
         EVP_MD_CTX_free(as_vctx);

         ps_context->seal_vfy = (res == 1) ? 1 : 0;
         syslog(LOG_INFO, "DA_EOM: ARC-Seal (i=%d): %s (RSA)", N,
         (res == 1) ? "VALID" : "INVALID");
      }

      /* DA-1: key cleanup centralized before the final return (handles the
       * as_pubkey == NULL path too, which this block would otherwise skip). */
   }
   else
   {
      syslog(LOG_ERR, "DA_EOM: as_pubkey NULL. Missing DNS key or decode failure for this level");
   }



   //////////////////  BUILD AUTHENTICATION RESULTS

   char aar_string[4096];
   char arc_details[256];
   const char *arc_verdict;



   if (ps_context->is_localhost == 0)
   {
      // 1. Determine the textual verdict
      if (ps_context->found_arc == 0)
      {
         arc_verdict = "none";
         snprintf(arc_details, sizeof(arc_details), "no signatures found");
      }
      else
      {
         int res = verify_arc_chain(ps_context);
         if (res == 1)
         {
            arc_verdict = "pass";
            const char *received_cv = ps_context->params.cv;
            if (received_cv == NULL || strlen(received_cv) == 0)
            {
               received_cv = "none"; // Case i=1
            }
            // Useful details for debug/user
            snprintf(arc_details, sizeof(arc_details), "as.%d.pass ams.%d.pass cv=%s",
            ps_context->found_arc, ps_context->found_arc,
            received_cv); // prev_cv extracted from the last ARC-Seal
         }
         else
         {
            arc_verdict = "fail";
            snprintf(arc_details, sizeof(arc_details), "verification failed");
         }
      }


      // 2. Final composition, Microsoft-style (ordered and clean)
      // Use the results saved in the context from the recent parsing
      // Utility macro to avoid NULLs in snprintf
      #define SAFE_ID(s)  ((s) && (s)[0] != '\0' ? (s) : "unknown")
      #define SAFE_STR(s) ((s) && (s)[0] != '\0' ? (s) : "none")
      get_results_from_auth_headers(ps_context);


      snprintf(aar_string, sizeof(aar_string),
      "i=%d; %s;\n"
      " arc=%s (%s);\n"
      " spf=%s smtp.mailfrom=%s;%s" // <-- %s inietterà "\r\n    dkim=pass..."
      "\n dmarc=%s header.from=%s",
      ps_context->found_arc + 1,
      (my_hostname[0] != '\0' ? my_hostname : "localhost"),
      arc_verdict, arc_details,
      SAFE_STR(ps_context->spf_res),  SAFE_ID(ps_context->spf_id),
      ps_context->dkim_results_buf,   // Multi-signature buffer
      SAFE_STR(ps_context->dmarc_res), SAFE_ID(ps_context->dmarc_id));


      // 3. Inject the header
      smfi_addheader(ctx, "ARC-Authentication-Results", aar_string);
   }
   if (ps_context->is_localhost == 0)
   {
      // Validation passed! Pass the ticket to the outbound milter.
      // Also insert the i= index so the outbound milter knows where we left off.
      clock_gettime(CLOCK_MONOTONIC, &ts_end);
      ps_context->cpu_ns += diff_ns(ts_start, ts_end);

      //    struct timespec end_time;

      //    clock_gettime(CLOCK_MONOTONIC, &end_time);
      char h_val[356];
      char hs_val[128];
      char hs1_val[128];

      // Compute elapsed time in milliseconds
      //    double elapsed_ms1 = (ps_context->cpu_ns) * 1000.0;
      //    elapsed_ms1 += (end_time.tv_nsec - ps_context->start_time.tv_nsec) / 1000000.0;

      //    double elapsed_ms = (end_time.tv_sec - ps_context->start_time.tv_sec) * 1000.0;
      //    elapsed_ms += (end_time.tv_nsec - ps_context->start_time.tv_nsec) / 1000000.0;


      // Total time since connection (da_envfrom)
      struct timespec now;
      clock_gettime(CLOCK_MONOTONIC, &now);

      unsigned long long total_ns = (unsigned long long)(now.tv_sec - ps_context->start_time.tv_sec) * 1000000000ULL +
      (now.tv_nsec - ps_context->start_time.tv_nsec);

      // Network time by exclusion
      // Note: Network = Total - (everything we measured ourselves)
      unsigned long long net_ns = (total_ns > (ps_context->cpu_ns + ps_context->dns_ns)) ?
      total_ns - (ps_context->cpu_ns + ps_context->dns_ns) : 0;

      char cpu_buf[32], dns_buf[32], net_buf[32];
      format_runtime(ps_context->cpu_ns, cpu_buf, sizeof(cpu_buf));
      format_runtime(ps_context->dns_ns, dns_buf, sizeof(dns_buf));
      format_runtime(net_ns, net_buf, sizeof(net_buf));

      // Final header: i=2; cpu=340.52ms; dns=450.10ms; net=1.05s
      snprintf (hs1_val, sizeof(hs_val), "cpu=%s; dns=%s; other=%s",
      cpu_buf, dns_buf, net_buf);


      // Prepare the header
      //    snprintf(h_val, sizeof(h_val), "status=%s; time=%.2fms",
      //             tuo_status_stringa, elapsed_ms);
      if (ps_context->body_size<1024)
      snprintf(hs_val, sizeof(hs_val), "%d bytes", ps_context->body_size);
      else if (ps_context->body_size<1048576)
      snprintf(hs_val, sizeof(hs_val), "%d Kbytes", ps_context->body_size/1024);
      else
      snprintf(hs_val, sizeof(hs_val), "%d Mbytes", ps_context->body_size/1048576);

      snprintf(h_val, sizeof(h_val), "%s; i=%d; %s; %s",
      arc_verdict, ps_context->found_arc+1, hs_val, hs1_val);

      // Inject the header
      smfi_addheader(ctx, "X-DarkARC-Internal-Status", h_val);


   }


   /* DA-1: free both ARC public keys on every exit path.  as_pubkey is freed
    * only when it is a distinct key (not borrowed from current_pubkey);
    * current_pubkey is always owned and always freed. */
   if (!as_key_is_borrowed && as_pubkey) EVP_PKEY_free(as_pubkey);
   if (current_pubkey) EVP_PKEY_free(current_pubkey);

   return SMFIS_CONTINUE;

}



// Utility to clean extracted values
void clean_value(char *s)
{
   while (*s)
   {
      if (*s == '\r' || *s == '\n' || *s == '\t' || *s == ';') *s = '\0';
      else s++;
   }
}

const char* extract_and_move_p(const char *p, const char *prefix, const char *id_prefix, char *res_out, char *id_out) 
{
    if (!p) return NULL;
    const char *start_search = strcasestr(p, prefix);
    if (!start_search) return NULL;
    const char *val_start = start_search + strlen(prefix);
    const char *val_end = strpbrk(val_start, " \t;(\r\n");
    size_t v_len = val_end ? (size_t)(val_end - val_start) : strlen(val_start);
    if (v_len > 31) v_len = 31;
    memcpy(res_out, val_start, v_len);
    res_out[v_len] = '\0';
    const char *id_ptr = strcasestr(val_start, id_prefix);
    if (!id_ptr) return val_start + v_len;
    id_ptr += strlen(id_prefix);
    const char *id_end = strpbrk(id_ptr, " \t;(\r\n");
    size_t i_len = id_end ? (size_t)(id_end - id_ptr) : strlen(id_ptr);
    if (i_len > 255) i_len = 255;
    memcpy(id_out, id_ptr, i_len);
    id_out[i_len] = '\0';
    // Advance past the ; that closes the whole dkim= entry
    const char *next = id_end ? id_end : id_ptr + i_len;
    while (*next && *next != ';') next++;
    if (*next == ';') next++;
    return next;
}


void get_results_from_auth_headers(struct context *ps_context)
{
   ps_context->dkim_results_buf[0] = '\0';

   for (int j = 0; j < ps_context->header_cnt; j++)
   {
      if (strcasecmp(ps_context->headers[j].name, "Authentication-Results") != 0) continue;

      const char *h_val = ps_context->headers[j].value;

      // Skip leading spaces and tabs for safety
      while (*h_val == ' ' || *h_val == '\t') h_val++;

      // More robust hostname match
      if (strncmp(h_val, my_hostname, strlen(my_hostname)) != 0) continue;

      // Extract SPF and DMARC (if present in this header)
      extract_auth_detail(h_val, "spf=", "smtp.mailfrom=", ps_context->spf_res, ps_context->spf_id);
      extract_auth_detail(h_val, "dmarc=", "header.from=", ps_context->dmarc_res, ps_context->dmarc_id);

      // Scan for multiple DKIM entries
      const char *current_p = h_val;
      while ((current_p = strcasestr(current_p, "dkim=")) != NULL)
      {
         char res[32] = {0}, id[256] = {0};
         char tmp_line[512];

         current_p = extract_and_move_p(current_p, "dkim=", "header.d=", res, id);

         if (res[0] != '\0' && id[0] != '\0')
         {
            clean_value(res); // Remove any leftover \r\n
            clean_value(id);
            snprintf(tmp_line, sizeof(tmp_line), "\r\n dkim=%s header.d=%s;", res, id);
            char search_pattern[300];
            snprintf(search_pattern, sizeof(search_pattern), "header.d=%s;", id);
            if (strstr(ps_context->dkim_results_buf, search_pattern) == NULL) 
            {
              strncat(ps_context->dkim_results_buf, tmp_line,
              sizeof(ps_context->dkim_results_buf) - strlen(ps_context->dkim_results_buf) - 1);
            }
         }
         if (!current_p) break;
      }
   }
}

static void feed_header_to_digest(EVP_MD_CTX *ctx, struct context *ps_context,
                                   int idx, bool relaxed, bool strip_b)
{
    char buf[BIG_HEADER_VALUE + 256];
    if (relaxed)
        canonicalize_header_relaxed(ps_context->headers[idx].name,
                                    ps_context->headers[idx].value,
                                    buf, sizeof(buf),1);
    else
        snprintf(buf, sizeof(buf), "%s: %s\r\n",
                 ps_context->headers[idx].name,
                 ps_context->headers[idx].value);

    if (strip_b)
        prepare_header_for_hash(buf);

    EVP_DigestVerifyUpdate(ctx, buf, strlen(buf));
}



// Helper: find the real section delimiter (outside parentheses)
const char* find_real_section_end(const char* p)
{
    int nesting = 0;
    while (*p)
    {
        if (*p == '(') nesting++;
        else if (*p == ')') nesting--;
        else if (*p == ';' && nesting == 0) return p; // Found ; outside comments
        p++;
    }
    return NULL; // End of string
}

void extract_auth_detail(const char *val, const char *method, const char *id_tag, char *out_res, char *out_id)
{
   // Look for the method start (e.g. "dkim=")
   const char *start = strcasestr(val, method);
   if (!start) return;

   start += strlen(method);
   while (*start == ' ' || *start == '=' || *start == '\t') start++;

   // 1. Extract the result (pass, fail, etc.)
   // Stop at space, semicolon, or start of comment
   int i = 0;
   while (start[i] && !isspace((unsigned char)start[i]) && start[i] != ';' && start[i] != '(' && i < 23)
   {
      out_res[i] = start[i];
      i++;
   }
   out_res[i] = '\0';

   // 2. Look for the identifier (header.d=, etc.)
   // Define the current section boundary intelligently
   const char *section_end = find_real_section_end(start);
   const char *id_ptr = strcasestr(start, id_tag);

   // If we find id_tag before the real section end
   if (id_ptr && (!section_end || id_ptr < section_end))
   {
      id_ptr += strlen(id_tag);
      while (*id_ptr == ' ' || *id_ptr == '=' || *id_ptr == '\t') id_ptr++;

      int j = 0;
      // Extract the ID value
      while (id_ptr[j] && !isspace((unsigned char)id_ptr[j]) && id_ptr[j] != ';' && id_ptr[j] != '(' && j < 127)
      {
         out_id[j] = id_ptr[j];
         j++;
      }
      out_id[j] = '\0';
   }
}


int verify_arc_chain (struct context * ps_context)
{
   if (ps_context->found_arc)
   {
      if ((ps_context->body_integrity) && (ps_context->header_vfy) && (ps_context->seal_vfy))
      return 1;
      else
      return -1;
   }
   else
   return 0;
}


sfsistat da_begin(SMFICTX *ctx)
{

   return SMFIS_CONTINUE;
}


sfsistat da_envfrom(SMFICTX *ctx, char **argv)
{
   // 1. Retrieve the private structure
   struct context *priv = (struct context *)smfi_getpriv(ctx);

   clock_gettime(CLOCK_MONOTONIC, &priv->start_time);



   if (argv[0] != NULL)
   {
      char *p = strchr(argv[0], '@');
      if (p)
      {
         strncpy(priv->spf_id, p + 1, sizeof(priv->spf_id) - 1);
         // Clean up eventuale '>' finale
         char *end = strchr(priv->spf_id, '>');
         if (end) *end = '\0';
      }
      else
      {
         strncpy(priv->spf_id, argv[0], sizeof(priv->spf_id) - 1);
      }
   }
   priv->msg_count++;

   // 2. First mail on this connection: allocate
   if (priv->msg_count == 1)
   {

      // Allocate the header reservoir (es. 256 slot)
      priv->header_capacity = MAX_CAPACITY;

      priv->h_num_fields = 0;            // number of fields to hash or buffer for signature verification
      priv->pending_newlines_relaxed=0;
      priv->body_has_content_relaxed=0;
      priv->pending_newlines_simple=0;
      priv->body_size = 0;
      priv->body_has_content_simple=0;
      priv->is_start_of_line=0;
      priv->header_cnt = 0;
      priv->p_had_space=0;
      memset(priv->spf_res, 0, sizeof(priv->spf_res));
      memset(priv->dmarc_res, 0, sizeof(priv->dmarc_res));        // return SMFIS_CONTINUE;
      priv->found_arc = 0;


      return SMFIS_CONTINUE;
   }
   else
   { 
      // 3. Not NULL: connection is being reused (RSET).
      // Reset previous mail data without freeing everything.
      EVP_MD_CTX_reset(priv->mdctx_body_relaxed);
      EVP_MD_CTX_reset(priv->mdctx_body_simple);
      EVP_MD_CTX_reset(priv->mdctx_header);
      // 4. Initialize SHA-256 for the new message
      if (EVP_DigestInit_ex(priv->mdctx_header, EVP_sha256(), NULL) != 1)
      {
         return SMFIS_TEMPFAIL;
      }

      if (EVP_DigestInit_ex(priv->mdctx_body_simple, EVP_sha256(), NULL) != 1)
      {
         return SMFIS_TEMPFAIL;
      }
      if (EVP_DigestInit_ex(priv->mdctx_body_relaxed, EVP_sha256(), NULL) != 1)
      {
         return SMFIS_TEMPFAIL;
      }

      priv->header_cnt = 0;
      priv->found_arc = 0;
      priv->pending_newlines_simple=0;
      priv->body_has_content_simple=0;
      priv->body_size = 0;
      priv->pending_newlines_relaxed=0;
      priv->body_has_content_relaxed=0;
      priv->is_start_of_line=0;
      memset (priv->body_hash, '\0', EVP_MAX_MD_SIZE);
      priv->body_hash_len=0;
      priv->p_had_space=0;

      // memset(priv->history, 0, sizeof(priv->history));
      // Reset the 'used' flag for every slot in the reservoir
      for(int i=0; i < priv->header_capacity; i++)
      {
         priv->headers[i].name[0]=0;
         priv->headers[i].value[0]=0;
         priv->headers[i].arc_index=0;
         priv->headers[i].used_for_signature = 0;
         // If you used strdup for values, free() them here
      }
   }


   return SMFIS_CONTINUE;
}


int main(int argc, char *argv[])
{
   tzset();
   openlog("DarkARC", LOG_PID | LOG_NDELAY, SYSLOG_FACILITY);
   int i_get=0, i_ret=0;
   const char *pc_ofile = NULL;
   bool b_fail=0;
   if (argc < 2)
   {
      fprintf(stderr, "Usage: %s <socket-path>\n", argv[0]);
      return 1;
   }

   while ((i_get = getopt(argc, argv, "p:u:U:")) != -1)
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
         da_usage(argv[0]);
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
         fprintf(stderr, "getpwnam: %s: %s\n", pc_user,
         strerror(errno));
         return (1);
      }
      setgroups(1, &pw->pw_gid);
      if (setegid(pw->pw_gid) || setgid(pw->pw_gid))
      {
         fprintf(stderr, "setgid: %s\n", strerror(errno));
         return (1);
      }
      if (
      seteuid(pw->pw_uid) ||
      setuid(pw->pw_uid))
      {
         fprintf(stderr, "setuid: %s\n", strerror(errno));
         return (1);
      }
   }
   if (smfi_setconn((char *)pc_oconn) != MI_SUCCESS)
   {
      fprintf(stderr, "smfi_setconn: %s: failed\n", pc_oconn);
      b_fail = 1;
   }
   if ((!b_fail) && (smfi_register(arcmilter) != MI_SUCCESS) )
   {
      fprintf(stderr, "smfi_register: failed\n");
      goto done;
   }
   if ((!b_fail) && (daemon(0, 0)))
   {
      fprintf(stderr, "daemon: %s\n", strerror(errno));
      goto done;
   }
   umask(0177);
   signal(SIGPIPE, SIG_IGN);
   signal(SIGTERM, cleanup_and_exit);
   signal(SIGINT,  cleanup_and_exit);
   i_ret = smfi_main();

   if (i_ret != MI_SUCCESS)
   syslog(LOGLEVEL, "[ERROR] DarkARC terminated due to a fatal error");
   done:
   return (i_ret);

   if (smfi_register(arcmilter) == MI_FAILURE) return 1;

}

// Helper function
void cleanup_session(SMFICTX *ctx)
{
   struct context *priv = (struct context *)smfi_getpriv(ctx);
   if (priv != NULL)
   {
      // 1. Free the header reservoir
      if (priv->headers)
      {
         free(priv->headers);
      }

      // 2. Free the OpenSSL context
      if (priv->mdctx_body_simple) EVP_MD_CTX_free(priv->mdctx_body_simple);
      if (priv->mdctx_body_relaxed) EVP_MD_CTX_free(priv->mdctx_body_relaxed);
      if (priv->mdctx_header) EVP_MD_CTX_free(priv->mdctx_header);

      // 3. Critical: null out the pointer in the milter context
      smfi_setpriv(ctx, NULL);

      // 4. Free the main structure
      free(priv);
   }
}

sfsistat da_abort(SMFICTX *ctx)
{
   struct context *priv = (struct context *)smfi_getpriv(ctx);
   if (priv != NULL)
   {
      cleanup_message(priv); // Clean up the message but keep 'priv' alive
   }
   return SMFIS_CONTINUE;
}

sfsistat da_close(SMFICTX *ctx)
{
   struct context *priv = (struct context *)smfi_getpriv(ctx);
   if (priv != NULL)
   {
      cleanup_message(priv); // Last message cleanup

      smfi_setpriv(ctx, NULL);
      free(priv); // NOW free the main structure
   }
   return SMFIS_CONTINUE;
}


void cleanup_message(struct context *priv)
{
   if (priv == NULL) return;

   // Free only data tied to the single MESSAGE
   if (priv->headers)
   {
      free(priv->headers);
      priv->headers = NULL;
   }

   if (priv->mdctx_body_simple)
   {
      EVP_MD_CTX_free(priv->mdctx_body_simple);
      priv->mdctx_body_simple = NULL;
   }
   if (priv->mdctx_body_relaxed)
   {
      EVP_MD_CTX_free(priv->mdctx_body_relaxed);
      priv->mdctx_body_relaxed = NULL;
   }
   if (priv->mdctx_header)
   {
      EVP_MD_CTX_free(priv->mdctx_header);
      priv->mdctx_header = NULL;
   }

   // Reset other per-message flags
   priv->msg_count = 0;
}



sfsistat da_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr)
{
   struct context *ps_context = calloc(1, sizeof(struct context));
   if (ps_context == NULL) return SMFIS_TEMPFAIL;

   smfi_setpriv(ctx, ps_context); // Salva nel thread corrente


   if (hostaddr != NULL)
   {
      syslog(LOG_DEBUG, "DA_CONNECT: sa_family=%d", hostaddr->sa_family);
      if (hostaddr->sa_family == AF_INET)
      {
         struct sockaddr_in *sa = (struct sockaddr_in *)hostaddr;
         char ip[INET_ADDRSTRLEN];
         inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));
         syslog(LOG_DEBUG, "DA_CONNECT: IPv4 raw = [%s]", ip);
      }
      else if (hostaddr->sa_family == AF_INET6)
      {
         struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)hostaddr;
         char ip[INET6_ADDRSTRLEN];
         inet_ntop(AF_INET6, &sa6->sin6_addr, ip, sizeof(ip));
         syslog(LOG_DEBUG, "DA_CONNECT: IPv6 raw = [%s]", ip);
      }
   }


   // Allocate hash engines once per connection
   //    ps_context->mdctx_header = EVP_MD_CTX_new();
   //    ps_context->mdctx_body_simple = EVP_MD_CTX_new();
   //    ps_context->mdctx_body_relaxed = EVP_MD_CTX_new();
   ps_context->msg_count=0;
   ps_context->mdctx_header = EVP_MD_CTX_new();
   ps_context->mdctx_body_simple = EVP_MD_CTX_new();
   ps_context->mdctx_body_relaxed = EVP_MD_CTX_new();

   EVP_DigestInit_ex(ps_context->mdctx_header, EVP_sha256(), NULL);
   EVP_DigestInit_ex(ps_context->mdctx_body_relaxed, EVP_sha256(), NULL);
   EVP_DigestInit_ex(ps_context->mdctx_body_simple, EVP_sha256(), NULL);

   // Create OpenSSL context for the body hash
   // priv->mdctx_header = EVP_MD_CTX_new();
   // priv->mdctx_body = EVP_MD_CTX_new();   // ATTENZIONE

   // Save the struct in the Milter context
   //   smfi_setpriv(ctx, priv);
   ps_context->header_capacity=MAX_CAPACITY;
   ps_context->header_cnt=0;

   // Allocate the header reservoir
   ps_context->headers = calloc(ps_context->header_capacity, sizeof(struct header_slot));
   ps_context->is_localhost = 0; // Default: traffico esterno


   // 1. ASK THE MTA: What do you see?
   char *c_addr = smfi_getsymval(ctx, "{client_addr}");

   if (c_addr != NULL)
   {
      // Check IPv4 string (127.0.0.x)
      if (strncmp(c_addr, "127.", 4) == 0)
      {
         ps_context->is_localhost = 1;
      }
      // Check IPv6 string (::1)
      else if (strcmp(c_addr, "::1") == 0)
      {
         ps_context->is_localhost = 1;
      }
      // Check IPv4-mapped IPv6 (::ffff:127...)
      else if (strncasecmp(c_addr, "::ffff:127.", 11) == 0)
      {
         ps_context->is_localhost = 1;
      }
   }

   // 2. FALLBACK: If the macro fails, inspect the binary socket
   if (!ps_context->is_localhost && hostaddr != NULL)
   {
      if (hostaddr->sa_family == AF_UNIX)
      {
         ps_context->is_localhost = 1; // Local socket = always localhost
      }
      else if (hostaddr->sa_family == AF_INET)
      {
         struct sockaddr_in *sa = (struct sockaddr_in *)hostaddr;
         // Check whether the first byte is 127 (0x7F)
         if ((ntohl(sa->sin_addr.s_addr) >> 24) == 0x7F)
         {
            ps_context->is_localhost = 1;
         }
      }
      else if (hostaddr->sa_family == AF_INET6)
      {
         struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)hostaddr;
         if (IN6_IS_ADDR_LOOPBACK(&sa6->sin6_addr))
         {
            ps_context->is_localhost = 1;
         }
         else if (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr))
         {
            // Extract the IPv4 byte from the mapped address (byte 12 of s6_addr)
            if (sa6->sin6_addr.s6_addr[12] == 0x7F)
            {
               ps_context->is_localhost = 1;
            }
         }
      }
   }

   // Log the result for tomorrow's debugging
   syslog(LOG_INFO, "DA_CONNECT: [%s] client_addr macro='%s', is_localhost=%d",
   hostname ? hostname : "unknown",
   c_addr ? c_addr : "NULL",
   ps_context->is_localhost);

   return SMFIS_CONTINUE;


}


static sfsistat da_helo(SMFICTX *ctx, char *pc_helohost)
{
   struct context *ps_context;

   syslog(LOGLEVEL, "DA_HELO: start");

   if ((ps_context = (struct context *)smfi_getpriv(ctx)) == NULL)
   {
      syslog(LOGLEVEL, "DA_HELO: smfi_getpriv error");
      return (SMFIS_ACCEPT);
   }
   securecpy(ps_context->helo, pc_helohost, sizeof(ps_context->helo));

   syslog(LOGLEVEL, "DA_HELO: end %s", ps_context->helo);
   return (SMFIS_CONTINUE);
}



static sfsistat da_envrcpt(SMFICTX *ctx, char **args)
{
   return (SMFIS_CONTINUE);
}

static sfsistat da_eoh(SMFICTX *ctx)
{
   char h_work_copy[BIG_HEADER_VALUE+1];

   struct context *ps_context;


   // Use a reasonable limit for h= fields
   char *h_fields[MAX_CAPACITY];
   int h_count = 0;
   int i_rsa=1;

   struct timespec cb_start, cb_end;
   clock_gettime(CLOCK_MONOTONIC, &cb_start);

   if ((ps_context = (struct context *)smfi_getpriv(ctx)) == NULL)
   {
      syslog(LOG_ERR, "DA_EOH: smfi_getpriv failed");
      return SMFIS_ACCEPT;
   }


   // Header analysis
   ps_context->i_hdr_relaxed = 0;
   if (ps_context->params.c_canonic_AMS[0] != '\0')
   {
      if (strncmp(ps_context->params.c_canonic_AMS, "relaxed", 7) == 0)
      {
         ps_context->i_hdr_relaxed = 1;
      }
   }

   // Body analysis
   ps_context->i_body_relaxed = 0;
   char *slash = strchr(ps_context->params.c_canonic_AMS, '/');
   if (slash != NULL && strstr(slash + 1, "relaxed") != NULL)
   {
      ps_context->i_body_relaxed = 1;
   }


   if (ps_context->found_arc == 0)
   {
      syslog(LOG_DEBUG, "DA_EOH: No ARC headers found. Skipping validation.");
      return SMFIS_CONTINUE;
   }

   // strtok_r modifies the string, so work on a local copy
   // h_signfields must remain intact in the context
   strncpy(h_work_copy, ps_context->params.h_signfields, BIG_HEADER_VALUE);
   h_work_copy[BIG_HEADER_VALUE] = '\0';

   char *token = NULL; // Initialized to silence the warning
   char *saveptr = NULL;

   // 1. Split the h= fields, trimming spaces/newlines
   token = strtok_r(h_work_copy, ":", &saveptr);
   while (token != NULL && h_count < 128)
   {

      // TRIMMING: remove leading spaces, \r, \n
      while (*token == ' ' || *token == '\t' || *token == '\r' || *token == '\n')
      {
         token++;
      }

      // TRIMMING: remove trailing spaces, \r, \n
      char *end = token + strlen(token) - 1;
      while (end > token && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n'))
      {
         *end = '\0';
         end--;
      }

      // Add to the vector only if the token is not empty
      if (*token != '\0')
      {
         h_fields[h_count++] = token;
      }

      token = strtok_r(NULL, ":", &saveptr);
   }


   ps_context->h_num_fields=h_count;

   if (strcmp (ps_context->params.a_alg_AMS, "rsa-sha256")==0)
   {
      EVP_MD_CTX_init(ps_context->mdctx_header); // Initialize the structure
      EVP_DigestInit_ex(ps_context->mdctx_header, EVP_sha256(), NULL);  // da verificare
      i_rsa=1;
      // char a_alg_AS[32];
   } else if (strcmp(ps_context->params.a_alg_AMS, "ed25519-sha256") == 0)
   {
      // EVP_DigestVerify path
      i_rsa = 0;
   }


   if (i_rsa)
   // 2. Process headers (bottom-to-top for each field)
   for (int i = 0; i < h_count; i++)
   {
      char *target_name = h_fields[i];

      for (int j = ps_context->header_cnt - 1; j >= 0; j--)
      {

         if (strcasecmp(ps_context->headers[j].name, target_name) == 0 &&
         ps_context->headers[j].used_for_signature == 0)
         {

            char canon_buf[BIG_HEADER_VALUE + MAX_HEADER_NAME + 64];
            memset (canon_buf, 0, sizeof (canon_buf));

            if (ps_context->i_hdr_relaxed)
            {
               // Canonicalization (Relaxed)
               // Note: function must append trailing CRLF as per DKIM/ARC spec
               canonicalize_header_relaxed(ps_context->headers[j].name,
               ps_context->headers[j].value,
               canon_buf, sizeof(canon_buf),1);
            }
            else
            {
               // Simple: original name + colon + space + original value
               snprintf(canon_buf, sizeof(canon_buf), "%s: %s\r\n",
               ps_context->headers[j].name, ps_context->headers[j].value);
            }
            // Update OpenSSL hash
            if (DEBUG)
            {
               char bufferino[5000];
               securecpy(bufferino, canon_buf, strlen(canon_buf));
               bufferino[strlen(canon_buf)]='\0';
               syslog (LOG_DEBUG, "DA_EOH: hashed header [%s]", bufferino);
            }

            if (EVP_DigestUpdate(ps_context->mdctx_header, canon_buf, strlen(canon_buf)) != 1)
            {
               syslog(LOG_ERR, "DA_EOH: EVP_DigestUpdate failed");
            }
            else
            ps_context->headers[j].used_for_signature = 1;
            break;
         }
      }
   }
   if (DEBUG)
   {
      syslog (LOG_DEBUG, "DA_EOH: REFERENCE INDEX [%i]", ps_context->found_arc);
      syslog (LOG_DEBUG, "DA_EOH: cv [%s], algAMS [%s], alg_AS [%s]", ps_context->params.cv,
      ps_context->params.a_alg_AMS, ps_context->params.a_alg_AS);
      syslog (LOG_DEBUG, "DA:EOH: b_sign_AS [%s]",  ps_context->params.b_sign_AS);
      syslog (LOG_DEBUG, "DA_EOH: b_sign_AMS [%s]",  ps_context->params.b_sign_AMS);
      syslog (LOG_DEBUG, "DA_EOH: bh_bodyhash [%s]", ps_context->params.bh_bodyhash);
      syslog (LOG_DEBUG, "DA_EOH: c_canonic_AMS [%s]",
      ps_context->params.c_canonic_AMS);

      syslog (LOG_DEBUG,  "DA_EOH: d_domain_AMS [%s], d_domain_AS [%s]",  ps_context->params.d_domain_AMS,
      ps_context->params.d_domain_AS);
      syslog (LOG_DEBUG,  "DA_EOH: h_signfields [%s]",  ps_context->params.h_signfields);
      syslog (LOG_DEBUG,  "DA_EOH: s_arcselector_AMS [%s], s_arcselector_AS [%s]", ps_context->params.s_arcselector_AMS,
      ps_context->params.s_arcselector_AS);
   }

   clock_gettime(CLOCK_MONOTONIC, &cb_end); // <--- END
   ps_context->cpu_ns += diff_ns(cb_start, cb_end);

   return SMFIS_CONTINUE;

}



void da_usage(const char * usage)
{
   fprintf(stderr, "usage: %s [-u user] [-p pipe]\n", usage);
   exit(1);
}


// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
/*
 * Chain example (The "Wax Seal"):
 * Imagine you are server i=3 (the last one). To verify chain integrity,
 * verify the AS at i=2:
 *   - Take the AS at i=2 and read its signature b.
 *   - Pull the i=2-era headers from your reservoir:
 *       AAR (i=2),  AMS (i=2),  AS (i=1)
 *   - Canonicalize and feed to EVP_DigestVerifyUpdate.
 *   - Compare against the b signature of AS at i=2.
 *   - If OK: proof that server i=2 correctly sealed what came before it.
 *
 * Example, mail with i=1 (verify Microsoft's AS):
 *   Hash: arc-authentication-results:i=1; ... \r\n
 *   Hash: arc-message-signature:i=1;    ... \r\n
 *   (AS i=0 does not exist, stop here)
 *   Verify against b= of AS at i=1.
 *
 * Example, mail with i=2:
 *   Hash AAR at i=2, AMS at i=2, AS at i=1 (previous server's seal).
 *   Verify against b= of AS at i=2.
 *
 * Summary:
 *   For AMS: read h=, split fields, find in reservoir, hash.
 *   For AS:  go straight for the three "triplet" headers at the index.
 */


void cleanup_and_exit(int sig)
{
   /* In a signal handler, the less we do the better.
   * Since we are shutting down, saving the DB is the priority.
   */
   write(2, "Signal received, exit...\n", sizeof("Signal received, exit...\n") - 1);

   // Now that the DB is safe, exit
   exit(0);
}
