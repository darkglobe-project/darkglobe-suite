/*
 * DarkARCs - ARC (RFC 8617) Signing Milter
 *
 * Adds ARC-Seal, ARC-Message-Signature and ARC-Authentication-Results
 * to outbound / relayed mail, sealing the ARC chain.
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

// Maximum line length (1000 characters)
// Header: RFC 5322 recommends not exceeding 998 characters per line.
/* Shared constants come from dark_common.h.
 * ARCS_* are DarkARCs-specific buffer sizes, deliberately distinct
 * from the suite defaults (ARCS_HEADER_BUF larger: signer builds long
 * ARC signature headers; ARCS_BODY_CHUNK smaller: incremental relaxed
 * body flush, not a whole-body buffer). */
#define ARCS_HEADER_BUF   8192
#define ARCS_BODY_CHUNK   4096

/* DarkARCs-specific configuration */
#define MY_SERVER         "dns.itb.it"
#define DOMAIN            "itb.it"
#define DEBUG1            0
#define MAX_DOMAIN_SIZE   256
#define MAX_HEADER_COUNT  800
#define MAX_CAPACITY      200
#define OCONN             "unix:/var/spool/DarkARCs/sock"
#define SSLPATH           "/etc/DarkARCs/arc1.private"
#define USER              "smmsp"
#define SDUSER            "smmsp"
#define SELETTORE         "arc1"
#define HPARAM            "from:message-id:date:subject:to"
#define LOGLEVEL          LOG_NOTICE
#define NOLOCALSIGN       1

/* Syslog facility */
#define SYSLOG_FACILITY	LOG_DAEMON

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

static sfsistat das_connect(SMFICTX *, char *, _SOCK_ADDR *);
static sfsistat das_helo(SMFICTX *, char *);
static sfsistat das_envfrom(SMFICTX *, char **);
static sfsistat das_envrcpt(SMFICTX *, char **);
static sfsistat das_header(SMFICTX *, char *, char *);
static sfsistat das_eoh(SMFICTX *);
static sfsistat das_body(SMFICTX *, u_char *, size_t);
static sfsistat das_eom(SMFICTX *);
static sfsistat das_abort(SMFICTX *);
static sfsistat das_close(SMFICTX *);

struct auth_data 
{
   char result[24];      // pass, fail, timeout, etc.
   char identifier[128]; // the associated domain
};

struct header_slot 
{
   char name[MAX_HEADER_NAME];
   char value[ARCS_HEADER_BUF];
   int used_for_signature;        // Flag to remember if we already "used" it (useful for duplicates)
   int arc_index;                 // if it's an ARC field, it gives me the index
};

// Private structure for each email session
struct context 
{
   int msg_count;
   struct header_slot *headers; // Pointer to dynamic array
   int header_cnt;              // How many we have saved
   int header_capacity;         // How many the current allocation can hold
   int found_arc;
   int new_arc;
   int h_num_fields;            // number of fields to hash or buffer for sign verification
   int is_start_of_line;
   int is_localhost;
   int skip_elab;
   char cv_status[10];
   char spf_res[24], spf_id[128];
   char first_rcpt[256];
//   struct auth_data spf, dkim, dmarc;
   EVP_MD_CTX *mdctx_header;           // Digest context for the header
   EVP_MD_CTX *mdctx_body_relaxed;     // Digest context for the body (relaxed)
//   EVP_PKEY* pkey;
   char helo[MAXHOST];
   int p_had_space;
   int has_darc_xsigned;   /* set if an X-Signed: DarkARC* is already present */
   int pending_newlines_relaxed;
   int body_has_content_relaxed;
};

const char *pc_oconn = OCONN;
const char *pc_user = USER;
char my_hostname[256] = MY_SERVER;
char signing_domain[256] = DOMAIN;
static EVP_PKEY* global_pkey;


struct smfiDesc arcmilter =
{
   "DarkARCs",
   SMFI_VERSION,             /* Version */
   SMFIF_ADDHDRS|SMFIF_CHGHDRS, /* Flags: needed to add our verification header */
   das_connect,               /* Here you can log the sender server's IP */
   das_helo,                  /* Often null, unless checking the hostname */
   das_envfrom,               /* FUNDAMENTAL: Here you initialize the priv struct and OpenSSL hash */
   das_envrcpt,               /* Here you verify if the recipient is your mailing list */
   das_header,                /* Fills the array with ALL headers */
   das_eoh,                   /* End of headers: here we already know which is the highest index */
   das_body,                  /* The intake: calculates SHA256 hash on 50MB chunks */
   das_eom,                   /* The Brain: performs DNS lookup, RSA verification and decides verdict */
   das_abort,                 /* Emergency cleanup if connection drops */
   das_close                  /* Final memory cleanup (free, etc.) */
};

typedef struct 
{
   char name[64];
   char value[1024];
} saved_header_t;

static void das_usage(const char *);
EVP_PKEY* load_public_key_from_base64(const char *);
int get_arc_index(const char *);
int canonicalize_arc_ms_for_verify(const char *, const char *, char *, size_t);
int verify_arc_chain (struct context *);
void extract_auth_detail(const char *, const char *, const char *, char *, char *);
void cleanup_and_exit(int);
static void feed_header_to_digest(EVP_MD_CTX *, struct context *, int , bool , bool );
void cleanup_session(SMFICTX *ctx, bool final_close);



// Function to clean up white spaces (fundamental for "relaxed")

int get_arc_index(const char *header_value)
{
   if (!header_value) return -1;

   // 1. Search for "i=" ignoring case if possible or handling space
   const char *p = strcasestr(header_value, "i"); 
   if (!p) return -1;

   // 2. Verify it is exactly the "i=" tag (avoid match inside other words)
   // Search for equal sign after 'i' skipping any spaces
   p++; // skip 'i'
   while (*p && isspace((unsigned char)*p)) p++; 
   
   if (*p != '=') return -1; // was not an i= tag
   p++; // skip equal sign

   // 3. Skip any spaces after equal sign (e.g.: i= 2)
   while (*p && isspace((unsigned char)*p)) p++;

   int index = atoi(p);
   
   syslog(LOG_DEBUG, "ARC parsing: found value '%s', converted to index=%d", p, index);
   
   return (index > 0) ? index : -1;
}


int canonicalize_arc_ms_for_verify(const char *name, const char *value,
                                    char *out, size_t out_max)
{
   char buf[8192];
   size_t vlen = strlen(value);
   if (vlen >= sizeof(buf)) return -1;
   memcpy(buf, value, vlen + 1);

   /* First unfold, then search for b= */
   unfold_header(buf);

   char *p = buf;
   while (*p) 
   {
      char *found = strstr(p, "b=");
      if (!found) break;

      // Check to avoid bh=
      if (found > buf && *(found - 1) == 'h') 
      {
         p = found + 2;
         continue;
      }

      char *val_start = found + 2;
      char *val_end = val_start;

      // Find the end of b= value
      while (*val_end && *val_end != ';' && *val_end != '\r' && *val_end != '\n')
         val_end++;

      if (*val_end == ';') 
      {
         // If there is a semicolon, we carry over everything that follows (other tags)
         memmove(val_start, val_end, strlen(val_end) + 1);
      } 
      else 
      {
         // If no ';' (end of string or CRLF), truncate categorically
         *val_start = '\0';
      }
      break;
   }
   return canonicalize_header_relaxed(name, buf, out, out_max, 0);
}

sfsistat das_header(SMFICTX *ctx, char *headerf, char *headerv) 
{
   struct context *ps_context;
   ps_context = (struct context *)smfi_getpriv(ctx);
   int indice_ARC;  

   syslog(LOG_DEBUG, "DAS_HEADER: [%s] -> [%s]", headerf, headerv);
   if (strcasecmp(headerf, "X-DarkARC-Internal-Status") == 0) 
   {
      syslog(LOG_DEBUG, "DAS_HEADER: Found X-ARC-Internal-Status: %s ", headerv);
      // DarkARC processed an incoming message
      char ca_head[MAX_HEADER_VALUE];
      strcpy (ca_head, headerv);
      int evalue=get_arc_index(ca_head);
      ps_context->new_arc=evalue;
      strncpy (ps_context->cv_status, headerv,4);
      ps_context->cv_status[4]='\0';
      syslog(LOG_DEBUG, "DAS_HEADER: Found Internal Status");

   }
   syslog (LOG_DEBUG, "DAS_HEADER: header count/capacity: %d/%d", ps_context->header_cnt,
             ps_context->header_capacity);
   // If current max capacity is reached, expand
   if (ps_context->header_cnt >= ps_context->header_capacity) 
   {
      // 1. DoS Protection: If reservoir is full, stop saving
      // (or error if paranoid, but better to ignore excess)
      if (ps_context->header_capacity >= MAX_HEADER_COUNT) 
      {
         return SMFIS_CONTINUE;
      }
      int new_capacity = ps_context->header_capacity + MAX_CAPACITY;
      struct header_slot *new_ptr = realloc(ps_context->headers, new_capacity * sizeof(struct header_slot));
      if (new_ptr == NULL) 
      {
         // If RAM really runs out: discard header or return temp failure
         return SMFIS_TEMPFAIL;
      }
      ps_context->headers = new_ptr;
      ps_context->header_capacity = new_capacity;
   }

   struct header_slot *slot = &ps_context->headers[ps_context->header_cnt];
   // 2. Copy Name and Value
   strncpy(slot->name, headerf, MAX_HEADER_NAME - 1);
   slot->name[MAX_HEADER_NAME - 1] = '\0'; // Safety

   strncpy(slot->value, headerv, ARCS_HEADER_BUF - 1);
   slot->value[ARCS_HEADER_BUF - 1] = '\0';
   unfold_header(slot->value); // Clean YOUR copy, not Sendmail's

   slot->used_for_signature = 0; // Reset flag

   /* Remember if the message already carries an X-Signed from DarkARC
    * (a previous hop): das_eom will then not add a duplicate. */
   if (strcasecmp(headerf, "X-Signed") == 0 &&
       strcasestr(headerv, "DarkARC") != NULL)
      ps_context->has_darc_xsigned = 1;

   // intercept ARC-Seal/Signature on the fly to save indices
   if (strncasecmp(headerf, "ARC-", 4) == 0)
   {
      indice_ARC=get_arc_index(headerv);
      if ((indice_ARC>ps_context->found_arc))
      {
         ps_context->found_arc=indice_ARC;
      }
      else if (indice_ARC==ps_context->found_arc)
      {
      }
      slot->arc_index=indice_ARC;
   }
   ps_context->header_cnt++;

   if ((ps_context->found_arc == ps_context->new_arc) && (ps_context->new_arc>0))
      ps_context->found_arc--;

   return SMFIS_CONTINUE;
}

sfsistat das_body(SMFICTX *ctx, unsigned char *bodyp, size_t bodylen) 
{
   struct context *ps = (struct context *)smfi_getpriv(ctx);
   if (!ps) return SMFIS_CONTINUE;

   unsigned char r_buf[ARCS_BODY_CHUNK]; // Relaxed temp buffer
   size_t  r_idx = 0;

   // Macro to flush Relaxed buffer
   #define FLUSH_RELAXED { \
        if (r_idx > 0) { \
            EVP_DigestUpdate(ps->mdctx_body_relaxed, r_buf, r_idx); \
            r_idx = 0; \
        } \
    }

   for (size_t i = 0; i < bodylen; i++) 
   {
      unsigned char c = bodyp[i];
      if (c == '\r') continue; // RFC: always ignore CR

      // --- RELAXED ---
      if (c == '\n') 
      {
         ps->p_had_space = 0;
         ps->is_start_of_line = 1;
         ps->pending_newlines_relaxed++;
      } 
      else if (c == ' ' || c == '\t') 
      {
         ps->p_had_space = 1;
      } 
      else 
      {
         // Write pending newlines
         while (ps->pending_newlines_relaxed > 0) 
         {
            if (r_idx >= ARCS_BODY_CHUNK - 2) FLUSH_RELAXED;
            r_buf[r_idx++] = '\r';
            r_buf[r_idx++] = '\n';
            ps->pending_newlines_relaxed--;
         }
         // Space management: compress to single ' '
         if (ps->p_had_space) 
         {
            if (r_idx >= ARCS_BODY_CHUNK) FLUSH_RELAXED;
            r_buf[r_idx++] = ' ';
            ps->p_had_space = 0;
         }
         // Write character
         if (r_idx >= ARCS_BODY_CHUNK) FLUSH_RELAXED;
         r_buf[r_idx++] = c;
         ps->is_start_of_line = 0;
      }
   }

   // Flush residuals at chunk end
   FLUSH_RELAXED;

   return SMFIS_CONTINUE;
}

// From String b= to Binary
// Signature in AMS header is Base64. We must bring it to a byte array.
// At message end
/* ---- HEADER FOLDING (emission only) ----
 *
 * Folds a header value at "; " separators, never inside base64.
 *
 * Under relaxed canonicalisation a fold (CRLF + WSP) unfolds to a single
 * space, so turning "; " into ";\n " produces a canonical form byte-identical
 * to the unfolded one. Nothing already hashed is affected: the ARC-Seal covers
 * the ARC-Message-Signature with its b= intact, and folding only at separators
 * leaves that value untouched.
 *
 * Folding inside b= or bh= would NOT be safe here: those runs contain no
 * whitespace, so the unfolded form would gain a space that was absent when the
 * signature was computed, and a downstream verifier would hash different bytes.
 * That is precisely the trap this function avoids — at the cost of one long
 * final line carrying b= (~350 chars with RSA-2048, ~690 with RSA-4096, both
 * well inside the 998-char limit of RFC 5322 section 2.1.1).
 *
 * first_line_offset accounts for the "Name: " prefix that the MTA prepends.
 */
#define FOLD_WIDTH 78

static void fold_header_value(char *dst, size_t dstsize, const char *src,
                              size_t first_line_offset)
{
   size_t out = 0, line = first_line_offset;

   if (dstsize == 0) return;
   dst[0] = '\0';

   while (*src != '\0' && out + 1 < dstsize)
   {
      /* Length of the next token, up to (not including) the next "; " */
      const char *sep = strstr(src, "; ");
      size_t tok = sep ? (size_t)(sep - src) + 1   /* keep the ';' */
                       : strlen(src);

      /* Break before this token if the line would overflow — but never on the
       * very first token, which would produce an empty leading line. */
      if (out > 0 && line + tok > FOLD_WIDTH)
      {
         if (out + 2 >= dstsize) break;
         dst[out++] = '\n';
         dst[out++] = ' ';
         line = 1;                      /* the folding space */
      }
      else if (out > 0)
      {
         if (out + 1 >= dstsize) break;
         dst[out++] = ' ';
         line += 1;
      }

      if (out + tok >= dstsize) tok = dstsize - out - 1;
      memcpy(dst + out, src, tok);
      out  += tok;
      line += tok;

      src += tok;
      while (*src == ' ') src++;        /* skip the separator's space(s) */
   }

   dst[out] = '\0';
}

sfsistat das_eom(SMFICTX *ctx) 
{
   struct context *ps_context;
   ps_context = (struct context *)smfi_getpriv(ctx);

   syslog (LOG_DEBUG, "DAS_EOM: found_arc=%d / new_arc=%d / localhost=%d", ps_context->found_arc,
               ps_context->new_arc, ps_context->is_localhost);

   ERR_clear_error();
   if ((ps_context->is_localhost==1) ||
       (ps_context->new_arc> 0))
   {
      syslog (LOG_DEBUG, "DAS_EOM: mail comung form localhost");
      if (ps_context->new_arc> 0)
        smfi_chgheader(ctx, "X-DarkARC-Internal-Status", 1, NULL);

      {
         syslog(LOG_DEBUG, "DAS_EOM - pkey ptr: %p", (void *)global_pkey);
         syslog(LOG_DEBUG, "DAS_EOM - ctx ptr: %p", (void *)ps_context->mdctx_header);
      }
      // Convenience pointers to avoid duplicating finalization code
      EVP_MD_CTX *target_ctx;
      target_ctx = ps_context->mdctx_body_relaxed;

      // body relaxed
      EVP_DigestUpdate(target_ctx, "\r\n", 2);

      unsigned char calcolato_bin[EVP_MAX_MD_SIZE];
      unsigned int calcolato_len = 0;

      if (EVP_DigestFinal_ex(target_ctx, calcolato_bin, &calcolato_len) != 1)
      {
         syslog(LOG_ERR, "DAS_EOM: Fatal OpenSSL error in EVP_DigestFinal");
         return SMFIS_TEMPFAIL;
      }

      char bh_bodyhash[256];
      char *b64_hash = encode_base64_hash (calcolato_bin, calcolato_len);
      strcpy (bh_bodyhash, b64_hash);
      free (b64_hash);
      syslog (LOG_ERR, "DAS_EOM: body hash: %s", bh_bodyhash);

      char aar_header_top[ARCS_HEADER_BUF];  // ARC-Authentication-Results
      char aar_header_top_inj[ARCS_HEADER_BUF];  // ARC-Authentication-Results
      char ams_header_top[ARCS_HEADER_BUF];  // ARC-Message-Signature
      char ams_header_top_inj[ARCS_HEADER_BUF];  // ARC-Message-Signature
      memset (aar_header_top, '\0', sizeof(aar_header_top));
      memset (aar_header_top_inj, '\0', sizeof(aar_header_top_inj));
      memset (ams_header_top, '\0', sizeof(ams_header_top));
      memset (ams_header_top_inj, '\0', sizeof(ams_header_top_inj));

      if (ps_context->new_arc>0)
      {
         // was marked at entrance
         syslog (LOG_DEBUG, "DAS_EOM: mail marked at entrance=>mailing list");
         for (int j = ps_context->header_cnt - 1; j >= 0; j--)
         {
            if ((strcasecmp(ps_context->headers[j].name, "ARC-Authentication-Results")==0) && 
                (ps_context->headers[j].arc_index==ps_context->new_arc))
            {
               canonicalize_header_relaxed(ps_context->headers[j].name,
                                             ps_context->headers[j].value,
                                             aar_header_top, sizeof(aar_header_top), 1);
               break;
            }
         }
      }
      else if ((ps_context->new_arc==0) && (ps_context->is_localhost==1) 
                 && (ps_context->found_arc>0))
      {
         syslog (LOG_DEBUG, "DAS_EOM: local mail with arc records=>local mailing list");
         #define SAFE_ID(s)  ((s) && (s)[0] != '\0' ? (s) : "unknown")
         #define SAFE_STR(s) ((s) && (s)[0] != '\0' ? (s) : "none")
         // const char *arc_verdict="pass";
         ps_context->new_arc=ps_context->found_arc + 1;
         memset (aar_header_top, '\0', sizeof(aar_header_top));
         snprintf(aar_header_top, sizeof(aar_header_top),
           "arc-authentication-results:i=%d; %s; arc=pass (i=%d)\r\n",
            ps_context->found_arc + 1, my_hostname, ps_context->found_arc + 1);
         strcpy(ps_context->cv_status, "pass");
         memset (aar_header_top_inj, '\0', sizeof(aar_header_top_inj));
         snprintf(aar_header_top_inj, sizeof(aar_header_top_inj),
           "i=%d; %s; arc=pass (i=%d)",
             ps_context->found_arc + 1,my_hostname, ps_context->found_arc + 1);
         smfi_addheader(ctx, "ARC-Authentication-Results", aar_header_top_inj);
      }
      else
      {
         syslog (LOG_DEBUG, "DAS_EOM: we're signing a delivering local mail");
         char ca_domain[MAX_DOMAIN_SIZE]=MY_SERVER;
         memset (aar_header_top, '\0', sizeof(aar_header_top));
         snprintf (aar_header_top, sizeof(aar_header_top), 
              "arc-authentication-results:i=1; %s; spf=none; dmarc=none; dkim=none; arc=none\r\n",
               ca_domain);
         memset (aar_header_top_inj, '\0', sizeof(aar_header_top_inj));
         snprintf (aar_header_top_inj, sizeof(aar_header_top_inj), 
              "i=1; %s; spf=none; dmarc=none; dkim=none; arc=none", ca_domain);
         smfi_addheader(ctx, "ARC-Authentication-Results", aar_header_top_inj);
      }
      syslog(LOG_DEBUG, "DAS_EOM - 1 - DEBUG AAR: [%s]", aar_header_top);

      if (ps_context->new_arc>0)
      {
         // 1. Build AMS header (i=1 for the first seal)
         memset (ams_header_top, '\0', sizeof(ams_header_top));
         memset (ams_header_top_inj, '\0', sizeof(ams_header_top_inj));

         snprintf(ams_header_top, sizeof(ams_header_top),
            "arc-message-signature:i=%d; a=rsa-sha256; c=relaxed/relaxed; d=%s; s=%s;"
            " bh=%s;"
            " h=%s;"
            " b=",
            ps_context->new_arc,
            signing_domain, SELETTORE, 
            bh_bodyhash, HPARAM);
         snprintf(ams_header_top_inj, sizeof(ams_header_top_inj),
            "i=%d; a=rsa-sha256; c=relaxed/relaxed; d=%s; s=%s; bh=%s; h=%s; b=",
                 ps_context->new_arc, signing_domain, SELETTORE, bh_bodyhash, HPARAM);
      }
      else
      {
         memset (ams_header_top, '\0', sizeof(ams_header_top));
         snprintf(ams_header_top, sizeof(ams_header_top),
            "arc-message-signature:i=%d; a=rsa-sha256; c=relaxed/relaxed; d=%s; s=%s;"
            " bh=%s;"
            " h=%s;"
            " b=", 1,
            signing_domain, SELETTORE,
            bh_bodyhash, HPARAM);
         memset (ams_header_top_inj, '\0', sizeof(ams_header_top_inj));
         snprintf(ams_header_top_inj, sizeof(ams_header_top_inj),
            "i=%d; a=rsa-sha256; c=relaxed/relaxed; d=%s; s=%s; bh=%s; h=%s; b=", 1,
            signing_domain, SELETTORE, 
            bh_bodyhash, HPARAM);
      }
      syslog(LOG_DEBUG, "DAS_EOM: 2 - DEBUG AMS: [%s]", ams_header_top);

      // 2. Pass this string to signature context
      // Note: header must be passed canonicalized (relaxed: lowercase name, trim spaces)
      if ((EVP_DigestSignUpdate(ps_context->mdctx_header, ams_header_top, strlen(ams_header_top)) ) != 1)
      {
         unsigned long err = ERR_get_error();
         char err_buf[256];
         ERR_error_string_n(err, err_buf, sizeof(err_buf));
         syslog(LOG_ERR, "DAS_EOM: OpenSSL Error: %s", err_buf);
         syslog(LOG_ERR, "DAS_EOM: EVP_DigestSignUpdate AMS failure");
         return SMFIS_TEMPFAIL;
      }

      // 3. Generate final signature (b=)
      size_t sig_len = 0;
      if (EVP_DigestSignFinal(ps_context->mdctx_header, NULL, &sig_len) != 1 || sig_len == 0)
      {
         syslog(LOG_ERR, "DAS_EOM: EVP_DigestSignFinal (AMS length probe) failed");
         return SMFIS_TEMPFAIL;
      }
      unsigned char *sig_value = malloc(sig_len);
      if (!sig_value)
      {
         syslog(LOG_ERR, "DAS_EOM: malloc(sig_len) AMS failed");
         return SMFIS_TEMPFAIL;
      }
      if (EVP_DigestSignFinal(ps_context->mdctx_header, sig_value, &sig_len) != 1)
      {
         syslog(LOG_ERR, "DAS_EOM: EVP_DigestSignFinal (AMS) failed");
         free(sig_value);
         return SMFIS_TEMPFAIL;
      }

      // 4. Encode sig_value in Base64 for final b=
      char *b64_signature = encode_base64_hash(sig_value, sig_len);
      if (!b64_signature)
      {
         syslog(LOG_ERR, "DAS_EOM: encode_base64_hash (AMS) failed");
         free(sig_value);
         return SMFIS_TEMPFAIL;
      }

      /* DAs-2: securecat takes the TOTAL buffer size and computes the
       * remaining space internally, fixing the prior strncat on
       * ams_header_top that passed sizeof(buf)-1 — ignoring existing
       * content — and could overflow. */
      securecat(ams_header_top_inj, b64_signature, sizeof(ams_header_top_inj));
      securecat(ams_header_top, b64_signature, sizeof(ams_header_top));

      syslog(LOG_DEBUG, "DAS_EOM: DEBUG AMS WITH b=: [%s]", ams_header_top);

      /* Fold at separators only — canonicalisation-invariant, see
       * fold_header_value(). The hashed form (ams_header_top) is untouched. */
      char ams_folded[ARCS_HEADER_BUF];
      fold_header_value(ams_folded, sizeof(ams_folded), ams_header_top_inj,
                        sizeof("ARC-Message-Signature: ") - 1);
      smfi_addheader(ctx, "ARC-Message-Signature", ams_folded);
      free(sig_value);
      free (b64_signature);

      EVP_MD_CTX_reset(ps_context->mdctx_header);
      EVP_MD_CTX  *as_sctx=ps_context->mdctx_header;

      sig_len=0;
      if (EVP_DigestSignInit(as_sctx, NULL, EVP_sha256(), NULL, global_pkey) <= 0) 
      {
         unsigned long err = ERR_get_error();
         char err_buf[256];
         ERR_error_string_n(err, err_buf, sizeof(err_buf));
         syslog(LOG_ERR, "DAS_EOM: EVP_DigestSignInit fallito: %s", err_buf);
         return SMFIS_TEMPFAIL;

      }
      // 2. Feed with previous ARC headers (if any, i < N)

      int N = ps_context->found_arc;
      if (ps_context->found_arc>0)
         for (int lvl = 1; lvl <= N; lvl++) 
         {
            // AAR level lvl
            for (int j = 0; j < ps_context->header_cnt; j++) 
            {
               if (strcasecmp(ps_context->headers[j].name, "ARC-Authentication-Results") == 0 &&
                   ps_context->headers[j].arc_index == lvl) 
               {
                  feed_header_to_digest(as_sctx, ps_context, j, 1, false);
                  break;
               }
            }
            // AMS level lvl
            for (int j = 0; j < ps_context->header_cnt; j++) 
            {
               if (strcasecmp(ps_context->headers[j].name, "ARC-Message-Signature") == 0 &&
                   ps_context->headers[j].arc_index == lvl) 
               {
                  feed_header_to_digest(as_sctx, ps_context, j, 1, false);
                  break;
               }
            }
            // AS level lvl
            for (int j = 0; j < ps_context->header_cnt; j++) 
            {
               if (strcasecmp(ps_context->headers[j].name, "ARC-Seal") == 0 &&
                   ps_context->headers[j].arc_index == lvl) 
               {
                  feed_header_to_digest(as_sctx, ps_context, j, 1, false);
                  break;
               }
            }
         }

      char as_header_top[ARCS_HEADER_BUF];
      char as_header_top_inj[ARCS_HEADER_BUF]; 
      memset (as_header_top, '\0', sizeof(as_header_top));
      memset (as_header_top_inj, '\0', sizeof(as_header_top_inj));
      syslog(LOG_DEBUG, "DAS_EOM: DEBUG AAR for AS [%s]", aar_header_top);

      if (EVP_DigestSignUpdate(as_sctx, aar_header_top, strlen(aar_header_top)) != 1)
      {
         syslog(LOG_ERR, "DAS_EOM: EVP_DigestSignInit AAR->AAS failure");
         return SMFIS_TEMPFAIL;
      }

      syslog(LOG_DEBUG, "DAS_EOM: DEBUG AMS for AS [%s]", ams_header_top);
      if (EVP_DigestSignUpdate(as_sctx, ams_header_top, strlen(ams_header_top)) != 1)
      {
         syslog(LOG_ERR, "DAS_EOM: EVP_DigestSignInit AMS->AS failure");
         return SMFIS_TEMPFAIL;
      }
      syslog(LOG_DEBUG, "DAS_EOM: DEBUG AMS for AS [%s]",  "\r\n");
      if ((EVP_DigestSignUpdate(as_sctx, "\r\n", 2)) != 1)
      {
         syslog(LOG_ERR, "DAS_EOM: EVP_DigestSignInit AMS->AAS failure");
         return SMFIS_TEMPFAIL;
      }

      if (ps_context->new_arc==0)
      {
         memset (as_header_top, '\0', sizeof(as_header_top));
         snprintf(as_header_top, sizeof(as_header_top),
              "arc-seal:i=%d; a=rsa-sha256; s=%s; d=%s; cv=%s; b=", 1,
                 SELETTORE, signing_domain, "none");
         memset (as_header_top_inj, '\0', sizeof(as_header_top_inj));
         snprintf(as_header_top_inj, sizeof(as_header_top),
              "i=%d; a=rsa-sha256; s=%s; d=%s; cv=%s; b=", 1,
                 SELETTORE, signing_domain, "none");
      }
      else
      {
         memset (as_header_top, '\0', sizeof(as_header_top)-1);
         snprintf(as_header_top, sizeof(as_header_top),
              "arc-seal:i=%d; a=rsa-sha256; s=%s; d=%s; cv=%s; b=", 
                 ps_context->new_arc,
                 SELETTORE, signing_domain, ps_context->cv_status);
         memset (as_header_top_inj, '\0', sizeof(as_header_top_inj));
         snprintf(as_header_top_inj, sizeof(as_header_top),
              "i=%d; a=rsa-sha256; s=%s; d=%s; cv=%s; b=", ps_context->new_arc,
                 SELETTORE, signing_domain, ps_context->cv_status);
      }

      syslog(LOG_DEBUG, "DAS_EOM: DEBUG AS per AS [%s]", as_header_top);

      if (EVP_DigestSignUpdate(as_sctx, as_header_top, strlen(as_header_top)) != 1)
      {
         syslog(LOG_ERR, "DAS_EOM: EVP_DigestSignInit AAR->AAS failure");
         return SMFIS_TEMPFAIL;
      }

      sig_len = 0;
      if (EVP_DigestSignFinal(as_sctx, NULL, &sig_len) != 1 || sig_len == 0)
      {
         syslog(LOG_ERR, "DAS_EOM: EVP_DigestSignFinal (AS length probe) failed");
         return SMFIS_TEMPFAIL;
      }
      unsigned char *sig = malloc(sig_len);
      if (!sig)
      {
         syslog(LOG_ERR, "DAS_EOM: malloc(sig_len) AS failed");
         return SMFIS_TEMPFAIL;
      }
      if (EVP_DigestSignFinal(as_sctx, sig, &sig_len) != 1)
      {
         syslog(LOG_ERR, "DAS_EOM: EVP_DigestSignFinal (AS) failed");
         free(sig);
         return SMFIS_TEMPFAIL;
      }

      char *b64_signature2 = encode_base64_hash(sig, sig_len);
      if (!b64_signature2)
      {
         syslog(LOG_ERR, "DAS_EOM: encode_base64_hash (AS) failed");
         free(sig);
         return SMFIS_TEMPFAIL;
      }
      securecat(as_header_top_inj, b64_signature2, sizeof(as_header_top_inj));   // for AS

      free(sig);
      free (b64_signature2);
      char as_folded[ARCS_HEADER_BUF];
      fold_header_value(as_folded, sizeof(as_folded), as_header_top_inj,
                        sizeof("ARC-Seal: ") - 1);
      smfi_addheader(ctx, "ARC-Seal", as_folded);
      if (!ps_context->has_darc_xsigned)
         smfi_addheader(ctx, "X-Signed", "DarkARC v1.2");
   }
   return SMFIS_CONTINUE;
}

static void feed_header_to_digest(EVP_MD_CTX *ctx, struct context *ps_context,
                                   int idx, bool relaxed, bool strip_b)
{
   char buf[ARCS_HEADER_BUF + 256];
   if (relaxed)
      canonicalize_header_relaxed(ps_context->headers[idx].name,
                                  ps_context->headers[idx].value,
                                  buf, sizeof(buf),1);
   else
   {
      snprintf(buf, sizeof(buf)-1, "%s: %s\r\n",
               ps_context->headers[idx].name,
               ps_context->headers[idx].value);
   }
   if (strip_b)
      prepare_header_for_hash(buf);

   syslog(LOG_DEBUG, "FEED_AS[%d]: [%s]", idx, buf);
   EVP_DigestSignUpdate(ctx, buf, strlen(buf));
}

// Support function to find real section delimiter (outside parentheses)
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
   // Search for method start (e.g. "dkim=")
   const char *start = strcasestr(val, method);
   if (!start) return;

   start += strlen(method);
   while (*start == ' ' || *start == '=' || *start == '\t') start++;

   // 1. Extract result (pass, fail, etc.)
   // Stop at space, semicolon or comment start
   int i = 0;
   while (start[i] && !isspace((unsigned char)start[i]) && start[i] != ';' && start[i] != '(' && i < 23) 
   {
      out_res[i] = start[i];
      i++;
   }
   out_res[i] = '\0';

   // 2. Search for identifier (header.d=, etc.)
   const char *section_end = find_real_section_end(start);
   const char *id_ptr = strcasestr(start, id_tag);

   if (id_ptr && (!section_end || id_ptr < section_end)) 
   {
      id_ptr += strlen(id_tag);
      while (*id_ptr == ' ' || *id_ptr == '=' || *id_ptr == '\t') id_ptr++;

      int j = 0;
      // Extract ID value
      while (id_ptr[j] && !isspace((unsigned char)id_ptr[j]) && id_ptr[j] != ';' && id_ptr[j] != '(' && j < 127) 
      {
         out_id[j] = id_ptr[j];
         j++;
      }
      out_id[j] = '\0';
   }
}

// At message start (mlfi_header or mlfi_envfrom)
sfsistat das_begin(SMFICTX *ctx) 
{
   return SMFIS_CONTINUE;
}

sfsistat das_envfrom(SMFICTX *ctx, char **argv) 
{
   // 1. Retrieve private structure
   struct context *priv = (struct context *)smfi_getpriv(ctx);

   syslog(LOG_DEBUG, "DAS_ENVFROM: start");

   priv->msg_count++;
   memset (priv->spf_id, '\0', sizeof (priv->spf_id));
   if (argv[0] != NULL) 
   {
      char *p = strchr(argv[0], '@');
      if (p) 
      {
         strncpy(priv->spf_id, p + 1, sizeof(priv->spf_id) - 1);
         // Clean final '>'
         char *end = strchr(priv->spf_id, '>');
         if (end) *end = '\0';
      } 
      else 
      {
         strncpy(priv->spf_id, argv[0], sizeof(priv->spf_id) - 1);
      }
   }

   syslog(LOG_DEBUG, "DAS_ENVFROM: spf_id: [%s]", priv->spf_id);
   ERR_clear_error(); 
   if (priv->msg_count == 1)
   {
      syslog(LOG_DEBUG, "DAS_ENVFROM: msg_count %d", (priv->msg_count));
      priv->header_capacity = MAX_CAPACITY;
      EVP_MD_CTX_reset(priv->mdctx_header);        
      EVP_MD_CTX_reset(priv->mdctx_body_relaxed);  
      priv->h_num_fields = 0;            
      priv->pending_newlines_relaxed=0;
      priv->body_has_content_relaxed=0;
      priv->is_start_of_line=1;
      priv->header_cnt = 0;
      priv->skip_elab = 0;
      priv->p_had_space=0;
   }
   else
   {
      syslog(LOG_DEBUG, "DAS_ENVFROM: other messages in the same connection");
      syslog(LOG_DEBUG, "DAS_ENVFROM: msg_count %d", (priv->msg_count));
      // 3. Connection reused (RSET). Reset data without deallocating everything.
      syslog(LOG_DEBUG, "DAS_ENVFROM: initializations");
      priv->cv_status[0]='\0';
      priv->first_rcpt[0]='\0';
      priv->header_cnt = 0;
      priv->skip_elab = 0;
      priv->found_arc = 0;
      priv->new_arc = 0;
      priv->has_darc_xsigned = 0;
      priv->h_num_fields = 0;            
      priv->pending_newlines_relaxed=0;
      priv->body_has_content_relaxed=0;
      priv->is_start_of_line=1;
      priv->p_had_space=0;
      syslog(LOG_DEBUG, "DAS_ENVFROM: initializations finished");
      EVP_MD_CTX_reset(priv->mdctx_body_relaxed);
      EVP_MD_CTX_reset(priv->mdctx_header);

      syslog(LOG_DEBUG, "DAS_ENVFROM: cycle i<%d",  priv->header_capacity);

      if (priv->headers != NULL) {
         memset(priv->headers, 0, priv->header_capacity * sizeof(struct header_slot));
      }
   }

   if (EVP_DigestInit_ex(priv->mdctx_body_relaxed, EVP_sha256(), NULL) != 1) 
   {
      return SMFIS_TEMPFAIL;
   }

   {
      syslog(LOG_DEBUG, "DAS_ENVFROM: pkey ptr: %p", (void *)global_pkey); 
      syslog(LOG_DEBUG, "DAS_ENVFROM: ctx ptr: %p", (void *)priv->mdctx_header);
   }
   if (EVP_DigestSignInit(priv->mdctx_header, NULL, EVP_sha256(), NULL, global_pkey) != 1)
   {
      unsigned long err = ERR_get_error();
      char err_buf[256];
      ERR_error_string_n(err, err_buf, sizeof(err_buf));
      syslog(LOG_ERR, "DAS_ENVFROM: EVP_DigestSignInit fallito: %s", err_buf);

      return SMFIS_TEMPFAIL;
   }

   {
      syslog(LOG_DEBUG, "DAS_ENVFROM: pkey ptr: %p", (void *)global_pkey); 
      syslog(LOG_DEBUG, "DAS_ENVFROM: ctx ptr: %p", (void *)priv->mdctx_header);
   }

   return SMFIS_CONTINUE;
}

int main(int argc, char *argv[]) 
{
   tzset();
   int i_get=0, i_ret=0;
   const char *pc_ofile = NULL;
   bool b_fail=0;
   int loglevel = LOGLEVEL;
   int foreground = 0;
   int log_stderr = 0;
   mode_t sock_umask = 0177;

   while ((i_get = getopt(argc, argv, "p:u:l:m:S:d:fLh")) != -1) 
   {
      switch (i_get) 
      {
         case 'p':
            pc_oconn = optarg;
            break;
         case 'u':
            pc_user = optarg;
            break;
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
         case 'm':
            sock_umask = (mode_t)strtol(optarg, NULL, 8);
            break;
         case 'S':
            snprintf(my_hostname, sizeof(my_hostname), "%s", optarg);
            break;
         case 'd':
            snprintf(signing_domain, sizeof(signing_domain), "%s", optarg);
            break;
         case 'f':
            foreground = 1;
            break;
         case 'L':
            log_stderr = 1;
            break;
         default:
            das_usage(argv[0]);
      }
   }

   {
      int log_flags = LOG_PID | LOG_NDELAY;
      if (log_stderr) log_flags |= LOG_PERROR;
      openlog("DarkARCs", log_flags, SYSLOG_FACILITY);
   }
   setlogmask(LOG_UPTO(loglevel));

   if (!strncmp(pc_oconn, "unix:", 5))
      pc_ofile = pc_oconn + 5;
   else if (!strncmp(pc_oconn, "local:", 6)) 
      pc_ofile = pc_oconn + 6;
   
   global_pkey=load_private_key(SSLPATH);
   if (global_pkey)
   {
      syslog(LOG_INFO, "main DarkARCs: Key loaded. Type: %d, Bits: %d",
          EVP_PKEY_id(global_pkey), EVP_PKEY_bits(global_pkey));
   }
   else
      return (1);

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
      if (seteuid(pw->pw_uid) || setuid(pw->pw_uid)) 
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
   if (!b_fail && !foreground && daemon(0, 0)) 
   {
      fprintf(stderr, "daemon: %s\n", strerror(errno));
      goto done;
   }
   umask(sock_umask);
   signal(SIGPIPE, SIG_IGN);
   signal(SIGTERM, cleanup_and_exit);
   signal(SIGINT,  cleanup_and_exit);

   i_ret = smfi_main();

   if (i_ret != MI_SUCCESS)
      syslog(LOG_ERR, "[ERROR] DarkARCs terminated due to a fatal error");
done:
   return (i_ret);
}


void cleanup_session(SMFICTX *ctx, bool final_close) {
    struct context *priv = (struct context *)smfi_getpriv(ctx);
    if (priv == NULL) return;

    if (final_close) {
        if (priv->headers) {
            free(priv->headers);
            priv->headers = NULL; 
        }

        if (priv->mdctx_body_relaxed) {
            EVP_MD_CTX_free(priv->mdctx_body_relaxed);
            priv->mdctx_body_relaxed = NULL;
        }
        if (priv->mdctx_header) {
            EVP_MD_CTX_free(priv->mdctx_header);
            priv->mdctx_header = NULL;
        }

        smfi_setpriv(ctx, NULL);
        free(priv);
    } else {
        // === DAS_ABORT: TRANSACTION CANCELLED (es. RSET) ===
        // La connessione resta aperta. Manteniamo i buffer in vita!
        
        // Reset only OpenSSL's crypto state to avoid
        // polluting the digest of the next message.
        if (priv->mdctx_body_relaxed) {
            EVP_MD_CTX_reset(priv->mdctx_body_relaxed);
        }
        if (priv->mdctx_header) {
            EVP_MD_CTX_reset(priv->mdctx_header);
        }
        
        // Do not free() the headers.
        // for cycle in envfrom (path msg_count > 1) 
        // will logically reset them.
    }
}


sfsistat das_abort(SMFICTX *ctx) {
        cleanup_session(ctx, false); // Clean up the message but keep 'priv' alive
    syslog(LOG_ERR, "DAS_ABORT: Cleanup: completed");
    return SMFIS_CONTINUE;
}

sfsistat das_close(SMFICTX *ctx) {
        cleanup_session(ctx, true); // Ultima pulizia messaggio
    syslog(LOG_ERR, "DAS_CLOSE: Cleanup: completed");
      
    return SMFIS_CONTINUE;
}


sfsistat das_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr)
{
   struct context *ps_context = calloc(1, sizeof(struct context));
   if (ps_context == NULL) return SMFIS_TEMPFAIL;

   ps_context->msg_count=0;
   ps_context->mdctx_header = EVP_MD_CTX_new();
   ps_context->mdctx_body_relaxed = EVP_MD_CTX_new();

   ps_context->is_localhost = 0; 
   smfi_setpriv(ctx, ps_context); 

   ps_context->header_capacity=MAX_CAPACITY;
   ps_context->header_cnt=0;
   ps_context->new_arc=0;
   ps_context->msg_count=0;
   ps_context->headers = calloc(ps_context->header_capacity, sizeof(struct header_slot));

   if (hostaddr != NULL) 
   {
      if (hostaddr->sa_family == AF_INET) 
      {
         struct sockaddr_in *sa = (struct sockaddr_in *)hostaddr;
         char ip[INET_ADDRSTRLEN];
         inet_ntop(AF_INET, &(sa->sin_addr), ip, INET_ADDRSTRLEN);
         if (strcmp(ip, "127.0.0.1") == 0) 
         {
            ps_context->is_localhost = 1;
            syslog(LOG_DEBUG, "DAS_CONNECT: Localhost connection (Outbound/Seal phase)");
         }
      }
      else if (hostaddr->sa_family == AF_INET6) 
      {
         struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)hostaddr;
         char ip[INET6_ADDRSTRLEN];
         inet_ntop(AF_INET6, &(sa6->sin6_addr), ip, INET6_ADDRSTRLEN);
         if (strcmp(ip, "::1") == 0) 
         {
            ps_context->is_localhost = 1;
         }
      }
   }
   return SMFIS_CONTINUE;
}

static sfsistat das_helo(SMFICTX *ctx, char *pc_helohost)
{
   struct context *ps_context;
   syslog(LOG_DEBUG, "DAS_HELO: start");

   if ((ps_context = (struct context *)smfi_getpriv(ctx)) == NULL)
   {
      syslog(LOG_ERR, "DAS_HELO: smfi_getpriv error");
      return (SMFIS_ACCEPT);
   }
   securecpy(ps_context->helo, pc_helohost, sizeof(ps_context->helo));

   syslog(LOG_DEBUG, "DAS_HELO: end %s", ps_context->helo);
   // ps_context->pkey=global_pkey;

   // ps_context->pkey=load_private_key(SSLPATH);
/* 
  if (ps_context->pkey) 
   {
      syslog(LOG_INFO, "DAS_HELO: Key loaded. Type: %d, Bits: %d", 
          EVP_PKEY_id(ps_context->pkey), EVP_PKEY_bits(ps_context->pkey));
   }
   else
    return (SMFIS_TEMPFAIL);
  */

   return (SMFIS_CONTINUE);
}


sfsistat das_envrcpt(SMFICTX *ctx, char **argv) {
    // Try to read the mailer assigned to this recipient
    const char *mailer = smfi_getsymval(ctx, "{rcpt_mailer}");
   if (DEBUG1)
   {
      static const char *dbg_macros[] =
      {
         "{rcpt_addr}", "{rcpt_host}", "{rcpt_mailer}",
         "{mail_addr}", "{mail_host}", "{mail_mailer}",
         "i", "j", "{client_addr}", "{daemon_name}", NULL
      };
      for (int dbg_i = 0; dbg_macros[dbg_i]; dbg_i++)
      {
         const char *dbg_v = smfi_getsymval(ctx, (char *)dbg_macros[dbg_i]);
         syslog(LOG_INFO, "DAS_MACRO[ENVRCPT] argv0='%s' %s = %s",
              (argv && argv[0]) ? argv[0] : "NULL",
              dbg_macros[dbg_i], dbg_v ? dbg_v : "(NULL)");
      }
   }


   if (NOLOCALSIGN)
   {
      struct context *ps_context = (struct context *)smfi_getpriv(ctx);

      if (mailer != NULL)
      {
          // Log the value to see what Sendmail returns in this setup
          // Typically: "local", "cyrus", "dovecot", "uucp", or "smtp"
          syslog(LOG_DEBUG, "DAS_ENVRCPT: rcpt_mailer per %s è %s", argv[0], mailer);

          // A non-smtp mailer normally means local delivery. But a *local*
          // mailer only means "delivered on this host" when the message also
          // originated here (is_localhost==1). When the message arrived from
          // outside (is_localhost==0) and the recipient resolves to a local
          // mailer, it is an alias that will be expanded and re-sent to an
          // external address — Sendmail has not expanded the alias yet at
          // ENVRCPT time. In that case we must NOT skip: the message is
          // leaving this host and must be ARC-sealed.
          if (strcmp(mailer, "smtp") != 0 && strcmp(mailer, "esmtp") != 0)
          {
              if (ps_context != NULL && ps_context->is_localhost == 0)
              {
                  syslog(LOG_DEBUG,
                     "DAS_ENVRCPT: local mailer but external origin — "
                     "alias forward, will sign");
                  return SMFIS_CONTINUE;
              }
              return SMFIS_ACCEPT; // Skip signing, it is our own local mail
          }
      }
   }
    return SMFIS_CONTINUE;
}


static sfsistat das_eoh(SMFICTX *ctx)
{
   char h_work_copy[ARCS_HEADER_BUF+1];
   struct context *ps_context;
   char *h_fields[MAX_CAPACITY]; 
   int h_count = 0;
   
   if ((ps_context = (struct context *)smfi_getpriv(ctx)) == NULL) 
   {
      syslog(LOG_ERR, "DAS_EOH: smfi_getpriv failed");
      return SMFIS_ACCEPT; 
   }

   strncpy(h_work_copy, HPARAM, ARCS_HEADER_BUF);
   h_work_copy[ARCS_HEADER_BUF] = '\0';

   char *token = NULL; 
   char *saveptr = NULL;
   h_work_copy[ARCS_HEADER_BUF] = '\0';
   
   token = strtok_r(h_work_copy, ":", &saveptr);
   while (token != NULL && h_count < 128) 
   {
      while (*token == ' ' || *token == '\t' || *token == '\r' || *token == '\n') 
      {
         token++;
      }

      char *end = token + strlen(token) - 1;
      while (end > token && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')) 
      {
         *end = '\0';
         end--;
      }

      if (*token != '\0') 
      {
         h_fields[h_count++] = token;
      }
      token = strtok_r(NULL, ":", &saveptr);
   }

   ps_context->h_num_fields=h_count;

   syslog(LOG_DEBUG, "DAS_EOH: h_count=%d, header_cnt=%d", h_count, ps_context->header_cnt);

   for (int i = 0; i < h_count; i++) 
   {
      char *target_name = h_fields[i];

      for (int j = ps_context->header_cnt - 1; j >= 0; j--) 
      {
         if (strcasecmp(ps_context->headers[j].name, target_name) == 0 && 
             ps_context->headers[j].used_for_signature == 0) 
         {
            char canon_buf[ARCS_HEADER_BUF + MAX_HEADER_NAME + 64];
            memset (canon_buf, 0, sizeof (canon_buf));

            canonicalize_header_relaxed(ps_context->headers[j].name, 
                                      ps_context->headers[j].value, 
                                      canon_buf, sizeof(canon_buf),1);
            syslog(LOG_ERR, "DAS_EOH: [%s]", canon_buf);
            if (EVP_DigestSignUpdate(ps_context->mdctx_header, canon_buf, strlen(canon_buf)) != 1)
            {
               syslog(LOG_ERR, "DAS_EOH: EVP_DigestSignUpdate failed");
            } 
            else
               ps_context->headers[j].used_for_signature = 1;
            break; 
         }
      }
   }
   return SMFIS_CONTINUE;
}

void das_usage(const char * usage)
{
   fprintf(stderr, "usage: %s [-u user] [-p socket] [-S hostname] [-d domain] [-l level] [-m umask] [-f] [-L]\n"
                   "  -u user      Run as user (default: smmsp)\n"
                   "  -p socket    Milter socket (default: unix:/var/spool/DarkARCs/sock)\n"
                   "  -S hostname  Server hostname (default: %s)\n"
                   "  -d domain    Signing domain for d= tag (default: %s)\n"
                   "  -l level     Log level: debug|info|notice|warning|err (default: notice)\n"
                   "  -m umask     Socket umask in octal (default: 0177)\n"
                   "  -f           Run in foreground (no daemon)\n"
                   "  -L           Log to stderr (in addition to syslog)\n", usage, MY_SERVER, DOMAIN);
   exit(1);
}

void cleanup_and_exit(int sig) 
{
   write(2, "Signal received, exiting...\n", 28);
   exit(0);
}


