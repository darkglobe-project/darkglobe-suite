/*
 * dc_shared.c — Shared DKIM2-core functions for DarkChain/DarkChains
 *
 * Tag parsing, envelope utilities, header hash exclusion/computation,
 * and qsort comparators shared between verifier and signer.
 *
 * Copyright (c) 2026 Vittorio Moccia / ITB.it
 * Licensed under Apache 2.0 License.
 */

#include "dc_shared.h"


/* ================================================================
 * GLOBALS
 * ================================================================ */

struct dc_hh_exclude hh_excludes[DC_HH_MAX_EXCLUDE];
int hh_exclude_count = 0;

const char *hh_default_excludes[] = {
   "Received", "Return-Path", "Authentication-Results",
   "DKIM-Signature", "DKIM2-", "ARC-", NULL
};

const char *hh_single_fields[] = {
   "Date", "From", "Sender", "Reply-To",
   "To", "Cc", "Bcc",
   "Message-ID", "In-Reply-To", "References",
   "Subject",
   "MIME-Version", "Content-Type",
   "Content-Transfer-Encoding", "Content-Disposition",
   NULL
};


/* ================================================================
 * DKIM2-SPECIFIC TAG PARSING
 *
 * Tag-value format per RFC 6376 §3.2:
 *   tag-list  = tag-spec *( ";" tag-spec ) [ ";" ]
 *   tag-spec  = [FWS] tag-name [FWS] "=" [FWS] tag-value [FWS]
 * ================================================================ */

/*
 * Find a tag in a tag-value header value.
 * Returns pointer to the first character after "tag=", or NULL.
 */
const char *dc_find_tag(const char *header_value, const char *tag)
{
   if (!header_value || !tag || !*tag) return NULL;

   size_t tag_len = strlen(tag);
   const char *p = header_value;

   while ((p = strstr(p, tag)) != NULL)
   {
      /* Check: tag must be followed by '=' */
      if (p[tag_len] != '=')
      {
         p += tag_len;
         continue;
      }

      /* Check: tag must be at start, or preceded by ';' or whitespace */
      if (p > header_value)
      {
         char prev = *(p - 1);
         if (prev != ';' && prev != ' ' && prev != '\t')
         {
            p += tag_len;
            continue;
         }
      }

      /* Found it — return pointer past "tag=" */
      return p + tag_len + 1;
   }

   return NULL;
}

/*
 * Extract i= from a DKIM2 header value.
 * Returns the integer value, or -1 if not found/invalid.
 */
int dc_get_hop_index(const char *header_value)
{
   const char *val = dc_find_tag(header_value, "i");
   if (!val) return -1;

   /* Skip whitespace after '=' */
   while (*val == ' ' || *val == '\t') val++;

   /* ABNF: 1*2DIGIT */
   if (!isdigit((unsigned char)*val)) return -1;

   int index = atoi(val);
   return (index > 0 && index <= DC_MAX_HOPS) ? index : -1;
}

/*
 * Highest i= among DKIM2-Signature headers only.
 *
 * Per the deployment profile, DKIM2-Signature headers are numbered
 * sequentially starting at i=1 and a gap MUST be treated as making the
 * message unsigned.  Given that rule, the highest signature index equals
 * the signature count, and (highest + 1) is the authoritative index for
 * the next signing hop — independent of any DKIM2-Mod present (which may
 * sit at the next level and would inflate a max taken over all headers).
 *
 * The inbound verifier already validates chain continuity in dc_eoh; this
 * function carries its own lightweight contiguity pass because it is also
 * called by the outbound signer in the post-list (Case B) path, where the
 * verifier did not run.  On a gap it logs and returns -1 so the caller can
 * treat the chain as unsigned.  Returns 0 when no DKIM2-Signature exists.
 *
 * Reads the already-parsed dc_type/hop fields directly — no re-parsing.
 */
int dc_max_sig_hop(const struct header_slot *headers, int header_cnt)
{
   int max_i = 0;
   for (int j = 0; j < header_cnt; j++)
   {
      if (headers[j].dc_type == DC_HDR_SIG && headers[j].hop > max_i)
         max_i = headers[j].hop;
   }
   if (max_i == 0)
      return 0;

   for (int i = 1; i <= max_i; i++)
   {
      int found = 0;
      for (int j = 0; j < header_cnt; j++)
      {
         if (headers[j].dc_type == DC_HDR_SIG && headers[j].hop == i)
         {
            found = 1;
            break;
         }
      }
      if (!found)
      {
         syslog(LOG_NOTICE,
                "dc_max_sig_hop: chain gap — no DKIM2-Signature at i=%d "
                "(max=%d); treating chain as unsigned", i, max_i);
         return -1;
      }
   }
   return max_i;
}

/*
 * Extract an integer tag value (v=, seq=, fr=) from a DKIM2 header.
 * Returns the integer value, or 0 if not found.
 */
int dc_get_tag_int(const char *header_value, const char *tag)
{
   const char *val = dc_find_tag(header_value, tag);
   if (!val) return 0;

   while (*val == ' ' || *val == '\t') val++;

   if (!isdigit((unsigned char)*val)) return 0;

   int result = atoi(val);
   return (result > 0) ? result : 0;
}

/*
 * Extract a string tag value from a DKIM2 header.
 * Copies into out, up to out_len-1 chars.
 * Stops at ';' or end of string.  Trims whitespace.
 */
void dc_get_tag_str(const char *header_value, const char *tag,
                    char *out, size_t out_len)
{
   out[0] = '\0';
   if (!header_value || !tag || out_len < 2) return;

   const char *val = dc_find_tag(header_value, tag);
   if (!val) return;

   /* Skip leading whitespace */
   while (*val == ' ' || *val == '\t') val++;

   /* Copy until ';' or end */
   size_t i = 0;
   while (*val && *val != ';' && i < out_len - 1)
   {
      out[i++] = *val++;
   }
   out[i] = '\0';

   /* Trim trailing whitespace */
   while (i > 0 && isspace((unsigned char)out[i - 1]))
   {
      out[--i] = '\0';
   }
}


/* ================================================================
 * ENVELOPE UTILITIES
 * ================================================================ */

/*
 * Extract addr= tag from a DKIM2-Sig-mf or DKIM2-Sig-rt header.
 * Quote-aware: does not stop at ';' inside a quoted local part.
 * addr= is defined as the last tag, so take everything remaining.
 */
void dc_get_addr_tag(const char *header_value, char *out, size_t out_len)
{
   out[0] = '\0';
   if (!header_value || out_len < 2) return;

   const char *p = dc_find_tag(header_value, "addr");
   if (!p) return;

   /* Skip leading whitespace */
   while (*p == ' ' || *p == '\t') p++;

   /* Copy to end-of-string */
   size_t i = 0;
   while (*p && i < out_len - 1)
   {
      out[i++] = *p++;
   }
   out[i] = '\0';

   /* Trim trailing whitespace and optional trailing ';' */
   while (i > 0 && (isspace((unsigned char)out[i - 1]) || out[i - 1] == ';'))
   {
      out[--i] = '\0';
   }
}

/*
 * Normalize an RFC 5321 addr-spec for comparison:
 *   1. Strip unnecessary quotes from local part
 *   2. Lowercase the domain part
 *   3. Leave local part case as-is
 */
void dc_normalize_addr(const char *addr, char *out, size_t out_len)
{
   if (!addr || !out || out_len < 2)
   {
      if (out && out_len > 0) out[0] = '\0';
      return;
   }

   const char *at = NULL;
   const char *p = addr;
   size_t o = 0;

   /* Find @ — but skip @ inside quotes */
   int in_quote = 0;
   for (const char *scan = addr; *scan; scan++)
   {
      if (*scan == '"') in_quote = !in_quote;
      if (*scan == '@' && !in_quote)
      {
         at = scan;
         break;
      }
   }

   if (!at)
   {
      /* No @ found — treat entire thing as local part, copy as-is */
      securecpy(out, addr, out_len);
      return;
   }

   /* --- Local part --- */
   int local_is_quoted = (*p == '"');

   if (local_is_quoted)
   {
      /* Check if quotes are necessary */
      int needs_quotes = 0;
      const char *inner = p + 1;
      while (*inner && *inner != '"')
      {
         if (*inner == ';' || *inner == ' ' || *inner == '@' ||
             *inner == '<' || *inner == '>' || *inner == '(' ||
             *inner == ')' || *inner == ',' || *inner == '[' ||
             *inner == ']' || *inner == '\\' || *inner == '.')
         {
            if (*inner != '.')
               needs_quotes = 1;
         }
         inner++;
      }

      if (needs_quotes)
      {
         while (p < at && o < out_len - 1)
            out[o++] = *p++;
      }
      else
      {
         /* Strip quotes */
         p++;
         while (p < at && *p != '"' && o < out_len - 1)
            out[o++] = *p++;
         p = at;
      }
   }
   else
   {
      while (p < at && o < out_len - 1)
         out[o++] = *p++;
   }

   /* --- @ --- */
   if (o < out_len - 1)
      out[o++] = '@';

   /* --- Domain part: lowercase --- */
   p = at + 1;
   while (*p && o < out_len - 1)
   {
      out[o++] = tolower((unsigned char)*p);
      p++;
   }

   out[o] = '\0';
}

/*
 * Compare two RFC 5321 addr-specs with normalization.
 * Returns 1 on match, 0 on mismatch.
 */
int dc_addr_match(const char *a, const char *b)
{
   char norm_a[DC_MAX_ADDR], norm_b[DC_MAX_ADDR];
   dc_normalize_addr(a, norm_a, sizeof(norm_a));
   dc_normalize_addr(b, norm_b, sizeof(norm_b));
   return (strcmp(norm_a, norm_b) == 0) ? 1 : 0;
}

/*
 * Strip angle brackets from an SMTP address.
 */
void dc_strip_angle_brackets(const char *src, char *dst, size_t dst_len)
{
   if (!src || !dst || dst_len < 2)
   {
      if (dst && dst_len > 0) dst[0] = '\0';
      return;
   }

   const char *start = src;
   const char *end;

   while (*start == ' ' || *start == '\t') start++;
   if (*start == '<') start++;

   size_t i = 0;
   for (; start[i] && start[i] != '>' && i < dst_len - 1; i++)
   {
      dst[i] = start[i];
   }
   dst[i] = '\0';

   end = dst + i - 1;
   while (end >= dst && (*end == ' ' || *end == '\t'))
   {
      dst[end - dst] = '\0';
      end--;
   }
}

/*
 * Relaxed domain match (draft -03 §3.1.2).
 * MAIL FROM domain MUST be at most two levels below d=.
 * Returns 1 on match, 0 on mismatch.
 */
int dc_relaxed_domain_match(const char *d_domain, const char *mf_addr)
{
   if (!d_domain || !mf_addr || d_domain[0] == '\0' || mf_addr[0] == '\0')
      return 0;

   /* Extract domain from mf addr-spec (quote-aware @ scan) */
   const char *at = NULL;
   int in_quote = 0;
   for (const char *scan = mf_addr; *scan; scan++)
   {
      if (*scan == '"') in_quote = !in_quote;
      if (*scan == '@' && !in_quote) { at = scan; break; }
   }
   const char *mf_domain = at ? at + 1 : mf_addr;

   /* Exact match (case-insensitive on domain) */
   if (strcasecmp(mf_domain, d_domain) == 0)
      return 1;

   /* Try removing labels from the left, max 2 levels */
   const char *p = mf_domain;
   int labels_removed = 0;

   while (labels_removed < 2)
   {
      p = strchr(p, '.');
      if (!p) break;
      p++; /* skip the dot */
      labels_removed++;

      if (strcasecmp(p, d_domain) == 0)
         return 1;
   }

   return 0;
}


/* ================================================================
 * HEADER HASH (hh=) EXCLUSION LIST AND COMPUTATION
 * ================================================================ */

void load_hh_excludes(const char *path)
{
   hh_exclude_count = 0;

   /* Always load structural defaults first */
   for (int i = 0; hh_default_excludes[i] && hh_exclude_count < DC_HH_MAX_EXCLUDE; i++)
   {
      const char *pat = hh_default_excludes[i];
      securecpy(hh_excludes[hh_exclude_count].pattern, pat, MAX_HEADER_NAME);
      int len = strlen(pat);
      hh_excludes[hh_exclude_count].is_prefix = (len > 0 && pat[len - 1] == '-') ? 1 : 0;
      hh_excludes[hh_exclude_count].match_len = len;
      hh_exclude_count++;
   }

   /* Load additional exclusions from config file */
   FILE *fp = fopen(path, "r");
   if (!fp)
   {
      syslog(LOG_INFO, "DC_SHARED: hh_exclude using %d defaults (no %s)",
             hh_exclude_count, path);
      return;
   }

   char line[MAX_HEADER_NAME];
   while (fgets(line, sizeof(line), fp) && hh_exclude_count < DC_HH_MAX_EXCLUDE)
   {
      char *p = line;
      while (*p == ' ' || *p == '\t') p++;
      if (*p == '#' || *p == '\n' || *p == '\0') continue;
      char *end = p + strlen(p) - 1;
      while (end > p && (*end == '\n' || *end == '\r' || *end == ' ')) *end-- = '\0';
      if (*p == '\0') continue;

      securecpy(hh_excludes[hh_exclude_count].pattern, p, MAX_HEADER_NAME);
      int len = strlen(p);
      hh_excludes[hh_exclude_count].is_prefix = (len > 0 && p[len - 1] == '-') ? 1 : 0;
      hh_excludes[hh_exclude_count].match_len = len;
      hh_exclude_count++;
   }
   fclose(fp);
   syslog(LOG_INFO, "DC_SHARED: hh_exclude: %d patterns (%d defaults + %d from %s)",
          hh_exclude_count,
          (int)(sizeof(hh_default_excludes)/sizeof(hh_default_excludes[0]) - 1),
          hh_exclude_count - (int)(sizeof(hh_default_excludes)/sizeof(hh_default_excludes[0]) - 1),
          path);
}

int dc_is_hh_excluded(const char *name)
{
   for (int i = 0; i < hh_exclude_count; i++)
   {
      if (hh_excludes[i].is_prefix)
      {
         if (strncasecmp(name, hh_excludes[i].pattern,
                         hh_excludes[i].match_len) == 0)
            return 1;
      }
      else
      {
         if (strcasecmp(name, hh_excludes[i].pattern) == 0)
            return 1;
      }
   }
   return 0;
}

int dc_is_single_field(const char *name)
{
   for (int i = 0; hh_single_fields[i]; i++)
   {
      if (strcasecmp(name, hh_single_fields[i]) == 0)
         return 1;
   }
   return 0;
}


/* ================================================================
 * QSORT COMPARATORS
 * ================================================================ */

/* Alphabetical by name, position for duplicates */
int cmp_header_hh(const void *a, const void *b)
{
   const struct header_slot *sa = *(const struct header_slot *const *)a;
   const struct header_slot *sb = *(const struct header_slot *const *)b;
   int cmp = strcasecmp(sa->name, sb->name);
   if (cmp != 0) return cmp;
   return (sa < sb) ? -1 : (sa > sb) ? 1 : 0;
}

/* Compare two header values in canonicalized form (relaxed) */
int cmp_canon_value(struct header_slot *a, struct header_slot *b)
{
   char ca[BIG_HEADER_VALUE + MAX_HEADER_NAME + 64];
   char cb[BIG_HEADER_VALUE + MAX_HEADER_NAME + 64];

   int la = canonicalize_header_relaxed(a->name, a->value, ca, sizeof(ca), 0);
   int lb = canonicalize_header_relaxed(b->name, b->value, cb, sizeof(cb), 0);

   if (la <= 0 && lb <= 0) return 0;
   if (la <= 0) return -1;
   if (lb <= 0) return 1;

   int minlen = la < lb ? la : lb;
   int cmp = memcmp(ca, cb, minlen);
   if (cmp != 0) return cmp;
   return la - lb;
}

/* DKIM2-Mod canonical order: i asc, seq asc, del<new, fr asc */
int cmp_mod_canonical(const void *a, const void *b)
{
   const struct header_slot *sa = *(const struct header_slot *const *)a;
   const struct header_slot *sb = *(const struct header_slot *const *)b;

   if (sa->hop != sb->hop) return sa->hop - sb->hop;
   if (sa->seq != sb->seq) return sa->seq - sb->seq;
   if (sa->is_new != sb->is_new) return sa->is_new - sb->is_new;
   if (sa->fr != sb->fr) return sa->fr - sb->fr;

   return 0;
}

/* DKIM2-Sig-rt: ascending v= */
int cmp_rt_by_v(const void *a, const void *b)
{
   const struct header_slot *sa = *(const struct header_slot *const *)a;
   const struct header_slot *sb = *(const struct header_slot *const *)b;
   return sa->v - sb->v;
}


/* ================================================================
 * HEADER HASH (hh=) COMPUTATION
 * ================================================================ */

/*
 * Compute hh= header hash.
 *
 * 1. Collect all non-excluded headers from the reservoir
 * 2. Sort alphabetically by name
 * 3. For duplicate groups:
 *    - Multi-allowed (Comments, Keywords, Resent-*): sort by canon value
 *    - All others: reorder using DKIM2-Mod i=
 * 4. Canonicalize each, concatenate, SHA-256
 *
 * Returns malloc'd base64 string, or NULL on error. Caller frees.
 */
char *dc_compute_hh(struct header_slot *headers, int header_cnt)
{
   /* Off-stack: one instance per worker thread (libmilter = 1 thread per
    * connection), so no locking is required and the ~10KB stays out of the
    * call frame. */
   static __thread struct header_slot *ptrs[MAX_HEADER_COUNT];
   int count = 0;

   for (int j = 0; j < header_cnt && count < MAX_HEADER_COUNT; j++)
   {
      if (headers[j].name[0] == '\0') continue;
      if (dc_is_hh_excluded(headers[j].name)) continue;
      ptrs[count++] = &headers[j];
   }

   if (count > 1)
      qsort(ptrs, count, sizeof(struct header_slot *), cmp_header_hh);

   /* Reorder duplicate groups using DKIM2-Mod */
   int grp_start = 0;
   while (grp_start < count)
   {
      int grp_end = grp_start + 1;
      while (grp_end < count &&
             strcasecmp(ptrs[grp_start]->name, ptrs[grp_end]->name) == 0)
         grp_end++;

      int grp_size = grp_end - grp_start;

      if (grp_size > 1)
      {
         /* Step A: For ALL members, try to find a matching DKIM2-Mod (new=) */
         static __thread int sort_keys[MAX_HEADER_COUNT];

         for (int g = grp_start; g < grp_end; g++)
         {
            sort_keys[g] = 0;

            for (int m = 0; m < header_cnt; m++)
            {
               if (headers[m].dc_type != DC_HDR_MOD) continue;
               if (headers[m].is_new != 1) continue;
               if (headers[m].fr != 1) continue;

               const char *fld = dc_find_tag(headers[m].value, "field");
               if (!fld) continue;

               char mod_field[MAX_HEADER_NAME] = "";
               int fi = 0;
               while (*fld && *fld != ';' && *fld != ' ' && *fld != '\t'
                      && fi < MAX_HEADER_NAME - 1)
                  mod_field[fi++] = *fld++;
               mod_field[fi] = '\0';

               if (strcasecmp(mod_field, ptrs[g]->name) != 0) continue;

               const char *nv = dc_find_tag(headers[m].value, "new");
               if (!nv) continue;
               if (*nv == '"') nv++;

               /* Find closing quote: last " in the string.
                * new= is always the last tag, so everything between
                * the first " and the last " is the value — even if
                * the value itself contains embedded ".
                */
               const char *nv_end = strrchr(nv, '"');
               if (!nv_end) nv_end = nv + strlen(nv);

               const char *hv = ptrs[g]->value;
               while (*hv == ' ' || *hv == '\t') hv++;

               int match = 1;
               const char *np = nv;
               const char *hp = hv;
               while (np < nv_end)
               {
                  if (*hp == '\0' || *np != *hp) { match = 0; break; }
                  np++; hp++;
               }

               if (match)
               {
                  sort_keys[g] = headers[m].hop;
                  break;
               }
            }
         }

         /* Step B: Bubble sort by sort_key (0 first, then i= ascending) */
         for (int i = grp_start; i < grp_end - 1; i++)
            for (int j = i + 1; j < grp_end; j++)
               if (sort_keys[j] < sort_keys[i])
               {
                  struct header_slot *tmp = ptrs[i];
                  ptrs[i] = ptrs[j]; ptrs[j] = tmp;
                  int tk = sort_keys[i];
                  sort_keys[i] = sort_keys[j]; sort_keys[j] = tk;
               }

         /* Step C: Among key=0 members, if multi-allowed
          * sub-sort by canonicalized value for determinism.
          */
         int zero_end = grp_start;
         while (zero_end < grp_end && sort_keys[zero_end] == 0)
            zero_end++;

         if (zero_end - grp_start > 1 &&
             !dc_is_single_field(ptrs[grp_start]->name))
         {
            for (int i = grp_start; i < zero_end - 1; i++)
               for (int j = i + 1; j < zero_end; j++)
                  if (cmp_canon_value(ptrs[i], ptrs[j]) > 0)
                  {
                     struct header_slot *tmp = ptrs[i];
                     ptrs[i] = ptrs[j]; ptrs[j] = tmp;
                  }
         }
      } /* end if (grp_size > 1) */

      grp_start = grp_end;
   }

   /* Hash */
   EVP_MD_CTX *ctx = EVP_MD_CTX_new();
   if (!ctx) return NULL;
   EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);

   char canon_buf[BIG_HEADER_VALUE + MAX_HEADER_NAME + 64];

   for (int i = 0; i < count; i++)
   {
      int clen = canonicalize_header_relaxed(
         ptrs[i]->name, ptrs[i]->value,
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
 * RFC 5322 ADDRESS EXTRACTION
 *
 * Extracts addr-spec values from address-list headers (To:, Cc:).
 * Used to compare envelope RCPT TO against visible recipients
 * for BCC detection.
 *
 * Handles:
 *   "Alice" <alice@ex.com>             → alice@ex.com
 *   alice@ex.com                       → alice@ex.com
 *   Team: alice@ex.com, bob@ex.com;    → alice@ex.com, bob@ex.com
 *   (comment) alice@ex.com             → alice@ex.com
 *   "user;name"@domain.com             → "user;name"@domain.com
 *   "a\"b"@ex.com                      → "a\"b"@ex.com
 *   Undisclosed recipients:;           → (nothing)
 *   <alice@ex.com>                     → alice@ex.com
 *
 * State machine:
 *   - Tracks: comment depth, quoted-string, angle-bracket
 *   - Inside <>: collects addr-spec directly
 *   - Outside <>: collects bare segment, extracts addr-spec at flush
 *   - ':' without prior '@' → group name, discard segment
 *   - ',' and ';' → flush and store address
 *   - Backslash escaping inside quotes and comments
 *
 * Returns: number of addresses extracted (0..max_addrs)
 * ================================================================ */

int dc_extract_addresses(const char *hdr,
                         char addrs[][DC_MAX_ADDR],
                         int max_addrs)
{
   if (!hdr || !addrs || max_addrs <= 0) return 0;

   int count = 0;
   int comment_depth = 0;
   int in_dquote = 0;
   int in_angle = 0;

   char abuf[DC_MAX_ADDR];     /* addr-spec inside <> */
   int  alen = 0;

   char sbuf[DC_MAX_ADDR * 2]; /* bare segment between separators */
   int  slen = 0;

   int got_angle = 0;          /* found <> in current segment */

   const char *p = hdr;

   for (; ; p++)
   {
      char c = *p;

      /* ---- BACKSLASH ESCAPE inside quotes or comments ---- */
      if (c == '\\' && (in_dquote || comment_depth > 0))
      {
         if (*(p + 1))
         {
            if (in_angle)
            {
               if (alen < DC_MAX_ADDR - 2)
               { abuf[alen++] = c; abuf[alen++] = *(p + 1); }
            }
            else if (comment_depth == 0)
            {
               if (slen < (int)sizeof(sbuf) - 2)
               { sbuf[slen++] = c; sbuf[slen++] = *(p + 1); }
            }
            /* else: inside comment, skip both chars */
            p++;  /* skip escaped char */
         }
         continue;
      }

      /* ---- SEPARATOR or END: flush current address ---- */
      if (c == '\0' ||
          ((c == ',' || c == ';') &&
           !in_dquote && comment_depth == 0 && !in_angle))
      {
         if (got_angle && alen > 0 && count < max_addrs)
         {
            /* Address from <...> */
            abuf[alen] = '\0';
            char *a = abuf;
            while (*a == ' ' || *a == '\t') a++;
            int al = strlen(a);
            while (al > 0 && (a[al - 1] == ' ' || a[al - 1] == '\t'))
               a[--al] = '\0';
            if (strchr(a, '@'))
               securecpy(addrs[count++], a, DC_MAX_ADDR);
         }
         else if (!got_angle && slen > 0 && count < max_addrs)
         {
            /* Bare addr-spec: trim and use if it contains @ */
            sbuf[slen] = '\0';
            char *s = sbuf;
            while (*s == ' ' || *s == '\t') s++;
            int sl = strlen(s);
            while (sl > 0 && (s[sl - 1] == ' ' || s[sl - 1] == '\t'))
               s[--sl] = '\0';
            if (strchr(s, '@'))
               securecpy(addrs[count++], s, DC_MAX_ADDR);
         }

         got_angle = 0;
         alen = 0;
         slen = 0;

         if (c == '\0') break;
         continue;
      }

      /* ---- COLON: possible group name ---- */
      if (c == ':' && !in_dquote && comment_depth == 0 && !in_angle)
      {
         /* If no '@' in segment so far, this is a group header.
          * Discard the display-name and continue collecting members.
          * If '@' present, colon is part of something else (pass through).
          */
         sbuf[slen] = '\0';
         if (!strchr(sbuf, '@'))
         {
            slen = 0;
            got_angle = 0;
            continue;
         }
         /* Fall through: colon is part of the value */
      }

      /* ---- COMMENTS: ( ) with nesting ---- */
      if (c == '(' && !in_dquote && !in_angle)
      {
         comment_depth++;
         continue;
      }
      if (c == ')' && comment_depth > 0 && !in_dquote && !in_angle)
      {
         comment_depth--;
         continue;
      }
      if (comment_depth > 0)
         continue;  /* skip comment content */

      /* ---- DOUBLE QUOTES ---- */
      if (c == '"' && comment_depth == 0)
      {
         in_dquote = !in_dquote;
         /* Keep the quote in the buffer — it's part of the addr-spec
          * for quoted local parts like "user;name"@domain.com
          */
         if (in_angle)
         {
            if (alen < DC_MAX_ADDR - 1) abuf[alen++] = c;
         }
         else
         {
            if (slen < (int)sizeof(sbuf) - 1) sbuf[slen++] = c;
         }
         continue;
      }

      /* ---- ANGLE BRACKETS ---- */
      if (c == '<' && !in_dquote && !in_angle)
      {
         in_angle = 1;
         alen = 0;
         continue;
      }
      if (c == '>' && in_angle && !in_dquote)
      {
         in_angle = 0;
         got_angle = 1;
         continue;
      }

      /* ---- COLLECT CHARACTER ---- */
      if (in_angle)
      {
         if (alen < DC_MAX_ADDR - 1)
            abuf[alen++] = c;
      }
      else
      {
         if (slen < (int)sizeof(sbuf) - 1)
            sbuf[slen++] = c;
      }
   }

   return count;
}
