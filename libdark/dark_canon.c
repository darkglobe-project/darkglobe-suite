/*
 * dark_canon.c — Header canonicalization for DarkGlobe Suite
 *
 * canonicalize_header_relaxed, canonicalize_sig_for_verify,
 * prepare_header_for_hash
 *
 * From DarkARC by Vittorio Moccia / ITB.it
 * Copyright (c) 2026 Vittorio Moccia / ITB.it
 * Licensed under the MIT License.
 */

#include "dark_common.h"


int canonicalize_header_relaxed(const char *name, const char *value,
                                char *out, size_t out_max, int add_crlf)
{
   if (!name || !value || !out || out_max < 3)
      return -1;

   size_t j = 0;

   /* 1. Name: lowercase */
   for (size_t i = 0; name[i]; i++)
   {
      if (j >= out_max - 3) return -1;
      out[j++] = tolower((unsigned char)name[i]);
   }

   /* 2. Separator */
   if (j >= out_max - 3) return -1;
   out[j++] = ':';

   /* 3. Value: handle WSP and folding */
   const char *p = value;
   while (*p == ' ' || *p == '\t') p++;

   int pending_space = 0;
   size_t last_nonspace_j = j;

   while (*p)
   {
      /* Folding: CRLF + WSP -> space */
      if (p[0] == '\r' && p[1] == '\n' && (p[2] == ' ' || p[2] == '\t'))
      {
         pending_space = 1;
         p += 2;
         continue;
      }
      /* End of value: CRLF not followed by WSP */
      if (p[0] == '\r' && p[1] == '\n')
         break;
      /* Lone LF not followed by WSP */
      if (p[0] == '\n' && p[1] != ' ' && p[1] != '\t')
         break;
      /* Lone LF + WSP -> folding */
      if (p[0] == '\n' && (p[1] == ' ' || p[1] == '\t'))
      {
         pending_space = 1;
         p++;
         continue;
      }

      if (*p == ' ' || *p == '\t')
      {
         pending_space = 1;
         p++;
         continue;
      }

      /* Normal character */
      if (pending_space)
      {
         if (j >= out_max - 3) return -1;
         out[j++] = ' ';
         pending_space = 0;
      }
      if (j >= out_max - 3) return -1;
      out[j++] = *p++;
      last_nonspace_j = j;
   }

   /* 4. Trailing trim */
   j = last_nonspace_j;

   /* 5. Trailing CRLF */
   if (add_crlf)
   {
      if (j + 2 >= out_max) return -1;
      out[j++] = '\r';
      out[j++] = '\n';
   }

   if (j >= out_max) return -1;
   out[j] = '\0';
   return (int)j;
}

/*
 * Canonicalize a DKIM2-Signature (or AMS) for verification:
 * zeroes the b= tag value, then applies relaxed canonicalization.
 */
int canonicalize_sig_for_verify(const char *name, const char *value,
                                char *out, size_t out_max)
{
   char buf[8192];
   size_t vlen = strlen(value);
   if (vlen >= sizeof(buf)) return -1;
   memcpy(buf, value, vlen + 1);

   unfold_header(buf);

   char *p = buf;
   while (*p)
   {
      char *found = strstr(p, "b=");
      if (!found) break;

      /* Guard against matching bh= */
      if (found > buf && *(found - 1) == 'h')
      {
         p = found + 2;
         continue;
      }

      char *val_start = found + 2;
      char *val_end = val_start;

      while (*val_end && *val_end != ';' && *val_end != '\r' && *val_end != '\n')
         val_end++;

      if (*val_end == ';')
         memmove(val_start, val_end, strlen(val_end) + 1);
      else
         *val_start = '\0';

      break;
   }
   return canonicalize_header_relaxed(name, buf, out, out_max, 0);
}

void prepare_header_for_hash(char *header_val)
{
   char *p_start = strcasestr(header_val, "b=");
   if (!p_start) return;

   char *p_value = p_start + 2;
   char *p_end = p_value;

   while (*p_end && *p_end != ';' && *p_end != '\r' && *p_end != '\n')
      p_end++;

   if (*p_end == ';')
      memmove(p_value, p_end, strlen(p_end) + 1);
   else
      *p_value = '\0';
}
