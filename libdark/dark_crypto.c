/*
 * dark_crypto.c — Crypto/Base64/DNS utilities for DarkGlobe Suite
 *
 * encode_base64_hash, decode_base64_to_buf, decode_base64_sig,
 * decode_dns_key, get_dns_arc_pubkey, load_private_key
 *
 * From DarkARC by Vittorio Moccia / ITB.it
 * Copyright (c) 2026 Vittorio Moccia / ITB.it
 * Licensed under the MIT License
 */

#include "dark_common.h"
#include <resolv.h>


char *encode_base64_hash(const unsigned char *bin_data, int bin_len)
{
   if (!bin_data || bin_len <= 0) return NULL;

   BIO *b64 = BIO_new(BIO_f_base64());
   BIO *mem = BIO_new(BIO_s_mem());
   BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
   BIO_push(b64, mem);

   BIO_write(b64, bin_data, bin_len);
   BIO_flush(b64);

   BUF_MEM *ptr;
   BIO_get_mem_ptr(b64, &ptr);

   char *out_str = malloc(ptr->length + 1);
   if (out_str)
   {
      memcpy(out_str, ptr->data, ptr->length);
      out_str[ptr->length] = '\0';

      /* Strip any trailing CR/LF that some OpenSSL versions add
       * despite BIO_FLAGS_BASE64_NO_NL
       */
      int len = strlen(out_str);
      int stripped = 0;
      while (len > 0 && (out_str[len-1] == '\r' || out_str[len-1] == '\n'))
      {
         out_str[--len] = '\0';
         stripped++;
      }
      if (stripped)
         syslog(LOG_WARNING, "encode_base64_hash: stripped %d trailing CR/LF", stripped);
   }

   BIO_free_all(b64);
   return out_str;
}

int decode_base64_to_buf(const char *base64_key, unsigned char *out_buf, int out_len)
{
   BIO *b64, *mem;

   b64 = BIO_new(BIO_f_base64());
   mem = BIO_new_mem_buf(base64_key, -1);
   BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
   mem = BIO_push(b64, mem);

   int length = BIO_read(mem, out_buf, out_len);

   BIO_free_all(mem);
   return length;
}

int decode_base64_sig(const char *base64_sig, unsigned char *out_bin, int out_len)
{
   if (!base64_sig || !out_bin) return -1;

   /* Copy while stripping all whitespace */
   char clean[4096];
   size_t k = 0;
   for (size_t i = 0; base64_sig[i] && k < sizeof(clean) - 1; i++)
   {
      if (!isspace((unsigned char)base64_sig[i]))
         clean[k++] = base64_sig[i];
   }
   clean[k] = '\0';

   if (k == 0) return -1;

   BIO *b64 = BIO_new(BIO_f_base64());
   if (!b64) return -1;

   BIO *mem = BIO_new_mem_buf(clean, (int)k);
   if (!mem)
   {
      BIO_free(b64);
      return -1;
   }

   BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
   BIO_push(b64, mem);

   int len = BIO_read(b64, out_bin, out_len);

   BIO_free_all(b64);
   return (len > 0) ? len : -1;
}

EVP_PKEY *decode_dns_key(const char *base64_key, bool is_ed25519)
{
   if (base64_key == NULL || *base64_key == '\0') return NULL;

   unsigned char decoded[1024];
   int decoded_len = decode_base64_to_buf(base64_key, decoded, sizeof(decoded));
   if (decoded_len <= 0) return NULL;

   /* Ed25519: bare 32-byte key */
   if (is_ed25519 && decoded_len == 32)
   {
      return EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, decoded, 32);
   }

   /* RSA or wrapped key: DER-encoded SubjectPublicKeyInfo */
   BIO *mem = BIO_new_mem_buf(decoded, decoded_len);
   EVP_PKEY *pkey = d2i_PUBKEY_bio(mem, NULL);
   BIO_free(mem);

   if (pkey == NULL)
   {
      syslog(LOG_WARNING, "DC_DECODE_DNS_KEY: Key decode failed. Length: %d bytes", decoded_len);
   }
   return pkey;
}

int get_dns_arc_pubkey(const char *d, const char *s, char *pubkey_out, size_t out_len)
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

            char *p_tag = strstr(full_record, "p=");
            if (p_tag)
            {
               p_tag += 2;
               char *end = strchr(p_tag, ';');
               if (end) *end = '\0';

               strncpy(pubkey_out, p_tag, out_len - 1);
               pubkey_out[out_len - 1] = '\0';

               /* Strip whitespace from key */
               char *src = pubkey_out, *dst = pubkey_out;
               while (*src)
               {
                  if (!isspace((unsigned char)*src))
                     *dst++ = *src;
                  src++;
               }
               *dst = '\0';

               return 1;
            }
         }
      }
   }
   return -1;
}

EVP_PKEY *load_private_key(const char *path)
{
   FILE *fp = fopen(path, "r");
   if (!fp) { syslog(LOG_ERR, "DARK_CRYPTO: Unable to open key: %s", path); return NULL; }
   EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
   fclose(fp);
   if (!pkey) syslog(LOG_ERR, "DARK_CRYPTO: Error parsing private key from %s", path);
   return pkey;
}
