/*
 * DarkSRS - Standalone SRS Envelope Rewriter Milter
 *
 * Rewrites MAIL FROM for forwarded mail to prevent SPF failures.
 * Handles both direct esmtp recipients AND alias-expanded recipients
 * by reading virtusertable.db and aliases.db at startup.
 *
 * Build:
 *   gcc -Wall -Wextra -o DarkSRS DarkSRS.c \
 *       -lmilter -lssl -lcrypto -ldb -lpthread
 *
 * Copyright (c) 2026 Vittorio Moccia / DarkGlobe Project
 * Licensed under the PolyForm Noncommercial License 1.0.0.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>
#include <time.h>
#include <pwd.h>
#include <stdint.h>
#include <ctype.h>

#include <libmilter/mfapi.h>
#include <openssl/hmac.h>
#include <db.h>
#define DEBUG1 1 
/* ================================================================
 * CONFIGURATION
 * ================================================================ */

#define OCONN               "unix:/var/spool/DarkSRS/sock"
#define USER                "smmsp"
#define SRS_DOMAIN          "itb.it"
#define SRS_KEY_CONF        "/etc/DarkSRS/srs.key"
#define VIRTUSERTABLE_DB    "/etc/mail/virtusertable.db"
#define ALIASES_DB          "/etc/mail/aliases.db"
#define LOCAL_DOMAINS_FILE  "/etc/mail/local-host-names"
#define MAX_ADDR            512
#define MAX_LOCAL_DOMAINS   64
#define MAX_ALIASES_VALUE   4096
#define DEBUG 1
/* ================================================================
 * SRS CRYPTO
 * ================================================================ */

static unsigned char srs_secret[256];
static size_t        srs_secret_len = 0;

static const char SRS_B32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static void load_srs_secret(const char *path)
{
   FILE *fp = fopen(path, "r");
   if (!fp)
   {
      syslog(LOG_INFO,
             "DSRS: no SRS key at %s — forge-resistance disabled", path);
      return;
   }
   size_t n = fread(srs_secret, 1, sizeof(srs_secret), fp);
   fclose(fp);
   while (n > 0 && (srs_secret[n - 1] == '\n' || srs_secret[n - 1] == '\r' ||
                    srs_secret[n - 1] == ' '  || srs_secret[n - 1] == '\t'))
      n--;
   srs_secret_len = n;
   syslog(LOG_INFO, "DSRS: loaded SRS key (%zu bytes)", srs_secret_len);
}

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
 * LOCAL DOMAINS
 * ================================================================ */

static char local_domains[MAX_LOCAL_DOMAINS][256];
static int  local_domain_count = 0;

static void load_local_domains(const char *path)
{
   FILE *fp = fopen(path, "r");
   if (!fp)
   {
      syslog(LOG_ERR, "DSRS: cannot open %s", path);
      return;
   }
   char line[256];
   while (fgets(line, sizeof(line), fp) && local_domain_count < MAX_LOCAL_DOMAINS)
   {
      /* Strip newline and whitespace */
      char *p = line;
      while (*p == ' ' || *p == '\t') p++;
      size_t len = strlen(p);
      while (len > 0 && (p[len-1] == '\n' || p[len-1] == '\r' ||
                         p[len-1] == ' '  || p[len-1] == '\t'))
         len--;
      if (len == 0 || p[0] == '#') continue;

      memcpy(local_domains[local_domain_count], p, len);
      local_domains[local_domain_count][len] = '\0';
      local_domain_count++;
   }
   fclose(fp);
   syslog(LOG_INFO, "DSRS: loaded %d local domains from %s",
          local_domain_count, path);
}

static int is_local_domain(const char *domain)
{
   for (int i = 0; i < local_domain_count; i++)
      if (strcasecmp(domain, local_domains[i]) == 0)
         return 1;
   return 0;
}

/* ================================================================
 * BERKELEY DB ACCESS (adapted from DarkSpam DB.c)
 * ================================================================ */

static DB *vut_dbp = NULL;    /* virtusertable.db */
static DB *ali_dbp = NULL;    /* aliases.db       */
static pthread_mutex_t db_mutex = PTHREAD_MUTEX_INITIALIZER;

static int db_load(DB **dbp_ptr, const char *path)
{
   DB *newdb = NULL;
   DB *old = NULL;
   int ret;

   if ((ret = db_create(&newdb, NULL, 0)) != 0)
   {
      syslog(LOG_ERR, "DSRS: db_create failed for %s: %s",
             path, db_strerror(ret));
      return -1;
   }

   ret = newdb->open(newdb, NULL, path, NULL, DB_HASH, DB_RDONLY, 0644);
   if (ret != 0)
   {
      syslog(LOG_ERR, "DSRS: db_open failed for %s: %s",
             path, db_strerror(ret));
      newdb->close(newdb, 0);
      return -1;
   }

   pthread_mutex_lock(&db_mutex);
   old = *dbp_ptr;
   *dbp_ptr = newdb;
   pthread_mutex_unlock(&db_mutex);

   if (old) old->close(old, 0);

   syslog(LOG_INFO, "DSRS: loaded %s", path);
   return 0;
}

/* Thread-safe lookup. Returns 1 if found (out filled), 0 if not, -1 on error.
 * Sendmail's newaliases stores keys with the null terminator included,
 * so if the first lookup (without null) fails, retry with strlen+1.
 */
static int db_lookup(DB *dbp, const char *key, char *out, size_t outsz)
{
   if (!dbp || !key) return -1;

   DBT s_key, s_value;
   memset(&s_key, 0, sizeof(s_key));
   memset(&s_value, 0, sizeof(s_value));

   s_key.data = (void *)key;
   s_key.size = strlen(key);

   pthread_mutex_lock(&db_mutex);
   int rc = dbp->get(dbp, NULL, &s_key, &s_value, 0);

   /* Retry with null terminator included (Sendmail convention) */
   if (rc == DB_NOTFOUND)
   {
      s_key.size = strlen(key) + 1;
      memset(&s_value, 0, sizeof(s_value));
      rc = dbp->get(dbp, NULL, &s_key, &s_value, 0);
   }

   if (rc == 0)
   {
      size_t cplen = s_value.size < outsz - 1 ? s_value.size : outsz - 1;
      memcpy(out, s_value.data, cplen);
      out[cplen] = '\0';
      pthread_mutex_unlock(&db_mutex);
      return 1;
   }
   pthread_mutex_unlock(&db_mutex);

   return (rc == DB_NOTFOUND) ? 0 : -1;
}

/* ================================================================
 * ALIAS EXPANSION CHECK
 *
 * Given a local RCPT TO (e.g. smista@itb.it):
 * 1. Look up in virtusertable.db → alias name (e.g. "smistiamo")
 * 2. Look up alias name in aliases.db → recipient list
 * 3. Parse list, check if any recipient has an external domain
 * ================================================================ */

static int has_external_recipients(const char *rcpt)
{
   char alias_name[MAX_ADDR] = "";
   char alias_value[MAX_ALIASES_VALUE] = "";
   int found;

   /* Step 1: virtusertable lookup */
   found = db_lookup(vut_dbp, rcpt, alias_name, sizeof(alias_name));
   if (DEBUG)
       syslog(LOG_INFO, "DSRS Step2: aliases lookup key='%s' found=%d value='%s'",
             rcpt, found, found == 1 ? alias_value : "(none)");
   if (found != 1)
   {
      /* Not in virtusertable — try the local part only
       * (some setups use just the local part as alias key)
       */
      const char *at = strchr(rcpt, '@');
      if (at)
      {
         char localpart[MAX_ADDR];
         int lp_len = (int)(at - rcpt);
         if (lp_len > (int)sizeof(localpart) - 1) lp_len = sizeof(localpart) - 1;
         memcpy(localpart, rcpt, lp_len);
         localpart[lp_len] = '\0';

         /* The alias might be the local part directly */
         found = db_lookup(ali_dbp, localpart, alias_value, sizeof(alias_value));
         if (DEBUG)
           syslog(LOG_INFO, "DSRS Step2: aliases lookup key='%s' found=%d value='%s'",
            localpart, found, found == 1 ? alias_value : "(none)");         if (found == 1)
            goto parse_aliases;
      }
      return 0;
   }

   /* Strip whitespace from alias name */
   char *p = alias_name;
   while (*p == ' ' || *p == '\t') p++;
   size_t len = strlen(p);
   while (len > 0 && (p[len-1] == ' ' || p[len-1] == '\t' ||
                      p[len-1] == '\n' || p[len-1] == '\0'))
      len--;
   if (len > 0)
   {
      memmove(alias_name, p, len);
      alias_name[len] = '\0';
   }

   syslog(LOG_DEBUG, "DSRS: virtusertable '%s' -> '%s'", rcpt, alias_name);

   /* Step 2: aliases lookup */
   found = db_lookup(ali_dbp, alias_name, alias_value, sizeof(alias_value));
   if (found != 1)
   {
      syslog(LOG_DEBUG, "DSRS: alias '%s' not found in aliases.db", alias_name);
      return 0;
   }

parse_aliases:
   syslog(LOG_DEBUG, "DSRS: alias expansion: '%s'", alias_value);

   /* Step 3: parse comma-separated list, check domains */
   char *saveptr = NULL;
   char *work = alias_value;
   char *token;

   while ((token = strtok_r(work, ",", &saveptr)) != NULL)
   {
      work = NULL;

      /* Trim whitespace */
      while (*token == ' ' || *token == '\t' || *token == '\n') token++;
      len = strlen(token);
      while (len > 0 && (token[len-1] == ' ' || token[len-1] == '\t' ||
                         token[len-1] == '\n'))
         len--;
      token[len] = '\0';

      if (len == 0) continue;

      /* Skip includes (:include:), pipes (|), files (/path) */
      if (token[0] == '/' || token[0] == '|' || token[0] == ':')
         continue;

      /* Extract domain */
      const char *at = strchr(token, '@');
      if (!at) continue;  /* local alias, no domain → local */

      const char *domain = at + 1;
      if (!is_local_domain(domain))
      {
         syslog(LOG_INFO, "DSRS: external recipient found in alias: %s", token);
         return 1;
      }
   }

   return 0;
}

/* ================================================================
 * PER-CONNECTION CONTEXT
 * ================================================================ */

struct context
{
   int  needs_rewrite;
   char mail_from[MAX_ADDR];
};

/* ================================================================
 * MILTER CALLBACKS
 * ================================================================ */

static sfsistat dsrs_connect(SMFICTX *ctx, char *hostname,
                             _SOCK_ADDR *sa)
{
   (void)hostname;
   (void)sa;

   struct context *ps = calloc(1, sizeof(*ps));
   if (!ps) return SMFIS_TEMPFAIL;
   smfi_setpriv(ctx, ps);

   return SMFIS_CONTINUE;
}

static sfsistat dsrs_envfrom(SMFICTX *ctx, char **argv)
{
   struct context *ps = (struct context *)smfi_getpriv(ctx);
   if (!ps) return SMFIS_TEMPFAIL;

   ps->needs_rewrite = 0;
   ps->mail_from[0] = '\0';

   if (argv[0])
   {
      const char *src = argv[0];
      char *dst = ps->mail_from;
      size_t max = sizeof(ps->mail_from) - 1;
      if (*src == '<') src++;
      size_t len = strlen(src);
      if (len > 0 && src[len - 1] == '>')
         len--;
      if (len > max) len = max;
      memcpy(dst, src, len);
      dst[len] = '\0';
   }

   return SMFIS_CONTINUE;
}

static sfsistat dsrs_envrcpt(SMFICTX *ctx, char **argv)
{
   struct context *ps = (struct context *)smfi_getpriv(ctx);
   if (!ps || !argv[0]) return SMFIS_CONTINUE;

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



   /* Se è già flaggato per la riscrittura, inutile fare altri controlli */
   if (ps->needs_rewrite) return SMFIS_CONTINUE;

   /* Estraiamo l'indirizzo pulito (senza parentesi angolari) */
   char rcpt[MAX_ADDR];
   const char *src = argv[0];
   if (*src == '<') src++;
   size_t len = strlen(src);
   if (len > 0 && src[len - 1] == '>') len--;
   if (len > sizeof(rcpt) - 1) len = sizeof(rcpt) - 1;
   memcpy(rcpt, src, len);
   rcpt[len] = '\0';

   /* Determiniamo se il dominio del destinatario è locale */
   int is_local = 0;
   const char *at = strchr(rcpt, '@');
   if (at) {
      is_local = is_local_domain(at + 1);
   } else {
      is_local = 1; /* Nessun dominio specificato (es. "root"), assumiamo locale */
   }

   if (!is_local) {
      /* Inoltro diretto verso l'esterno (SMTP relay) */
      ps->needs_rewrite = 1;
   } else {
      /* Consegna locale: controlliamo se l'alias punta all'esterno */
      if (has_external_recipients(rcpt)) {
         ps->needs_rewrite = 1;
      }
   }

   return SMFIS_CONTINUE;
}


static sfsistat dsrs_eom(SMFICTX *ctx)
{
   struct context *ps = (struct context *)smfi_getpriv(ctx);
   if (!ps) return SMFIS_CONTINUE;

   /* Conditions for SRS rewrite:
    * 1. needs_rewrite (esmtp recipient or alias with external)
    * 2. non-empty MAIL FROM (not a DSN)
    * 3. not already SRS0=
    * 4. sender domain differs from SRS_DOMAIN
    */
   if (!ps->needs_rewrite)
      return SMFIS_CONTINUE;
   if (ps->mail_from[0] == '\0')
      return SMFIS_CONTINUE;
   if (strncasecmp(ps->mail_from, "SRS0=", 5) == 0)
   {
      syslog(LOG_DEBUG, "DSRS: Already SRS, skip: %s", ps->mail_from);
      return SMFIS_CONTINUE;
   }

   const char *at = strchr(ps->mail_from, '@');
   const char *mf_domain = at ? at + 1 : "";
   if (mf_domain[0] == '\0')
      return SMFIS_CONTINUE;
   if (strcasecmp(mf_domain, SRS_DOMAIN) == 0)
      return SMFIS_CONTINUE;

   /* Build SRS0 address */
   char localpart[MAX_ADDR] = "";
   if (at)
   {
      int lp_len = (int)(at - ps->mail_from);
      if (lp_len > (int)sizeof(localpart) - 1)
         lp_len = sizeof(localpart) - 1;
      memcpy(localpart, ps->mail_from, lp_len);
      localpart[lp_len] = '\0';
   }

   unsigned int days = (unsigned int)(time(NULL) / 86400) % 1024;
   char tt[3];
   tt[0] = SRS_B32[(days >> 5) & 0x1f];
   tt[1] = SRS_B32[days & 0x1f];
   tt[2] = '\0';

   char mac_input[MAX_ADDR * 2];
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
                          hhh, tt, mf_domain, localpart, SRS_DOMAIN);

   if (nm_len < 0 || nm_len >= (int)sizeof(new_mailfrom))
   {
      syslog(LOG_NOTICE,
             "DSRS: SRS address too long (%d bytes). Skip.", nm_len);
      return SMFIS_CONTINUE;
   }

   syslog(LOG_INFO, "DSRS: Rewriting MAIL FROM: '%s' -> '%s'",
          ps->mail_from, new_mailfrom);

   if (smfi_chgfrom(ctx, new_mailfrom, NULL) == MI_FAILURE)
   {
      syslog(LOG_WARNING, "DSRS: smfi_chgfrom failed");
   }

   return SMFIS_CONTINUE;
}

static sfsistat dsrs_close(SMFICTX *ctx)
{
   struct context *ps = (struct context *)smfi_getpriv(ctx);
   if (ps)
   {
      free(ps);
      smfi_setpriv(ctx, NULL);
   }
   return SMFIS_CONTINUE;
}

/* ================================================================
 * MILTER DESCRIPTOR
 * ================================================================ */

static struct smfiDesc milter_desc =
{
   "DarkSRS",
   SMFI_VERSION,
   SMFIF_CHGFROM,
   dsrs_connect,
   NULL,               /* helo      */
   dsrs_envfrom,
   dsrs_envrcpt,
   NULL,               /* header    */
   NULL,               /* eoh       */
   NULL,               /* body      */
   dsrs_eom,
   NULL,               /* abort     */
   dsrs_close,
   NULL,               /* unknown   */
   NULL,               /* data      */
   NULL                /* negotiate */
};

/* ================================================================
 * MAIN
 * ================================================================ */

static void usage(const char *prog)
{
   fprintf(stderr, "Usage: %s [-u user] [-s socket]\n", prog);
   exit(1);
}

int main(int argc, char *argv[])
{
   const char *user = USER;
   const char *conn = OCONN;
   int c;

   while ((c = getopt(argc, argv, "u:s:")) != -1)
   {
      switch (c)
      {
         case 'u': user = optarg; break;
         case 's': conn = optarg; break;
         default:  usage(argv[0]);
      }
   }

   openlog("DarkSRS", LOG_PID | LOG_NDELAY, LOG_DAEMON);

   /* Load configuration */
   load_srs_secret(SRS_KEY_CONF);
   load_local_domains(LOCAL_DOMAINS_FILE);

   /* Open Berkeley DB files */
   if (db_load(&vut_dbp, VIRTUSERTABLE_DB) != 0)
      syslog(LOG_WARNING, "DSRS: virtusertable.db not available — "
             "alias expansion check disabled");
   if (db_load(&ali_dbp, ALIASES_DB) != 0)
      syslog(LOG_WARNING, "DSRS: aliases.db not available — "
             "alias expansion check disabled");

   /* Drop privileges */
   struct passwd *pw = getpwnam(user);
   if (pw)
   {
      setgid(pw->pw_gid);
      setuid(pw->pw_uid);
   }

   if (smfi_setconn((char *)conn) == MI_FAILURE)
   {
      syslog(LOG_ERR, "DSRS: smfi_setconn failed for %s", conn);
      return 1;
   }

   if (smfi_register(milter_desc) == MI_FAILURE)
   {
      syslog(LOG_ERR, "DSRS: smfi_register failed");
      return 1;
   }

   syslog(LOG_INFO, "DSRS: DarkSRS starting on %s, domain=%s, "
          "local_domains=%d, vut=%s, ali=%s",
          conn, SRS_DOMAIN, local_domain_count,
          vut_dbp ? "OK" : "N/A", ali_dbp ? "OK" : "N/A");

   return smfi_main();
}
