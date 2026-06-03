/*
 * dark_common.h — Shared header for DarkGlobe Suite
 *
 * Prototypes, includes, and constants shared between DarkChain
 * (inbound verifier) and DarkChains (outbound signer).
 *
 * Copyright (c) 2026 Vittorio Moccia / ITB.it
 * Licensed under the MIT License.
 */

#ifndef DARK_COMMON_H
#define DARK_COMMON_H

#include <libmilter/mfapi.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <netinet/in.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <grp.h>
#include <arpa/inet.h>
#include <stdbool.h>

/* ================================================================
 * BUFFER SIZE CONSTANTS
 * ================================================================ */

#define MAXHOST            2000
#define MAX_HEADER_NAME     200
#define MAX_HEADER_VALUE   2048
#define BIG_HEADER_VALUE   6144
#define BIG_BUFFER         4096
#define BODY_BUF_SIZE     32768
#define MAX_PUB_KEY        1024
#ifndef EVP_MAX_MD_SIZE
#define EVP_MAX_MD_SIZE      64
#endif

/* ================================================================
 * STRING UTILITIES — dark_string.c
 * ================================================================ */

long securecpy(register char *pc_dst, register const char *pc_src, long l_sizeof);
long securecat(register char *pc_dst, register const char *pc_src, long l_sizeof);
void trim(char *s);
void unfold_header(char *h);
void strip_whitespace(char *s);

/* ================================================================
 * HEADER CANONICALIZATION — dark_canon.c
 * ================================================================ */

int canonicalize_header_relaxed(const char *name, const char *value,
                                char *out, size_t out_max, int add_crlf);
int canonicalize_sig_for_verify(const char *name, const char *value,
                                char *out, size_t out_max);
void prepare_header_for_hash(char *header_val);

/* ================================================================
 * CRYPTO / BASE64 / DNS — dark_crypto.c
 * ================================================================ */

char *encode_base64_hash(const unsigned char *bin_data, int bin_len);
int   decode_base64_to_buf(const char *base64_key, unsigned char *out_buf, int out_len);
int   decode_base64_sig(const char *base64_sig, unsigned char *out_bin, int out_len);
EVP_PKEY *decode_dns_key(const char *base64_key, bool is_ed25519);
int   get_dns_arc_pubkey(const char *d, const char *s, char *pubkey_out, size_t out_len);
EVP_PKEY *load_private_key(const char *path);

/* ================================================================
 * TIMING — dark_util.c
 * ================================================================ */

void format_runtime(unsigned long long total_ns, char *dest, size_t destlen);

static inline unsigned long long diff_ns(struct timespec start, struct timespec end)
{
   return (unsigned long long)(end.tv_sec - start.tv_sec) * 1000000000ULL
        + (end.tv_nsec - start.tv_nsec);
}

#endif /* DARK_COMMON_H */
