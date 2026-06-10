/*
 * dc_shared.h — Shared DKIM2-core structures for DarkChain/DarkChains
 *
 * Defines, data structures, and prototypes for functions shared
 * between the inbound verifier and outbound signer.
 *
 * Copyright (c) 2026 Vittorio Moccia / ITB.it
 * Licensed under Apache 2.0 License.
 */

#ifndef DC_SHARED_H
#define DC_SHARED_H

#include "dark_common.h"

/* ================================================================
 * DKIM2-CORE CHAIN LIMITS (from draft §2)
 * ================================================================ */

#define DC_MAX_HOPS          15     /* Maximum i= value                      */
#define DC_MAX_RT           500     /* Maximum RCPT TO per hop               */
#define DC_MAX_SEQ           20     /* Maximum seq= per hop for DKIM2-Mod    */
#define DC_MAX_FR             2     /* Maximum fr= frames per Mod entry      */
#define DC_MAX_MOD          400     /* Maximum DKIM2-Mod headers in hop index */
#define DC_MAX_ADDR         256     /* Max length of an addr-spec            */
#define DC_MAX_EXTRACTED     64     /* Max addresses extracted from To:/Cc:  */
#define DC_RCPT_INITIAL      16     /* Starting allocation for rcpt_to       */

/* Header reservoir limits */
#define MAX_HEADER_COUNT    800     /* Hard ceiling for DoS protection       */
#define INITIAL_CAPACITY    100     /* Starting allocation for header slots  */

/* Header hash exclusion list */
#define DC_HH_MAX_EXCLUDE    64

/* ================================================================
 * DKIM2 HEADER TYPE CODES
 * ================================================================ */

#define DC_HDR_OTHER          0     /* Any non-DKIM2 header                  */
#define DC_HDR_SIG            1     /* DKIM2-Signature                       */
#define DC_HDR_MF             2     /* DKIM2-Sig-mf                          */
#define DC_HDR_RT             3     /* DKIM2-Sig-rt                          */
#define DC_HDR_MOD            4     /* DKIM2-Mod                             */

/* ================================================================
 * DATA STRUCTURES
 * ================================================================ */

/*
 * header_slot — flat storage for every header in the message.
 */
struct header_slot
{
   char name[MAX_HEADER_NAME];
   char value[BIG_HEADER_VALUE];
   int  used_for_signature;     /* Flag: already consumed by h= walk     */
   int  dc_type;                /* DC_HDR_* code, 0 for non-DKIM2        */
   int  hop;                    /* i= value, 0 if not DKIM2              */
   int  v;                      /* v= for DKIM2-Sig-rt, 0 otherwise      */
   int  seq;                    /* seq= for DKIM2-Mod, 0 otherwise       */
   int  fr;                     /* fr= for DKIM2-Mod, 0 otherwise (1-based) */
   int  is_new;                 /* 1 if DKIM2-Mod with new=, 0 if del=   */
};

/*
 * dc_envelope — SMTP envelope captured during the session.
 */
struct dc_envelope
{
   char  mail_from[DC_MAX_ADDR];         /* MAIL FROM addr-spec           */
   char (*rcpt_to)[DC_MAX_ADDR];         /* RCPT TO addr-specs (dynamic)  */
   int   rcpt_count;                     /* How many RCPT TO we've seen   */
   int   rcpt_capacity;                  /* Current allocation size       */
};

/*
 * dc_hh_exclude — Header hash exclusion pattern.
 */
struct dc_hh_exclude
{
   char  pattern[MAX_HEADER_NAME];
   int   is_prefix;     /* 1 if pattern ends with '-' */
   int   match_len;     /* length to compare           */
};

/* ================================================================
 * DKIM2-SPECIFIC TAG PARSING — dc_shared.c
 * ================================================================ */

const char *dc_find_tag(const char *header_value, const char *tag);
int  dc_get_hop_index(const char *header_value);
int  dc_get_tag_int(const char *header_value, const char *tag);
void dc_get_tag_str(const char *header_value, const char *tag,
                    char *out, size_t out_len);

/* Highest i= among DKIM2-Signature headers only (0 if none, -1 on a
 * chain gap).  Authoritative source for the next signing hop index,
 * grounded in the spec's contiguous-chain rule. */
int  dc_max_sig_hop(const struct header_slot *headers, int header_cnt);

/* ================================================================
 * ENVELOPE UTILITIES — dc_shared.c
 * ================================================================ */

void dc_strip_angle_brackets(const char *src, char *dst, size_t dst_len);
void dc_get_addr_tag(const char *header_value, char *out, size_t out_len);
void dc_normalize_addr(const char *addr, char *out, size_t out_len);
int  dc_addr_match(const char *a, const char *b);
int  dc_relaxed_domain_match(const char *d_domain, const char *mf_addr);

/* ================================================================
 * HEADER HASH (hh=) — dc_shared.c
 * ================================================================ */

void load_hh_excludes(const char *path);
int  dc_is_hh_excluded(const char *name);
char *dc_compute_hh(struct header_slot *headers, int header_cnt);
int   dc_extract_addresses(const char *hdr, char addrs[][DC_MAX_ADDR], int max_addrs);
int  dc_is_single_field(const char *name);
int  cmp_canon_value(struct header_slot *a, struct header_slot *b);
int  cmp_header_hh(const void *a, const void *b);
int  cmp_mod_canonical(const void *a, const void *b);
int  cmp_rt_by_v(const void *a, const void *b);

/* ================================================================
 * EXTERN GLOBALS — defined in dc_shared.c
 * ================================================================ */

extern struct dc_hh_exclude hh_excludes[];
extern int hh_exclude_count;
extern const char *hh_default_excludes[];
extern const char *hh_single_fields[];

#endif /* DC_SHARED_H */
