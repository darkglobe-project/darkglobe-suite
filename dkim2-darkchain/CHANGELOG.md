# Changelog DarkChain / DarkChains (DKIM2)


## [0.5 - 30/06/2026]

## [Unreleased]

### Postfix compatibility (Case A)
The signer's hop-classification no longer keys Case A (inbound/relay) on the
connection origin (`is_localhost`). When a message is re-injected through a
loopback cascade â€” as required on Postfix to apply SRS before signing â€” the
client address is always `127.0.0.1`, which previously misclassified relayed
mail as locally originated. Case A is now driven by the presence of a verifier
verdict, so a message that carries one is treated as relay regardless of the
connecting IP. This makes the two-stage Postfix cascade behave like the
single-pass Sendmail path.

### DKIM2-Authentication-Results: gate on domain table
The verifier no longer injects a `DKIM2-Authentication-Results` header for
domains that are not DKIM2-enabled on this host. The verifier now loads the
shared domain table (`/etc/DarkChain/domains.conf`, typically a symlink to the
signer's `/etc/DarkChains/domains.conf`) and injects the AR record only when the
recipient domain is present in it.

### DSN / null sender (mf=)
When a message is a DSN (Delivery Status Notification) the envelope sender is
empty (`<>`), as mandated by RFC 5321 to prevent bounce loops. The verifier
treats an empty `mf=` as legitimate: envelope-sender alignment is skipped rather
than failed, so a null-sender DSN is not rejected on alignment grounds.


## [0.4 - 16/06/2026]

### Refactored

- **Improved the lookup logic** against the DKIM2 signed domains table, covering both inbound chains (under NOLOCALSIGN=0 conditions) and outbound traffic.

### Removed

- **Dropped the implicit fallback/default case** that resolved to the host server's local domain name. Lookups are now strictly explicit.

## [0.3 - 13/06/2026]

### Added

- **Enforcement mode (verifier).** `#define ENFORCE 0|1` controls whether
  the verifier rejects messages on DKIM2 failure. When `ENFORCE=1`:
  `dkim2=fail` or `dkim2=permerror` → `550 5.7.1` (REJECT);
  `dkim2=temperror` → `451 4.7.1` (TEMPFAIL). Default is 0 (log-only,
  transitional mode). DKIM2-Authentication-Results and
  X-DarkChain-Internal-Status are always injected before the
  reject/tempfail decision, preserving observability.

- **Version trace updated.** X-Signed header now reports `DarkChain 0.3`.

## [0.2 - 10/06/2026]

## [unreleased] — Security hardening pass

Security and robustness review of the DarkChain (inbound verifier) and
DarkChains (outbound signer) milters. No change to the wire format or to
the transitional log-only operating mode; all changes are defensive.

### Security

- **Case B verdict selection anchored to the previous signed hop (signer).**
  The DKIM2-Authentication-Results record from which the propagated verdict
  is taken is now selected by matching `i = N-1` (the previous hop's signed
  level, where N = highest DKIM2-Signature index + 1) instead of the highest
  `i=` found among AR records. In Case B the prior AR is emitted by the
  pre-list signer at level N-1, while a DKIM2-Mod sits at level N; anchoring
  to the highest AR `i=` (an unsigned, injectable field) or to max_prev_hop
  (= N) would pick the wrong record. New behaviour at level N-1: no AR →
  `none`; all agree → that verdict; disagreement → `fail`;
  malformed/unrecognized `dkim2=` → `none`.

- **Authoritative signing-hop index via `dc_max_sig_hop()` (shared).** New
  helper in dc_shared.c returns the highest `i=` among DKIM2-Signature
  headers only (0 if none, -1 on a chain gap), reading the already-parsed
  dc_type/hop fields without re-parsing. Case B now derives `N` from this
  helper instead of the signature count, removing the ambiguity between a
  count and a max when Mods are present. The helper carries its own
  lightweight contiguity pass because the post-list signer path is not
  covered by the inbound verifier's dc_eoh chain-continuity check; on a gap
  (unsigned per the profile) the signer logs and does not sign.

- **Tag-boundary-aware `b=` location in canonicalization (libdark).**
  `canonicalize_sig_for_verify()` and `prepare_header_for_hash()` no longer
  use `strstr("b=")` with a single-character guard, which could zero out the
  wrong region when `b=` appeared inside another tag's value. A shared
  `dc_find_b_value()` helper now requires the tag to start at the value head
  or after `;`/WSP and to be followed by `=`, matching `dc_find_tag()`
  semantics.

### Robustness / memory safety

- **Rollback scratch moved off the stack (verifier).** `dc_rollback_hh()`
  previously placed a `DC_MAX_SEQ`-entry `header_slot` array (~128 KB) on the
  stack, risking stack overflow on worker threads with small stacks. The
  buffer is now allocated once per connection in `dc_connect()`, reused for
  every message, and freed in `dc_close()`. The signer is unaffected.

- **Scratch pointer/index arrays made thread-local.** The `ptrs`/`sort_keys`
  arrays in `dc_compute_hh()` (shared) and `work`/`sort_keys` in
  `dc_rollback_hh()` (verifier) are now `static __thread`, keeping them off
  the call frame without locking (libmilter uses one thread per connection).

- **Bounds guards on header-accumulation buffers.** Both the verifier
  (`FEED_DATA`, Ed25519 path) and the signer (`APPEND_CANON`) now check the
  remaining space before each `memcpy` into the signing-input buffer and bail
  with `SMFIS_TEMPFAIL` / `temperror` instead of risking a heap overflow.

- **OpenSSL init return values checked (verifier).** `EVP_DigestVerifyInit`
  (Ed25519) and `EVP_PKEY_verify_init` / `EVP_PKEY_CTX_set_rsa_padding` /
  `EVP_PKEY_CTX_set_signature_md` (RSA) return values are now validated;
  failure is treated as verification failure (fail-closed).

### Changed

- **Canonical SRS0 forward-path rewrite (signer).** Relay envelope rewriting
  now emits a canonical `SRS0=HHH=TT=domain=local@signing` address: `TT` is
  the day count mod 1024 in base32, `HHH` is HMAC-SHA1 truncated to 4 base32
  chars. The HMAC secret is loaded from `/etc/DarkChains/srs.key` if present;
  when absent the address remains well-formed and routable but carries no
  forge-resistance (acceptable when inbound bounce SRS is not validated).
  Replaces the previous ad-hoc keyless SHA-256 hex scheme.

### Notes

- Open item not addressed here: the signer honours `X-DarkChain-Internal-Status`
  (hop/verdict handoff) across the verifier→signer boundary without an
  `is_localhost` gate or authentication. Deferred pending review of how the
  hop index is generated in multi-node topologies.
