# DarkChain / DarkChains (DKIM2)

**Quick take:** a DKIM2 core verifier (DarkChain) and signer (DarkChains) milter pair, in C. Drop-in for Sendmail or Postfix via standard milter sockets - no MTA changes, no JSON, no persistent state. Running in production today, log-only by default, enforcement mode behind a single compile flag.

- 5-minute setup: build, point the MTA at the socket, done
- Tested live with Microsoft Exchange Online and Google MTA traffic
- Not a full DKIM2 implementation - see [Specification](#specification) for what this profile covers

---

- ✅ Stateless milter
- ✅ Streaming (no body buffering)
- ✅ No MTA core changes required
- ✅ Tested with Sendmail
- ⚠️ Looking for Postfix testing / feedback

This is not an official DKIM2 implementation, but a practical, running implementation of a deployable core profile.

## Quick start

```bash
# Build
cd dkim2-darkchain/verify && make && cd ../sign && make

# Socket directories
mkdir -p /var/spool/DarkChain /var/spool/DarkChains
chown smmsp:smmsp /var/spool/DarkChain /var/spool/DarkChains

# Signer config (required): domain, selector, private key path
mkdir -p /etc/DarkChains
echo "yourdomain.tld  dkim2  /etc/DarkChains/yourdomain.tld.private" > /etc/DarkChains/domains.conf
openssl genrsa -out /etc/DarkChains/yourdomain.tld.private 2048

# Publish the public key in DNS (copy the output into a TXT record)
echo -n 'v=DKIM1; k=rsa; p=' && openssl rsa -in /etc/DarkChains/yourdomain.tld.private -pubout -outform DER | openssl base64 -A
# dkim2._domainkey.yourdomain.tld  IN TXT  "v=DKIM1; k=rsa; p=<paste above>"

# Run
su -c "/usr/local/sbin/DarkChain &" -s /bin/sh - smmsp
su -c "/usr/local/sbin/DarkChains &" -s /bin/sh - smmsp
```

Add the milter sockets to `sendmail.mc` (see [Sendmail configuration](#sendmail-configuration) below), reload, and you are running. The verifier is log-only by default - no message is ever rejected until enforcement mode is explicitly enabled (see [Operating Mode](#operating-mode)).

Full configuration, pipeline ordering, key rotation, and enforcement details are in the sections below.

---

## What this is

DarkChain and DarkChains implement the DKIM2-core deployment profile defined in `draft-moccia-dkim2-deployment-profile-04`. They run as standard milter processes alongside any MTA that supports the milter protocol - Sendmail, Postfix, or any compatible MTA - without requiring modifications to MTA core software or configuration beyond the milter socket definition.

The implementation is in C, built on libmilter, and follows the Unix principle of doing one thing correctly: DarkChain verifies, DarkChains signs. Both are stateless within a single message transaction and impose no persistent state requirements on the host system.

## What DKIM2-core provides

DKIM2-core addresses the three fundamental weaknesses of DKIM1 that have made email authentication fragile in indirect mail flows:

**Envelope binding.** Every DKIM2-core signature cryptographically binds the MAIL FROM and each RCPT TO of the SMTP transaction to the signed message. A message replayed to a recipient not listed in the original signature produces a verifiable mismatch. Replay to a different address at the same domain is detected - a gap that domain-level binding approaches cannot close.

**Chain of custody.** Each hop in the delivery path verifies the previous signature before adding its own. The result is a mathematically verifiable transit record: not a reputational assertion that a trusted party handled the message, but a cryptographic proof that a specific identifiable domain handled this specific message to these specific recipients. The chain is validated in real time during transit, not reconstructed after the fact at the final receiver.

**Header accountability.** Modifications to header fields are declared by the modifying hop via DKIM2-Mod, signed with the modifier's key. An intermediary that adds or removes a header must declare it or break the chain. The optional hh= tag extends this to the full non-excluded header set, enabling each hop to verify cryptographically that its predecessor declared all modifications it made. The hh= mechanism has the same security model as bh= for the body: the hash is signed within the DKIM2-Signature and cannot be altered without invalidating the signature.

**Operational transparency.** All DKIM2-core fields - envelope binding, modification declarations, chain of custody records - are in cleartext tag-value format. They are directly readable in mail logs and headers without specialised tooling. This is not a minor convenience: it is a prerequisite for operational diagnostics, incident response and real-time threat detection at MTA level.

## What DKIM2-core does not require

DKIM2-core does not require body reconstruction. Each hop signs the body hash of the message as it receives it. Body modifications are detected via bh= changes between consecutive signatures, identifying the modifying hop. The chain of custody and envelope binding are fully verifiable without reconstructing the message body at any hop.

DKIM2-core does not require JSON, base64-encoded recipe payloads or multi-kilobyte header fields. A standard DKIM2-core message header set is comparable in size to a DKIM1 + ARC signed message. Header overhead scales with the number of hops and declared modifications, not with message body size.

DKIM2-core does not require MTA modifications. The entire profile is implementable at the milter layer. The MTA presents the SMTP envelope to the milter via standard callbacks; the milter constructs the signature headers and injects them into the message. No MTA source changes, no custom SMTP extensions, no out-of-band signalling.

DKIM2-core does not require trust in intermediaries. The chain self-validates: each honest hop verifies its predecessor before signing. A modification introduced without declaration breaks the chain at the next honest verifying hop, not at the final receiver.

## Architecture

```
darkglobe-suite/
├── libdark/          - shared crypto, canonicalization, utilities (MIT)
└── dkim2-darkchain/
    ├── dc_shared.*   - shared DKIM2-core logic
    ├── verify/
    │   └── DarkChain.c    - inbound verifier milter
    └── sign/
        └── DarkChains.c   - outbound signer milter
```

DarkChain and DarkChains share signing and verification logic via `dc_shared`. They are built separately and run as independent processes, insertable at any point in the MTA's milter pipeline.

## Deployment

DarkChain and DarkChains are in active beta on production mail infrastructure, processing live traffic including messages from Microsoft Exchange Online and messages relayed through Google's MTA infrastructure.

DKIM2-core headers generated by DarkChains are present in messages posted to the IETF DKIM working group mailing list, where they transit through the IETF mail infrastructure and are signed by Google's ARC implementation without any coordination or configuration. This confirms that DKIM2-core headers are recognized as structural authentication metadata by production infrastructure at scale, with no changes required on the receiving side.

The Google ARC implementation signs DKIM2-core headers as part of its standard defensive signing behaviour, providing an additional layer of protection for the DKIM2 chain without any Google-side configuration.

The implementation follows the incremental deployment path defined in the deployment profile: monitoring mode first, enforcement when the deployment boundary is sufficiently covered.

## Installation

DarkChain and DarkChains are milter processes. They require no MTA core modifications: the MTA communicates with them via Unix domain sockets using the standard milter protocol.

### Build

```bash
cd dkim2-darkchain/verify && make
cd dkim2-darkchain/sign && make
```

Both binaries link against libmilter and libdark. See `libdark/` for build instructions.

### Pipeline position

DarkChain and DarkChains must be positioned correctly in the milter pipeline relative to other authentication components. The correct order reflects the verification sequence: verify first on inbound, sign last on outbound.

A complete inbound pipeline processes messages in this order:

1. SPF verification
2. DKIM1 verification (OpenDKIM)
3. DMARC verification (OpenDMARC)
4. ARC verification (DarkARC)
5. **DKIM2-core verification (DarkChain)**
6. Content filtering (DarkSpam or equivalent)

Signing milters follow content filtering, so they see the final form of the message:

7. ARC signing (DarkARCs)
8. **DKIM2-core signing (DarkChains)**

DarkChain runs on inbound only. DarkChains runs on outbound only. Both can be declared in the same MTA configuration - the milter protocol and MTA routing logic handle the separation.

## Configuration

### Verifier (DarkChain)

```bash
mkdir -p /etc/DarkChain
mkdir -p /var/spool/DarkChain
chown smmsp:smmsp /var/spool/DarkChain
```

**`/etc/DarkChain/hh_exclude.conf`** (optional) — additional header names
to exclude from the `hh=` header hash. One per line. Lines ending with `-`
are prefix matches. Structural exclusions (`Received`, `Return-Path`,
`Authentication-Results`, `DKIM-Signature`, `DKIM2-`, `ARC-`) are always
applied regardless of this file.

### Example: exclude all X-* and Message-Instance

```bash
X-
Message-Instance
```

If the file is absent, only the built-in exclusions apply.

**`/etc/DarkChain/domains.conf`** (recommended) — the list of DKIM2-enabled
domains served by this host. The verifier injects a
`DKIM2-Authentication-Results` header **only** when the recipient domain is
present in this table. This prevents a non-DKIM2 domain that is co-hosted with
a DKIM2 domain (for example a mailing-list domain) from emitting a spurious
`dkim2=none` record: the DKIM2 chain correctly begins at the first
DKIM2-enabled hop.

The verifier reads the same table as the signer and uses only the domain name
field (it never needs the keys). Keep a single source of truth with a symlink:

```bash
ln -s /etc/DarkChains/domains.conf /etc/DarkChain/domains.conf
```

If the file is absent, the table is empty and the verifier injects no
`DKIM2-Authentication-Results` records.

### Signer (DarkChains)

```bash
mkdir -p /etc/DarkChains
mkdir -p /var/spool/DarkChains
chown smmsp:smmsp /var/spool/DarkChains
```

**`/etc/DarkChains/domains.conf`** (required) — domain-to-key mapping,
one line per domain. Format: `domain  selector  /path/to/private.key`

```
itb.it          dkim2  /etc/DarkChains/itb.it.private
pacedisarmo.org dkim2  /etc/DarkChains/pacedisarmo.org.private
```

The signer looks up the MAIL FROM domain in this table. If no match is
found (including up to two subdomain levels), the message is not signed.
Private keys must be readable by the milter process (user `smmsp` after
privilege drop).

**`/etc/DarkChains/hh_exclude.conf`** (optional) — same format and
behavior as the verifier's file. Both milters should use the same
exclusion list to ensure `hh=` values match.

**`/etc/DarkChains/srs.key`** (optional) - SRS key generation
openssl rand -base64 32 > /etc/DarkChains/srs.key
chmod 600 /etc/DarkChains/srs.key

### Sendmail configuration

Add to `sendmail.mc`, DarkChain **before** DarkChains in the milter chain. Adjust macro definitions as needed for your environment:

```m4
define(`confMILTER_MACROS_CONNECT',
  `{client_addr}, {client_name}, {client_ptr}, {j}, {daemon_name}, {auth_type}')
define(`confMILTER_MACROS_ENVFROM',
  `i, {auth_type}, {auth_authen}, {auth_ssf}, {auth_author},
   {mail_addr}, {mail_host}, {mail_mailer}')
define(`confMILTER_MACROS_ENVRCPT',
  `{rcpt_addr}, {rcpt_host}, {rcpt_mailer}')
define(`confMILTER_MACROS_EOM', `{msg_id}')

dnl # Inbound verification pipeline (order matters)
INPUT_MAIL_FILTER(`smf-spf',
  `S=unix:/var/run/smfs/smf-spf.sock, T=S:30s;R:1m')
INPUT_MAIL_FILTER(`opendkim',
  `S=local:/run/opendkim/opendkim.sock')
INPUT_MAIL_FILTER(`opendmarc',
  `S=local:/run/opendmarc/opendmarc.sock, F=T')
INPUT_MAIL_FILTER(`DarkARC',
  `S=unix:/var/spool/DarkARC/sock, T=S:30s;R:2m')
INPUT_MAIL_FILTER(`DarkChain',
  `S=unix:/var/spool/DarkChain/sock, T=S:30s;R:2m')
INPUT_MAIL_FILTER(`DarkSpam',
  `S=unix:/var/spool/DarkSpam/sock, T=S:30s;R:2m')

dnl # Outbound signing pipeline (after content filtering)
INPUT_MAIL_FILTER(`DarkARCs',
  `S=unix:/var/spool/DarkARCs/sock, T=S:30s;R:2m')
INPUT_MAIL_FILTER(`DarkChains',
  `S=unix:/var/spool/DarkChains/sock, T=S:30s;R:2m')
```

After modifying `sendmail.mc`, rebuild and reinstall `sendmail.cf`:

```bash
m4 sendmail.mc > sendmail.cf
systemctl reload sendmail
```

### Socket directories

Each milter expects its socket directory to exist before startup:

```bash
mkdir -p /var/spool/DarkChain /var/spool/DarkChains
chown smmsp:smmsp /var/spool/DarkChain /var/spool/DarkChains
```

## Running scripts

### Signer

```bash
PIDFILE="/var/run/darkchains.pid"
pgrep -x DarkChains >/dev/null && { echo "DarkChains already running"; exit 1; }
su -c "/usr/local/sbin/DarkChains &" -s /bin/sh - smmsp
sleep 1
pgrep -x DarkChains > "$PIDFILE"
```

### Verifier

```bash
PIDFILE="/var/run/darkchain.pid"
pgrep -x DarkChain >/dev/null && { echo "DarkChain already running"; exit 1; }
su -c "/usr/local/sbin/DarkChain &" -s /bin/sh - smmsp
sleep 1
pgrep -x DarkChain > "$PIDFILE"
```

### Key generation

```bash
# RSA-2048
openssl genrsa -out /etc/DarkChains/itb.it.private 2048
openssl rsa -in /etc/DarkChains/itb.it.private -pubout -outform DER | openssl base64 -A
```

Publish the base64 public key as a DNS TXT record:

```
dkim2._domainkey.itb.it  IN TXT "v=DKIM1; k=rsa; p=<base64 public key>"
```

### DNS

DarkChains requires a DKIM2 signing key published in DNS. Key format and selector configuration follow the conventions of the DKIM2 base specification. See `dkim2-darkchain/sign/README.md` for key generation and DNS record format.

## Specification

This implementation follows `draft-moccia-dkim2-deployment-profile-04`.

It does not implement `draft-ietf-dkim-dkim2-spec` directly. The deployment profile defines a milter-implementable subset with explicit architectural choices documented in the profile document, including the rationale for those choices where they differ from or extend the base specification.

## Operating Mode

DarkChain currently operates in **transition mode** (log-only) by default:

- All verification results are logged via syslog and injected as
  `DKIM2-Authentication-Results` headers
- No message is rejected — both milters return `SMFIS_CONTINUE`
- The `X-DarkChain-Internal-Status` header provides timing and diagnostics
  (removed before delivery by the signer)

To switch to **enforcement mode**, set `#define ENFORCE 1` in
`DarkChain.c` and recompile. When enabled:

- `dkim2=fail` or `dkim2=permerror` → `550 5.7.1` REJECT
- `dkim2=temperror` → `451 4.7.1` TEMPFAIL
- Per draft §3.5.1, the rejection targets the connected peer — never
  the original sender — preventing backscatter

Authentication headers are always injected before the reject decision,
preserving full observability in logs.

The signer (`DarkChains.c`) always returns `SMFIS_CONTINUE` — it signs
outbound mail but never rejects.

## License

DarkChain and DarkChains are released under the Apache License 2.0.

## Author

Vittorio Moccia
