# DarkARC / DarkARCs

ARC (RFC 8617) verifier and signer milters for production mail infrastructure.

## What this is

DarkARC and DarkARCs implement ARC — Authenticated Received Chain — as a pair
of standard milter processes. They run alongside any MTA that supports the
milter protocol (Sendmail, Postfix, or any compatible MTA) without requiring
modifications to MTA core software or configuration beyond the milter socket
definition.

The implementation is in C, built on libmilter, and follows the Unix principle
of doing one thing correctly: **DarkARC verifies, DarkARCs signs.** The two
phases are logically separated into two distinct processes. This separation is
not a packaging detail — it is the design decision that makes the
implementation correct in both directions, and it is precisely where the
existing ARC implementations fall short.

## Why a new ARC implementation

ARC is conceptually simple but unforgiving in practice: an implementation that
canonicalizes a header one byte differently from the signer, or that conflates
the inbound verification path with the outbound sealing path, produces chains
that fail to validate against real-world mail. The two widely available
implementations both have problems that DarkARC was written to avoid.

**OpenARC does not validate Microsoft's ARC chains.** ARC sets sealed by
Microsoft Exchange Online consistently fail validation under OpenARC, even
when the chains are well-formed and validate elsewhere — in practice it has
never been possible to get OpenARC to accept a Microsoft-sealed chain. OpenARC
is old, poorly maintained code, and a verifier that cannot validate one of the
two largest ARC sealers in existence is not usable as an inbound
authentication component.

**rspamd has stability and architectural problems.** On certain configurations
rspamd's ARC handling crashes (core dump), which is unacceptable for a
component sitting in the inbound mail path. Beyond stability, rspamd does not
cleanly separate the inbound verification chain from the outbound signing
chain — the two phases are entangled, which is the root cause of much of the
ambiguity in how it treats a message that is both received and re-sent.

DarkARC separates the two phases at the process level. The verifier only
verifies; the signer only signs. There is no shared mutable state between the
two, and no code path where a verification decision can leak into a signing
decision or vice versa.

## Interoperability

DarkARC is in active use on production mail infrastructure and interoperates
without issue with the ARC chains produced by **Google** and **Microsoft** —
both as a verifier of their inbound seals and as a signer whose seals are
accepted downstream. These are the two implementations that matter most in
practice, and they are also the two that expose the canonicalization and
chain-handling edge cases most aggressively.

## Architecture

```
darkglobe-suite/
├── libdark/          - shared crypto, canonicalization, utilities (MIT)
└── darkarc/
    ├── DarkARC.c     - inbound verifier milter
    └── DarkARCs.c    - outbound signer milter
```

DarkARC and DarkARCs share their cryptographic, canonicalization and string
utilities through `libdark`. They are built separately and run as independent
processes.

DarkARC runs on inbound only: it validates the ARC chain (ARC-Seal,
ARC-Message-Signature, ARC-Authentication-Results) of received mail and records
the result in an internal status header that downstream components can consume.
DarkARCs runs on outbound: it adds a new ARC set, sealing the chain so that the
authentication state assessed on receipt survives onward relaying — the case
ARC exists to solve, where a message passes through an intermediary (a mailing
list, a forwarder) that breaks SPF and DKIM alignment.

## Pipeline position

Placement in the milter pipeline is critical for ARC to work correctly.

**DarkARC (verifier)** goes at the **end of the inbound chain** — it must run
after SPF, DKIM1 and DMARC so that it can seal their results into the
ARC-Authentication-Results. If DKIM2 (DarkChain) is also deployed, DarkARC runs
**immediately before** DarkChain.

**DarkARCs (signer)** goes **last in the outbound chain** — or **second to
last** if DKIM2 (DarkChains) is deployed, in which case DarkChains is last
(DKIM2 signs over the final state, ARC seal included).

```
Inbound:   SPF → DKIM1 → DMARC → DarkARC [→ DarkChain] → content filter
Outbound:  DarkARCs [→ DarkChains]
```

(Brackets denote the optional DKIM2 components. Without DKIM2, DarkARC is last
inbound and DarkARCs is last outbound.)

## Installation

DarkARC and DarkARCs are milter processes. They require no MTA core
modifications: the MTA communicates with them via Unix domain sockets using the
standard milter protocol.

### Source configuration

A few values are compiled in via `#define` and must be set for your
environment before building.

**DarkARCs.c (signer):**

```c
#define MY_SERVER  "dns2.itb.it"   /* this host's name */
#define DOMAIN     "itb.it"        /* the related signing domain */
```

**DarkARC.c (verifier):**

```c
#define MY_DOMAIN  "dns.itb.it"    /* this host's name (authserv-id) */
```

Socket paths (`OCONN`), the privilege-drop user (`USER`/`SDUSER`) and the
signer's key path and selector (`SSLPATH`, `SELETTORE`) are also `#define`d and
can be adjusted if your layout differs from the defaults below.

### Build

```bash
cd darkarc && make
```

Both binaries link against libmilter and libdark.

### Key

DarkARCs seals the ARC chain with a **single RSA key**. There is no
multi-domain table: one host, one ARC key.

```bash
mkdir -p /etc/DarkARCs
openssl genrsa -out /etc/DarkARCs/arc1.private 2048
chown smmsp:smmsp /etc/DarkARCs/arc1.private
chmod 600 /etc/DarkARCs/arc1.private
```

The key path and selector are compiled in:

```c
#define SSLPATH    "/etc/DarkARCs/arc1.private"
#define SELETTORE  "arc1"
```

Publish the public key in DNS as the ARC selector for your domain:

```bash
openssl rsa -in /etc/DarkARCs/arc1.private -pubout -outform DER | openssl base64 -A
```

```
arc1._domainkey.itb.it  IN TXT  "v=DKIM1; k=rsa; p=<base64 public key>"
```

> **Note:** the current release signs and verifies RSA only. Ed25519 support is
> planned but not yet implemented.

### Socket directories

Each milter expects its socket directory to exist before startup:

```bash
mkdir -p /var/spool/DarkARC /var/spool/DarkARCs
chown smmsp:smmsp /var/spool/DarkARC /var/spool/DarkARCs
```

### Sendmail integration

Add the following to your `sendmail.mc`. The milter macros must be exported so
the milters can read the SMTP envelope and connection data; the
`INPUT_MAIL_FILTER` order reflects the pipeline position described above.

```m4
define(`confMILTER_MACROS_CONNECT',
  `{client_addr}, {client_name}, {client_ptr}, {j}, {daemon_name}, {auth_type}')
define(`confMILTER_MACROS_ENVFROM',
  `i, {auth_type}, {auth_authen}, {auth_ssf}, {auth_author},
   {mail_addr}, {mail_host}, {mail_mailer}')
define(`confMILTER_MACROS_ENVRCPT',
  `{rcpt_addr}, {rcpt_host}, {rcpt_mailer}')
define(`confMILTER_MACROS_EOM', `{msg_id}')

dnl # Inbound: verification chain. DarkARC last (or just before DarkChain).
INPUT_MAIL_FILTER(`smf-spf',
  `S=unix:/var/run/smfs/smf-spf.sock, T=S:30s;R:1m')
INPUT_MAIL_FILTER(`opendkim',
  `S=local:/run/opendkim/opendkim.sock')
INPUT_MAIL_FILTER(`opendmarc',
  `S=local:/run/opendmarc/opendmarc.sock, F=T')
INPUT_MAIL_FILTER(`DarkARC',
  `S=unix:/var/spool/DarkARC/sock, T=S:30s;R:2m')
dnl INPUT_MAIL_FILTER(`DarkChain', ...)   # if DKIM2 is deployed, after DarkARC
INPUT_MAIL_FILTER(`DarkSpam',
  `S=unix:/var/spool/DarkSpam/sock, T=S:30s;R:2m')

dnl # Outbound: signing chain. DarkARCs last (or just before DarkChains).
INPUT_MAIL_FILTER(`DarkARCs',
  `S=unix:/var/spool/DarkARCs/sock, T=S:30s;R:2m')
dnl INPUT_MAIL_FILTER(`DarkChains', ...)  # if DKIM2 is deployed, after DarkARCs
```

After modifying `sendmail.mc`, rebuild and reload:

```bash
m4 sendmail.mc > sendmail.cf
systemctl reload sendmail
```

### Run scripts

```bash
# Verifier
pgrep -x DarkARC  >/dev/null || su -c "/usr/local/sbin/DarkARC &"  -s /bin/sh - smmsp

# Signer
pgrep -x DarkARCs >/dev/null || su -c "/usr/local/sbin/DarkARCs &" -s /bin/sh - smmsp
```

## Operating mode

DarkARC operates as a transparent authentication component: the verifier
records its assessment, the signer seals the chain, and neither rejects mail.
ARC is an authentication-state-preservation mechanism, not a policy enforcement
point — enforcement decisions belong to DMARC, consuming the authentication
results that ARC makes survivable across intermediaries.

## License

DarkARC and DarkARCs are released under the PolyForm Noncommercial License
1.0.0. The shared utility library `libdark` is released separately under the
MIT license.

## Author

Vittorio Moccia
