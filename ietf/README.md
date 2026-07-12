# IETF Internet-Drafts

This directory contains Internet-Drafts related to the deployment of DKIM2 via the milter interface, as implemented by DarkChain and DarkChains in this repository.

## draft-moccia-dkim2-deployment-profile

**Individual submission** — DKIM2 Working Group (ietf-dkim@ietf.org)

Datatracker: https://datatracker.ietf.org/doc/draft-moccia-dkim2-deployment-profile/

This document defines a deployment profile for DomainKeys Identified Mail v2 (DKIM2) implementable via the existing milter interface without modifications to Mail Transfer Agent (MTA) core software. It identifies a mandatory core profile (DKIM2-core) covering envelope binding, chain of custody, header accountability, replay prevention and DSN authentication, and an optional extended profile (DKIM2-extended) covering body recipes and Message-Instance headers.

The separation is motivated by deployment realism: DKIM2-core addresses the primary threat models identified in the DKIM2 motivation document and is deployable incrementally across heterogeneous infrastructure using the same milter-based deployment model that has proven effective for DKIM1 and ARC.

### Directory structure

```
src/    kramdown-rfc Markdown source (working files)
txt/    Plain text output submitted to the IETF datatracker
```

### Published versions

| Version | Date | Datatracker |
|---------|------|-------------|
| -04 | 2026-04 | https://datatracker.ietf.org/doc/draft-moccia-dkim2-deployment-profile/04/ |
| -05 | 2026-06 | https://datatracker.ietf.org/doc/draft-moccia-dkim2-deployment-profile/05/ |
| -06 | 2026-07 | pending submission after IETF-124 freeze |

### Implementation

The DKIM2-core profile described in this document is implemented by **DarkChain** (verifier) and **DarkChains** (signer) in the `dkim2-darkchain/` directory of this repository.

### Author

Vittorio Moccia — v.moccia@itb.it — ITB.it, Naples, Italy
