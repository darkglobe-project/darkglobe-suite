# darkglobe-suite - DKIM2 and ARC authentication milters

A suite of milter components for email authentication (DKIM2 and ARC), deployable on any MTA supporting the milter protocol without core modifications.

## Components

### Authentication

| Component | Function | License |
|-----------|----------|---------|
| [DarkChain](dkim2-darkchain/) | DKIM2-core verifier and signer | Apache 2.0 |
| [DarkARC](darkarc/) | ARC verifier and signer (RFC 8617) | PolyForm Noncommercial 1.0.0 |

## Shared library

[libDark](libdark/) provides common utilities, canonicalization, cryptographic primitives and string handling used by all components. Released under the MIT License.

## Design

All components follow the same principles: C implementation, standard milter API, Unix domain socket communication, no MTA core modifications required. Each component is a standalone process insertable at any point in the MTA's milter pipeline.

## Status

DarkChain and DarkARC are in active beta on production mail infrastructure.

## Author

Vittorio Moccia
