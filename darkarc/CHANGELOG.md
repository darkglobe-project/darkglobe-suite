# Changelog DarkARC 

## [1.3 - 10/10/2026]

### Fixed

- **C locale pinned.** Both milters now call `setlocale(LC_ALL, "C")` at
  the top of main. Header canonicalization and address comparison rely on
  ctype and strcase* behaving as pure ASCII; under a single-byte LC_CTYPE
  those routines classify octets >= 0x80 and would case-fold or collapse
  continuation bytes of a UTF-8 sequence, corrupting the AMS and AS hashes
  on legitimate mail. Nothing called setlocale before, so the processes
  already ran in "C" — this makes it a decision rather than an accident.

- **Folding definition aligned (via libdark).** `unfold_header()` used
  `isspace()` to decide what constitutes a fold, which also accepts VT, FF,
  CR and LF, while `canonicalize_header_relaxed()` tests SP and HTAB
  explicitly. Both now use `dark_is_wsp()`, matching RFC 5234 WSP and
  RFC 5322 folding. The change lives in libdark and is shared with
  DarkChain / DarkChains.


## [1.2 - 21/07/2026]

Runtime configuration and deployment improvements, aligned with the
DarkChain 0.7 release.

### Added

- **Command-line options.** Both milters now accept:
  `-l level` (log level: debug/info/notice/warning/err, default notice),
  `-m umask` (socket umask in octal, default 0177),
  `-f` (foreground, no daemon),
  `-L` (mirror syslog to stderr via LOG_PERROR),
  `-h` (usage help),
  `-S` (server hostname)
  The `-f` and `-L` flags support Docker deployments where daemonization
  is undesirable and syslog may not be available.

  further line options for DarkARCs:
  `-d` domain    Signing domain for d= tag


### Changed

- **Default log level.** Changed from LOG_ERR to LOG_NOTICE. Debug trace
  messages (HELO start/end, ENVFROM internals) reclassified from LOGLEVEL
  to LOG_DEBUG. Errors (smfi_getpriv failure, fatal termination)
  reclassified to LOG_ERR. The `-l` flag controls filtering via
  `setlogmask(LOG_UPTO())`.
- **b= strip** in simple mode
- **Folding** \r\n to \n in AAR dkim=

### Fixed

- **Removed dead code in DarkARC main.** Unreachable `smfi_register()`
  call after `return` statement removed.

- **Removed argc < 2 check.** Both milters now work with defaults when
  invoked without arguments; `-h` shows usage.


## [1.1 - 05/07/2026]

### Added

New flow for external emails defined in aliases db (for Sendmail)


## [1.0 - 15/06/2026]

First public release

