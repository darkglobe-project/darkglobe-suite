# DarkSRS

SRS milter generator for sendmail

* **Persistence and Concurrency (Startup):** Upon startup, the milter opens and maintains persistent handles for the `virtusertable.db` and `aliases.db` databases. Access to these files is thread-safe and managed via mutexes.
* **Resolution Flow (Local Mailer):** When a recipient is handled by a local mailer, the system checks for external recipients through a sequential two-step lookup:
  1. **`virtusertable.db`:** Searches for the recipient's email address to find the corresponding alias name.
  2. **`aliases.db`:** Uses the retrieved alias name to extract the final list of associated recipients.
* **Rewrite Logic:** The final list of recipients is compared against the local domains (loaded from `local-host-names` at startup). If the alias resolution reveals at least one external domain, the SRS rewrite flag (`needs_rewrite`) is triggered.

### Socket directory

```bash
mkdir -p /var/spool/DarkSRS
chown smmsp:smmsp /var/spool/DarkSRS 
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
INPUT_MAIL_FILTER(`DarkSRA',
  `S=unix:/var/spool/DarkSRS/sock, T=S:30s;R:2m')
```

After modifying `sendmail.mc`, rebuild and reload:

```bash
m4 sendmail.mc > sendmail.cf
systemctl reload sendmail
```

### Run scripts

```bash
pgrep -x DarkSRS  >/dev/null || su -c "/usr/local/sbin/DarkSRS &"  -s /bin/sh - smmsp
```

## License

DarkSRS is released under the PolyForm Noncommercial License.

## Author

Vittorio Moccia
