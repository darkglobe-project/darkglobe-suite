# Postfix Configuration: SRS Routing + Milter (DarkChains) Signing

This document describes the two-phase architecture implemented in Postfix to manage sender rewriting (**SRS - Sender Rewriting Scheme**) on forwarded messages. This ensures that the subsequent **Milter (DarkChain/DarkChains)** signing occurs on the correct final envelope, preventing SPF/DKIM breakage.

---

## 1. Alias Mapping (`/etc/postfix/srs_aliases`)
This file intercepts specific destination addresses subject to forwarding and forcefully routes them to the internal SRS processing port (Phase 1).

Add or modify the lines in the file:
```text
forward@yourdomain.com    FILTER smtp:[127.0.0.1]:10026
```

> **Note:** After modifying this file, you must rebuild the index by running:
> `postmap /etc/postfix/srs_aliases`

---

## 2. Global Configuration (`/etc/postfix/main.cf`)
Add or update the following parameters to enable the SRS alias checks and define the macros required for the matching Milter to function correctly.

```ini
# --- Reception Restrictions and SRS Filter Execution ---
smtpd_recipient_restrictions =
    check_client_access hash:/etc/postfix/access,
    check_sender_access hash:/etc/postfix/access,
    permit_mynetworks,
    reject_unauth_destination,
    check_recipient_access hash:/etc/postfix/srs_aliases

# --- Global Milter Configuration (DarkChain) ---
smtpd_milters = unix:/var/spool/DarkChain/sock
milter_default_action = accept
milter_protocol = 6

# )-- Macros for passing metadata to the Milter ---
milter_connect_macros = j {client_addr} {client_name} {client_ptr} {daemon_name} {auth_type}
milter_mail_macros = i {auth_type} {auth_authen} {auth_ssf} {auth_author} {mail_addr} {mail_host} {mail_mailer}
milter_rcpt_macros = {rcpt_addr} {rcpt_host} {rcpt_mailer} {mail_addr} {mail_host} {mail_mailer} i j
milter_end_of_data_macros = {rcpt_addr} {rcpt_host} {rcpt_mailer} {mail_host} {mail_mailer} i j {msg_id}

# --- Transport Tables ---
transport_maps = hash:/etc/postfix/transport
```

---

## 3. Service Configuration (`/etc/postfix/master.cf`)
This section defines the cascading flow on internal ports. At the bottom of the `master.cf` file, ensure the following blocks are present:

```text
# ====================================================================
# PHASE 1 (FORWARDS ONLY): Apply SRS and route to Phase 2
# ====================================================================
127.0.0.1:10026 inet n  -       n       -       0       smtpd
    -o cleanup_service_name=cleanup_srs
    -o smtpd_milters=
    -o content_filter=smtp:[127.0.0.1]:10027
    -o receive_override_options=no_header_body_checks

cleanup_srs unix  n       -       n       -       0       cleanup
    -o sender_canonical_maps=tcp:localhost:10001
    -o sender_canonical_classes=envelope_sender

# ====================================================================
# PHASE 2 (FOR ALL MAILS): Apply Milter DarkChains on the final 
# envelope and send
# ====================================================================
127.0.0.1:10027 inet n  -       n       -       -       smtpd
    -o smtpd_milters=unix:/var/spool/DarkChains/sock
    -o cleanup_service_name=cleanup_outbound
    -o receive_override_options=no_address_mappings
    -o content_filter=
    -o relayhost=

cleanup_outbound unix  n       -       n       -       0       cleanup
```

---

## 4. Applying the Changes
To apply the changes cleanly without leaving orphan or hanging processes, restart the Postfix daemon:

```bash
systemctl daemon-reload
systemctl restart postfix
```

### Verifying listening ports
You can verify the correct startup of the architecture by ensuring that Postfix is listening on the required sockets:
```bash
ss -tlnp | grep -E ':25|:10026|:10027'
```
