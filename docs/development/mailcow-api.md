# mailcow API notes (for contributors)

What mailcow-mcp relies on, verified by reading the mailcow-dockerized source at tag `2026-09`
(commit ca07d8d). Line references are to that commit. Re-check these when supporting a new
mailcow release.

## General

- `/api/v1/<action>/<category>/<object>` → `data/web/json_api.php`. `get` is GET; `add`, `edit`,
  `delete` are POST with `Content-Type: application/json`. Bodies: `add` = attribute object,
  `edit` = `{"items": [...], "attr": {...}}`, `delete` = JSON array of IDs.
- Write calls answer **HTTP 200 even on failure**, with a list of `{type, log, msg}`; `type` is
  `success`, `danger` or `error`. Empty `get` results are `{}` (sometimes `[]`). Numbers may be
  strings.
- Auth: header `X-API-Key`. **Any valid key acts as admin** (username `API`); there are no
  per-user keys. A read-only key gets 403 on writes. "Allow API access from" is checked against
  the client address; nginx trusts `X-Forwarded-For` from private ranges, so the broker never
  sends one.

## App passwords

- Create: `POST /api/v1/add/app-passwd` with `username`, `app_name`, `app_passwd`,
  `app_passwd2`, `active: "1"`, `protocols` (subset of `imap_access`, `smtp_access`,
  `dav_access`, `eas_access`, `pop3_access`, `sieve_access`). Omitting `active` creates it
  disabled; omitting `protocols` gives no access. **The new ID is not returned**: list and match
  by name (we add a random tag to the name for that).
- List: `GET /api/v1/get/app-passwd/all/<mailbox>`, includes the **password hash**, which we drop.
  `GET /api/v1/get/app-passwd/<id>` throws on PHP 8: don't use it.
- Delete: `POST /api/v1/delete/app-passwd` with `[id, …]`.
- Password policy: `GET /api/v1/get/passwordpolicy`.

## OAuth (mailcow as identity provider)

- `GET /oauth/authorize?response_type=code&client_id&redirect_uri&state&scope=profile`. `state`
  is required, the redirect URI must match exactly, **no PKCE**, no discovery metadata, no dynamic
  registration. So MCP clients can't use mailcow directly; mailcow-mcp is the authorization
  server and uses mailcow as the upstream login.
- The login page enforces the user's 2FA (TOTP/WebAuthn). An existing mailcow browser session,
  including an admin session, skips the login (an admin's profile then fails).
- `POST /oauth/token` (client secret in the body or HTTP Basic). Access tokens last 24 h.
- `GET /oauth/profile` with the bearer token → `{"success": true, "username": …, "active": "1", …}`.
- OAuth2 apps: System → Configuration → Access → OAuth2 Apps.

## Quarantine

- `GET /api/v1/get/quarantine/all` → `id, qid, subject, virus_flag, score, rcpt, sender, action,
  created (unix), notified`. `rcpt` is the final mailbox after alias resolution.
- `GET /api/v1/get/quarantine/<id>` adds `msg` (the raw message), `symbols`, …
- Release: `POST /api/v1/edit/qitem` `{"items": ["<id>"], "attr": {"action": "release"}}`. It is
  re-injected without filters and lands in INBOX; rspamd learns it as ham.
- Delete: `POST /api/v1/delete/qitem` `["<id>"]`.
- `add header` / `rewrite subject` mail is delivered to Junk **and** kept in quarantine.

## Aliases and logs

- `GET /api/v1/get/alias/all` → `address, goto` (comma-separated), `active`, … A mailbox's aliases
  are those whose `goto` contains it (mailcow's own regex: `(^|,)<mailbox>($|,)`).
- `GET /api/v1/get/logs/postfix/<N>` → newest first, `{time, priority, program, message}`; the
  list holds about `LOG_LINES` (default 9999) lines, so delivery status only covers recent mail.

## Mail server facts

- Network `<COMPOSE_PROJECT_NAME>_mailcow-network` (default `mailcowdockerized_mailcow-network`),
  `IPV4_NETWORK` default `172.22.1`. Names: `dovecot-mailcow` (alias `dovecot`),
  `postfix-mailcow` (`postfix`), `nginx-mailcow` (`nginx`), `sogo-mailcow`.
- Dovecot 993 (TLS) / 143 (STARTTLS); Postfix 465 (TLS) / 587 (STARTTLS required). Both present
  the mailcow certificate for `MAILCOW_HOSTNAME`, hence `TLS_SERVER_NAME`.
- **Postfix permits relaying from the mailcow network without authentication**
  (`mynetworks_style = subnet`). mailcow-mcp always authenticates.
- Moving a message out of Junk (except to Trash) reports it to rspamd as ham; into Junk as spam
  (Dovecot imapsieve, `data/conf/dovecot/dovecot.conf`).
- CardDAV: `https://<host>/SOGo/dav/<user>/Contacts/personal/`; app passwords need `dav_access`.
- Custom nginx config: any `data/conf/nginx/*.conf` is included at http level.
