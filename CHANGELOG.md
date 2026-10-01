# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/). Breaking configuration changes happen only in major
versions and are described in `docs/upgrading.md`.

## [Unreleased]

### Security

- Access logs no longer contain query strings (they carried sign-in request ids and mailcow OAuth
  codes).
- SMTP servers that advertise AUTH without a usable mechanism are refused cleanly; nothing is sent.
- Client registration bodies are limited to 64 KB.

### Fixed

- The `/mcp` request body limit now follows `MAX_MESSAGE_MB`; the SDK default (4 MB) refused
  tool calls with larger attachments.

### Added

- Negative tests (phase 6): unauthenticated, plaintext and wrong-certificate SMTP servers get
  nothing; `X-Forwarded-For` is used only from `TRUSTED_PROXIES`; tokens bound to another resource
  and other users' MCP sessions are refused; body limits.
- `scripts/check` runs everything CI checks.

- mailcow extras (phase 5): `release_from_quarantine` and `delete_from_quarantine` (only items
  addressed to the mailbox or its aliases, re-checked by the broker), `delivery_status`
  (per-recipient sent/deferred/bounced with the remote server's answer, from mailcow's mail log),
  `my_addresses` (the mailbox and its aliases).
- `list_spam` includes quarantined items in mailcow mode; `find_replies` also lists quarantined
  messages from the original recipients after the original was sent, marked as possible replies.
- `find_contacts`: CardDAV search (SOGo in mailcow mode with the app password's DAV access; any
  CardDAV server in generic mode via `CARDDAV_URL`), with standard discovery.
- Rejected broker capabilities sign the connection out like rejected passwords.

- mailcow mode (phase 4): "Sign in with mailcow" on the consent page. The user signs in on
  mailcow's own login page (with 2FA); the OAuth state is bound to the browser. The mailcow token
  goes only to the broker, which asks mailcow who it is and creates an app password named
  `MCP: <client> (<date>, <tag>)` with IMAP, SMTP and DAV access only. The app password is tested
  with an IMAP login before the client gets a code.
- The broker (`mailcow-mcp broker`): the only process with the mailcow API key. Shared-secret
  header, capability tokens signed with `BROKER_SIGNING_KEY` and checked against the broker's own
  records, per-mailbox rate limits, its own audit log, no generic API passthrough.
- Revocation lifecycle: revoked, expired or rejected connections queue their app password for
  deletion through the broker; an hourly `reconcile` deletes `MCP: ` app passwords the app no
  longer holds. `revoke --all` for uninstalling.
- `docs/development/mailcow-api.md`: the mailcow API facts mailcow-mcp relies on.

- Reading and follow-up (phase 3): `list_folders`, `list_messages`, `search_messages`,
  `read_message`, `get_attachment`, `find_replies`, `get_thread`, `mark_messages`,
  `move_messages`. Reads never set `\Seen`. HTML-only messages are converted to text.
- `get_attachment` returns the text of PDF, DOCX and text files, images as image content,
  otherwise metadata (up to 5 MB, 50,000 characters).
- `find_replies` searches INBOX and Junk by In-Reply-To/References and says where each reply was
  found; `get_thread` collects ancestors and replies across INBOX, Sent, Junk and Archive.
- Spam rescue: `list_spam` (Junk with spam scores) and `rescue_from_junk`.
- All message content returned to the model is wrapped as untrusted, in a tag with a random
  suffix the content can't close; Junk content is flagged as likely spam or phishing.

- Sending and drafts (phase 2): `send_email`, `save_draft`, `send_draft`, `delete_draft`.
  Markdown bodies are sent as sanitized HTML with a plain-text alternative. Replies get
  `In-Reply-To` and `References` (taken from the original when it's in the mailbox). Bcc is kept
  only in the Sent and Drafts copies. `send_email` returns the Message-ID.
- Attachments from three sources: uploaded (base64), from a message in the mailbox, or a PDF
  rendered on the server from Markdown (WeasyPrint, never fetches external resources). Filenames
  are sanitized, content is sniffed and must match the declared type, executables are refused;
  limits: 10 files, `MAX_MESSAGE_MB` in total.
- SMTP always over TLS and always authenticated; nothing is sent if the server doesn't offer AUTH.
  Sender ACL rejections are reported as such. If the mail server rejects the stored password,
  the connection is signed out and the client is asked to reconnect.
- Per-mailbox send limits (`SEND_LIMIT_HOUR`, `SEND_LIMIT_DAY`), kept across restarts.
- Folders found by SPECIAL-USE flags, then `FOLDER_SENT`/`_DRAFTS`/`_JUNK`/`_TRASH`, then
  common names. `SAVE_SENT=auto` skips the copy only for servers that file sent mail themselves.
- `TLS_CA_FILE` for mail servers with a private CA.
- Loopback redirect URIs match on any port (RFC 8252 §7.3), as VS Code needs.
- Integration tests against a real Dovecot + Postfix server in Docker.

- MCP authorization (phase 1): Streamable HTTP endpoint at `/mcp` behind OAuth 2.1 with
  protected resource metadata (RFC 9728), server metadata (RFC 8414), dynamic client
  registration (RFC 7591), PKCE S256, resource indicators (RFC 8707), the `iss` response
  parameter (RFC 9207) and token revocation (RFC 7009). Refresh tokens rotate; reusing a spent
  code or refresh token revokes the connection. Access tokens last 1 hour, refresh tokens 30 days
  without use; codes and tokens are stored as hashes.
- Sign-in and consent page for generic mode: password checked with an IMAP login, allowed domains
  checked first, CSRF token, strict CSP, no third-party assets, English and Czech. Shows the
  client's name and where access goes.
- Rate limits: client registrations per IP, sign-in page views and attempts per IP, failed
  sign-ins per mailbox. Unused client registrations expire after 24 hours.
- SQLite storage with versioned migrations, run on start. Passwords and client secrets are
  encrypted with `ENC_KEY`.
- Audit log (JSON lines on stdout and in `DATA_DIR/audit.log`) for registrations, sign-ins and
  revocations.
- CLI: `migrate`, `users`, `clients`, `revoke <mailbox>`.

- Project scaffold: package layout, `serve` / `broker` commands with a `/healthz` endpoint.
- Configuration validation for app and broker. A container refuses to start on a missing or
  invalid setting and lists every problem at once.
- `generate-key` command for `ENC_KEY`, `BROKER_SIGNING_KEY` and `BROKER_SHARED_SECRET`.
- Dockerfile (non-root, works with a read-only root filesystem), CI and release workflows,
  Dependabot.
