# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/). Breaking configuration changes happen only in major
versions and are described in `docs/upgrading.md`.

## [Unreleased]

## [0.1.6] - 2026-10-02

Fixes from a full code review. Update both containers (`sudo ./setup-mailcow.sh update`).

### Security

- The sign-in form only works in the browser that loaded it (its token is derived from a
  SameSite cookie), and posts with `Origin: null` are refused: a sign-in request started
  elsewhere could be posted from a victim's browser, skipping the consent page.
- Every piece of email content a tool returns is marked untrusted, also subjects, names,
  addresses and attachment filenames in `read_message`, `get_thread` and `get_attachment`.
- Rate limits: failed passwords are counted before they're checked (parallel guesses),
  `/authorize` is limited, IPv6 clients are limited per /64.
- Limits on resources: thread bodies (50 MB together), DOCX inflation (50 MB), Markdown for
  PDFs (200,000 characters each, 500,000 per message), CardDAV answers, chunked registrations.
- CardDAV credentials are never sent to another host named in the server's answers.

### Fixed

- A temporary IMAP or SMTP authentication failure (e.g. Dovecot's `[UNAVAILABLE]`, SMTP 454)
  no longer signs the connection out and deletes its app password.
- `find_contacts` works through `MAILCOW_INTERNAL_URL` (the mailcow kit's default).
- A message with a malformed header no longer breaks the whole listing.
- Broker: reconcile deletes nothing when most capabilities don't verify (e.g. a changed
  `BROKER_SIGNING_KEY`), works with any number of connections, and locks one mailbox at a
  time; a failed sign-in no longer leaves an app password behind.
- A sent message is never reported as an error: problems saving the Sent copy are a note, and
  `send_draft` keeps the draft if no copy reached Sent. Send limits count before sending.
- Long non-ASCII subjects and names are folded into RFC 2047 encoded words of at most 75
  characters again (Message-ID and filename headers stay unfolded).
- `get_thread` returns the newest 30 messages by date across folders.
- Servers without UIDPLUS: no unrelated messages are expunged.
- Clients that refreshed recently stay registered after their connection ends.
- Two "Sign in with mailcow" tabs at once both work.
- Database migrations can't run twice at once; an older image refuses a newer database.
- `audit.log` rotates at 10 MB.
- `setup-mailcow.sh`: consistent `BROKER_SHARED_SECRET`, a clear error for a changed hostname,
  nginx's upload limit from `MAX_MESSAGE_MB`, nginx reloaded instead of restarted, passwords
  not on command lines, DNS checks without `/etc/hosts`, and more robust `update`.

### Changed

- `BROKER_URL` defaults to `http://mcp-broker:8091`, the name the kits use.
- The kits set memory, process and `/tmp` limits; HSTS comes from the app only.
- Releases stay drafts until their images are pushed; kit archives are reproducible.

## [0.1.5] - 2026-10-02

### Fixed

- 0.1.4 regression: replies to messages with long Message-IDs (e.g. Outlook's) had `In-Reply-To`
  and `References` RFC 2047-encoded, which breaks threading, and long attachment filenames were
  split into RFC 2231 parts. Messages are now built with a 76-column policy (quoted-printable lines
  ≤ 76, as RFC 2045 requires; 0.1.4 allowed 78) and sent without refolding headers.
- `send_draft` re-encodes 8bit drafts (e.g. saved by another client) for 7-bit transport.
- ASCII text with form feeds or other separators is measured by real line breaks, so long lines
  get quoted-printable.
- `TIMEZONE=Europe` (a folder, not a zone) is reported as a configuration error instead of
  crashing.
- `FROM_NAMES` accepts `=` in local parts and Unicode domains, reports each error once, and
  rejects DEL in names; `my_addresses` matches addresses like `send_email` does.
- An IP as EHLO name is sent as an address literal (`[192.0.2.1]`).
- `setup-mailcow.sh` no longer glues an added setting onto the last line of an env file that
  lacks a final newline.
- `.env.example` leaves `TIMEZONE` empty (the default is the container's zone).

## [0.1.4] - 2026-10-02

### Changed

- Outgoing mail is 7-bit clean: text parts with non-ASCII characters (or long lines) are
  quoted-printable UTF-8, never raw 8bit; plain ASCII stays 7bit. Lines are wrapped at 76
  (quoted-printable) and headers folded at 78; sub-parts no longer repeat `MIME-Version`.
- `FROM_NAMES`: default display names per sender address, used when a client doesn't give
  `from_name` (a name in `from_address` comes first). `my_addresses` returns them; the
  `send_email` and `save_draft` descriptions tell clients to set `from_name`.
- `SMTP_HELO_NAME`: the EHLO name (default `TLS_SERVER_NAME`, i.e. the mail server's name) instead
  of the container's `[127.0.0.1]` in the Received header.
- `TIMEZONE`: the Date header's time zone (the mailcow kit copies mailcow's `TZ`), instead of
  `+0000`.

## [0.1.3] - 2026-10-02

### Fixed

- mailcow with IPv6 enabled: the containers also got IPv6 addresses on mailcow's network and
  connected from those, so mailcow's API refused the broker ("api access denied") and the
  Fail2ban allowlist didn't cover the app. Both containers are now IPv4-only
  (`net.ipv6.conf.all.disable_ipv6`), so mailcow always sees their fixed addresses.

### Added

- The broker logs mailcow's reason when the API refuses it; `mailcow-mcp check-mailcow` (broker)
  tests the API key and address, and `setup-mailcow.sh` runs it in step 9.

## [0.1.2] - 2026-10-02

### Fixed

- After a failed mailcow sign-in, "Sign in with mailcow" on the error page said the sign-in had
  expired; it now retries the same request.

### Added

- In mailcow mode `/healthz` reports whether the app reaches the broker (`"broker": "ok"`), and
  `setup-mailcow.sh` checks it.

### Changed

- The deployment kits are release downloads (`mailcow-kit.tar.gz`, `generic-kit.tar.gz`, with
  SHA-256 checksums); no git clone or copying from a source folder. The kit's `VERSION` pins the
  image.
- `setup-mailcow.sh update [VERSION]` installs a release's kit (checksum verified, changes shown,
  env files never touched), pins the image, restarts and runs the checks. `--restart` pulls and
  (re)starts after `--apply`, restarting mailcow's nginx only when its site file changed.
  `--hostname` and `--mailcow-dir` are remembered after the first run.

## [0.1.1] - 2026-10-02

### Fixed

- Signing in failed in browsers with "cross-origin request refused": under the sign-in page's
  `no-referrer` policy, browsers send `Origin: null` with the form. The page now uses
  `Referrer-Policy: same-origin` (no referrer to other sites), and `Origin: null` is accepted; the
  CSRF token is the protection, only posts from another site are refused.

### Changed

- `setup-mailcow.sh` checks every deployment step against mailcow's state and marks it ✓/✗/?:
  DNS, the certificate file, the OAuth2 app and read-write API key (mailcow's database), the
  Fail2ban allowlist (mailcow's Redis), and whether mailcow-mcp is running and routed. It reads the
  OAuth2 client and API key from mailcow, so they no longer have to be copied, and fills in empty
  values in existing env files. The nginx site file is checked with `nginx -t` and disabled if
  nginx rejects it. Run with `sudo`, the files it writes belong to the kit directory's owner.

## [0.1.0] - 2026-10-01

First release.

### Added

- **Remote MCP server** (Streamable HTTP at `/mcp`) with the MCP authorization spec: protected
  resource metadata (RFC 9728), server metadata (RFC 8414), dynamic client registration
  (RFC 7591), PKCE S256, resource indicators (RFC 8707), the `iss` parameter (RFC 9207),
  revocation (RFC 7009). Access tokens 1 hour, rotating refresh tokens (30 days without use), reuse
  detection; codes and tokens stored as hashes. Loopback redirect URIs match on any port
  (RFC 8252).
- **mailcow mode**: "Sign in with mailcow" on mailcow's own login page (with 2FA); the broker
  creates a per-client app password `MCP: <client> (<date>, <tag>)` with IMAP, SMTP and DAV access
  only, tested before the client gets a code. Revoked, expired and rejected connections delete
  their app password; an hourly reconcile removes leftovers.
- **Broker**: the only process with the mailcow API key; internal network only, shared secret,
  signed capability tokens checked against its own records, a fixed list of mailbox-scoped
  operations, per-mailbox limits, audit log.
- **Generic mode**: password sign-in against any IMAP/SMTP server.
- **Tools**: `send_email`, `save_draft`, `send_draft`, `delete_draft` (Markdown or text bodies;
  attachments uploaded, taken from a message, or rendered as PDF from Markdown), `list_folders`,
  `list_messages`, `search_messages`, `read_message`, `get_attachment` (PDF/DOCX/text extraction,
  images), `find_replies` (INBOX, Junk and quarantine), `get_thread`, `mark_messages`,
  `move_messages`, `list_spam`, `rescue_from_junk`, `release_from_quarantine`,
  `delete_from_quarantine`, `delivery_status`, `my_addresses`, `find_contacts` (CardDAV).
- **Prompt-injection safety**: all email content wrapped as untrusted with random tags; Junk and
  quarantine content flagged; read-only and destructive tool annotations.
- **Hardening**: strict header and address validation, 50 recipients, 1 MB body, attachment type
  checks; SMTP always TLS and authenticated; certificates verified against `TLS_SERVER_NAME`;
  per-mailbox send limits; sign-in limits per IP and per mailbox; client IP only from
  `TRUSTED_PROXIES`; strict CSP on the sign-in page; no secrets or query strings in logs.
- **Sign-in page** in English and Czech.
- **CLI**: `generate-key`, `migrate`, `users`, `clients`, `revoke <mailbox>`, `revoke --all`,
  `healthcheck`.
- **Deployment kits**: mailcow (compose file, nginx site file, `setup-mailcow.sh`) and generic
  (Caddy).
- **Documentation**: deployment guides, clients, tools, configuration, security, upgrading, Czech
  user guide.
- Multi-arch image (linux/amd64, linux/arm64) on GHCR with SBOM and provenance.

[Unreleased]: https://github.com/nitramxx/mailcow-mcp/compare/v0.1.6...HEAD
[0.1.6]: https://github.com/nitramxx/mailcow-mcp/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/nitramxx/mailcow-mcp/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/nitramxx/mailcow-mcp/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/nitramxx/mailcow-mcp/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/nitramxx/mailcow-mcp/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/nitramxx/mailcow-mcp/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/nitramxx/mailcow-mcp/releases/tag/v0.1.0
