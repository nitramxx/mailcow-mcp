# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/). Breaking configuration changes happen only in major
versions and are described in `docs/upgrading.md`.

## [Unreleased]

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

[Unreleased]: https://github.com/nitramxx/mailcow-mcp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/nitramxx/mailcow-mcp/releases/tag/v0.1.0
