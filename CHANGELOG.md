# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/). Breaking configuration changes happen only in major
versions and are described in `docs/upgrading.md`.

## [Unreleased]

### Added

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
