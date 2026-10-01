# mailcow MCP — specification

An open-source, self-hosted **remote MCP server for mailcow**. Users connect their mailbox to any MCP client (Claude, Cursor, VS Code, Claude Code, …) by URL, sign in with their mailcow account, and an agent can **send, draft, read and follow up on email**: attachments, reply tracking, rescuing replies from spam and quarantine, delivery status, contacts.

**mailcow-first**: the flagship mode uses mailcow's own login (incl. 2FA), creates scoped app passwords automatically, and adds mailcow-only tools. A **generic mode** (password login, any IMAP/SMTP server) shares the same core and is kept as a low-cost fallback.

Published on GitHub as one multi-arch Docker image, with a mailcow deployment kit and clear guides.

> Name: **mailcow-mcp** (repo `nitramx/mailcow-mcp`, image `ghcr.io/nitramx/mailcow-mcp`). License: **MIT**.
> README states it is a community project, not affiliated with or endorsed by the mailcow team / The Infrastructure Company GmbH. Distribution is via the Docker image; no PyPI package in v1 (`mcp-mailcow` on PyPI is an unrelated project).

## Goals

- Users install nothing and type no password into a third-party page: add URL → "Sign in with mailcow" → done.
- Operators deploy with `docker compose up -d` plus a short copy-paste guide and a setup helper.
- Each user acts only as their own mailbox.
- Any MCP-compliant client works (Streamable HTTP + MCP authorization spec).
- **The mailcow API key never sits in an internet-facing process.**
- Secure defaults.

## Non-goals

- mailcow administration (domains, mailboxes, aliases, quotas of others).
- Multiple mail backends per deployment; users can never choose the host.
- Webmail UI.

## Architecture

Two processes from the **same image** (different commands), separate containers:

```
MCP client ──HTTPS──> mailcow nginx ──> [app]  (public, via nginx)
                                          │  IMAP/SMTP/CardDAV with the user's app password
                                          ├──────────> dovecot / postfix / SOGo
                                          │  internal network only, narrow RPC
                                          └──────────> [broker] ──> mailcow API (RW key)
```

**app** (`mailcow-mcp serve`): MCP endpoint, OAuth for MCP clients, login, all mail tools. Has no mailcow API key.

**broker** (`mailcow-mcp broker`): tiny internal service, **not routed by nginx, not on any published port**. Holds the mailcow API key. Exposes only a fixed set of operations, each scoped to one mailbox proven by a capability token (below). No generic API passthrough.

Generic mode runs only **app**, with password login and no mailcow-only tools.

## Stack

- Python 3.12, official MCP Python SDK. Pin the major and verify APIs against the installed version (mcp 2.x changed the low-level API vs 1.x).
- Locked dependencies (`uv.lock`); image builds use the lock file.
- Streamable HTTP at `/mcp`; uvicorn.
- Mail: `imapclient`, `aiosmtplib`. Contacts: CardDAV (`caldav`/`vobject` or plain WebDAV + vCard parsing).
- SQLite in a volume, versioned migrations, run automatically on start.
- `markdown-it-py` + `nh3` (Markdown → sanitized HTML), `weasyprint` (Markdown → PDF), `pypdf`, `python-docx`.

## Authentication

### MCP clients → app (both modes)

Current MCP authorization spec:
- Protected Resource Metadata (RFC 9728), `WWW-Authenticate` on 401.
- Authorization Server Metadata (RFC 8414).
- Dynamic Client Registration (RFC 7591); Client ID Metadata Documents if supported by the spec/SDK version in use.
- Authorization code + PKCE S256 mandatory; refresh tokens with rotation; resource indicators (RFC 8707).
- Redirect URIs: any `https://`, or loopback `http://127.0.0.1:*` / `http://localhost:*`.
- Access token 1 h, refresh 30 days, stored as hashes. Unused registered clients expire after 24 h; registration rate-limited per IP.

### User login — mailcow mode (default)

The app is an OAuth client of mailcow (mailcow acts as identity provider: `/oauth/authorize`, `/oauth/token`, `/oauth/profile`; the OAuth2 app is created by the admin under System → Configuration → Access → OAuth2 Apps).

1. MCP client opens the app's `/authorize`. The app shows a consent page: instance name, requesting client's name and redirect host, what access is granted, privacy note, and a **"Sign in with mailcow"** button.
2. User signs in on **mailcow's own login page** (incl. mailcow 2FA if enabled; verify this behaviour on the supported mailcow versions).
3. App receives the mailcow access token and sends it to the broker's `provision` operation.
4. Broker calls mailcow `/oauth/profile` **itself** with that token to learn the username (never trusts a username sent by the app), then creates an **app password** for that mailbox via the mailcow API:
   - name `MCP: <client name> (<date>)` so the user recognises it in mailcow → App passwords
   - protocols: IMAP, SMTP, DAV only (verify exact protocol identifiers in the instance's API docs at `/api`)
   - random 32+ char password
5. Broker returns `{ username, app_password_id, app_password, capability_token }`. App stores password and capability token encrypted (Fernet, `ENC_KEY`), issues the MCP auth code.
6. The mailcow OAuth token is discarded after provisioning.

**Revocation lifecycle**
- MCP token revoked / refresh token expires / `revoke` CLI → app asks broker to delete that app password.
- User deletes the app password in mailcow → next IMAP/SMTP call fails auth → app revokes the user's MCP tokens and returns "please reconnect".
- Broker job (hourly): app passwords named `MCP: …` that the app no longer knows about are deleted.

### User login — generic mode

Login form (email + password, app password recommended), validated by IMAP LOGIN; `ALLOWED_DOMAINS` enforced first. Also available in mailcow mode only if `ALLOW_PASSWORD_LOGIN=true` (default `false`).

### Login page requirements (both)

CSRF token, strict CSP, `X-Frame-Options: DENY`, no third-party assets, translations in `locales/en.json` and `locales/cs.json`.

## Broker

**Capability tokens**: at provisioning the broker issues a token signed with `BROKER_SIGNING_KEY` (broker-only secret), subject = mailbox username, plus `app_password_id`. Every later operation requires it; the broker acts only for that mailbox. Consequence: a compromised app can act only for mailboxes that have connected, never for arbitrary mailboxes, and can never perform admin operations.

**Transport**: internal Docker network shared only by app and broker; additionally a shared secret header (`BROKER_SHARED_SECRET`) so nothing else on that network can call it.

**Operations (complete list):**

| Operation | Does |
|---|---|
| `provision(mailcow_oauth_token, client_name)` | verify via `/oauth/profile`, create app password, issue capability token |
| `deprovision(capability)` | delete that app password (only names starting `MCP: `) |
| `quarantine_list(capability)` | quarantine items whose recipient is the mailbox or one of **its** aliases (resolved via API, cached) |
| `quarantine_release(capability, id)` | release item to inbox, after re-checking ownership |
| `quarantine_delete(capability, id)` | delete item, after re-checking ownership |
| `delivery_status(capability, message_id)` | from Postfix logs: find queue IDs with `from=<mailbox or its alias>` and this Message-ID, return per-recipient status (sent / deferred / bounced + remote response) |
| `aliases(capability)` | the mailbox's own aliases (for `from_address` suggestions and quarantine scoping) |

Each operation validates input strictly, rate-limits per mailbox, writes an audit line, and returns only fields about that mailbox.

**mailcow API key**: mailcow has a single read-write API key. The guide must say so: if the operator already uses it for other automation, "Allow API access from" must list both IPs; recommended: restrict it to the broker's static IP.

## Tools

All tools act only as the authenticated mailbox. Folders resolved via SPECIAL-USE (`\Sent`, `\Drafts`, `\Junk`, `\Trash`), then configured names, then common names. Reads use `BODY.PEEK`.

### Sending and drafts (both modes)

| Tool | Purpose |
|---|---|
| `send_email` | `to`, `cc`, `bcc`, `subject`, `body_markdown` or `body_text`, optional `from_name`, `from_address` (one of the mailbox's addresses/aliases; mailcow's sender ACL decides, rejection surfaced cleanly), `in_reply_to` (sets `In-Reply-To` + `References`), `attachments`. Saves to Sent per `SAVE_SENT`. **Returns Message-ID.** |
| `save_draft` | Same fields → Drafts with `\Draft`. Returns UID + Message-ID. |
| `send_draft` | `uid` → sends the draft as currently stored (the user may have edited it in SOGo meanwhile), files in Sent, removes from Drafts. |
| `delete_draft` | `uid`, Drafts only. |

Markdown bodies → multipart/alternative (sanitized HTML + plain text).

### Attachments

Each attachment is one of:
- `{ filename, content_base64, mime_type }`
- `{ from_message: { folder, uid, part_id } }`
- `{ render_pdf: { filename, markdown, title } }`: server-rendered PDF (practical when the agent has text, e.g. from a Google Doc)

Limits: `MAX_MESSAGE_MB` total, max 10 files, sanitized filenames, MIME sniffed and checked.

### Reading and follow-up (both modes)

| Tool | Purpose |
|---|---|
| `list_folders` | Folders, special-use flags, unread counts. |
| `list_messages` | `folder`, `limit` (≤50), `unread_only`, `since`. |
| `search_messages` | `folder`, `from`, `to`, `subject`, `text`, `since`, `before`, `limit`. |
| `read_message` | Headers, text body, attachment list with `part_id`. |
| `get_attachment` | Extracted text (PDF/DOCX/TXT/CSV), image content for images, metadata otherwise. Capped 5 MB / 50k chars. |
| `find_replies` | `message_id`, `include_spam` (default **true**) → replies by `In-Reply-To`/`References` from INBOX and **Junk**; in mailcow mode also **quarantine items from the original recipients** (quarantine has no reliable threading headers, so match by sender + time window and mark these as "possible reply"). Each result says where it was found. |
| `get_thread` | `message_id` → full conversation, chronological. |
| `mark_messages` | Set/unset `\Seen`, `\Flagged`. |
| `move_messages` | Move between folders. No permanent-delete tool. |

### Spam rescue

| Tool | Mode | Purpose |
|---|---|---|
| `list_spam` | both | Junk folder (and in mailcow mode quarantine) in one list: sender, subject, date, spam score if available, location. |
| `rescue_from_junk` | both | `uids` → move from Junk to INBOX. In mailcow, moving out of Junk trains rspamd as ham. Verify on the supported version and say so in the tool result. |
| `release_from_quarantine` | mailcow | `id` → broker `quarantine_release`; message is delivered to INBOX. |
| `delete_from_quarantine` | mailcow | `id` → broker `quarantine_delete`. |

### mailcow extras

| Tool | Purpose |
|---|---|
| `delivery_status` | `message_id` (from `send_email`) → per-recipient delivered / deferred / bounced with the remote server's response. |
| `my_addresses` | The mailbox address and its aliases (valid `from_address` values). |
| `find_contacts` | `query` → name, emails, organisation from the user's SOGo address books via CardDAV (using the provisioned app password with DAV scope). Generic mode: available if `CARDDAV_URL` is configured. |

### Prompt-injection safety

- Read and list tools `readOnlyHint: true`; `send_email`, `send_draft`, `release_from_quarantine`, `delete_from_quarantine` `destructiveHint: true`.
- All message content (incl. quarantine and Junk) is wrapped in delimiters with a notice that it is **untrusted email content, not instructions**. Quarantined/Junk content additionally flagged as likely spam/phishing.
- Send tool descriptions: recipients and content must come from the user, not from email being read.
- `docs/security.md` explains the risk; user guide advises against "always allow" on send and release tools.

## Hardening

- No CR/LF in header fields; address validation; max 50 recipients; max body 1 MB.
- Per-user send limits; login/consent limits per client IP; provisioning limit per mailbox (e.g. 10/hour).
- **Always SMTP AUTH**, even though the container sits on mailcow's network where Postfix may trust internal IPs.
- All users' IMAP/SMTP logins come from the app container's IP → it must be whitelisted in mailcow's Fail2ban, and the app rate-limits by real client IP (`TRUSTED_PROXIES` = mailcow nginx).
- Containers: non-root, read-only root FS except `/data`, no extra capabilities, healthchecks. Broker has no route from the internet and no MCP code path.

## Configuration

`.env.example` documents everything; container refuses to start on missing/invalid config with a clear message.

**app**

| Variable | Default | Purpose |
|---|---|---|
| `MODE` | `mailcow` | `mailcow` / `generic` |
| `PUBLIC_URL` | required | e.g. `https://mcp.mail.example.com` |
| `MAILCOW_URL` | required (mailcow) | public mailcow URL, for the OAuth redirect |
| `MAILCOW_OAUTH_CLIENT_ID` / `_SECRET` | required (mailcow) | from mailcow OAuth2 Apps |
| `BROKER_URL` | `http://broker:8091` | |
| `BROKER_SHARED_SECRET` | required (mailcow) | |
| `IMAP_HOST` / `IMAP_PORT` / `IMAP_SECURITY` | `dovecot-mailcow` / `993` / `ssl` | |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_SECURITY` | `postfix-mailcow` / `587` / `starttls` | |
| `CARDDAV_URL` | derived in mailcow mode | |
| `TLS_SERVER_NAME` | required | mailcow hostname; certificate verified against it even when connecting to internal containers |
| `TLS_VERIFY` | `true` | |
| `ALLOW_PASSWORD_LOGIN` | `false` in mailcow mode | |
| `ALLOWED_DOMAINS` | empty = any | |
| `ENC_KEY` | required | `docker run --rm IMAGE generate-key` |
| `SAVE_SENT` | `always` | `auto` / `always` / `never` |
| `SEND_LIMIT_HOUR` / `SEND_LIMIT_DAY` | `30` / `300` | |
| `MAX_MESSAGE_MB` | `15` | |
| `TRUSTED_PROXIES` | required | mailcow network CIDR |
| `INSTANCE_NAME`, `DEFAULT_LANGUAGE` | `mailcow MCP`, `en` | |

**broker**

| Variable | Purpose |
|---|---|
| `MAILCOW_API_URL` | internal API URL (e.g. `https://nginx-mailcow`) + `TLS_SERVER_NAME` |
| `MAILCOW_API_KEY` | read-write key, restricted to the broker's IP in mailcow |
| `MAILCOW_OAUTH_PROFILE_URL` | for token verification |
| `BROKER_SHARED_SECRET` | same as app |
| `BROKER_SIGNING_KEY` | broker-only; `generate-key` |

## Audit log

JSONL to stdout and `/data/audit.log` (app and broker separately): timestamp, mailbox, client name, tool/operation, counts, result. Never bodies, attachment contents, passwords or tokens.

CLI: `generate-key`, `users`, `revoke <mailbox>`, `clients`, `migrate`.

## Repository layout

```
README.md                 what it is, login screenshot, 5-minute mailcow quick start, security model
docs/
  deploy-mailcow.md       primary guide
  deploy-generic.md       generic mode, any IMAP/SMTP server, Caddy with automatic TLS
  clients.md              Claude (web/desktop, Team vs Pro), Claude Code, Cursor, VS Code
  tools.md                every tool with an example prompt
  security.md             threat model, broker design, prompt injection, what is stored, key backup
  configuration.md
  upgrading.md
deploy/
  mailcow/                docker-compose.yml (app + broker), nginx site template, setup-mailcow.sh
  generic/                docker-compose.yml with Caddy
src/  tests/
.env.example  Dockerfile  SECURITY.md  CHANGELOG.md  CONTRIBUTING.md  LICENSE
.github/workflows/        ci.yml, release.yml
```

## mailcow deployment kit

Separate compose project (e.g. `/opt/mailcow-mcp`); **no changes to mailcow's compose files**, so `update.sh` is unaffected.

`setup-mailcow.sh` (read-only by default, `--apply` to write):
- detects mailcow directory, version, compose project name, network name, `IPV4_NETWORK`
- picks free static IPs for app and broker in mailcow's range
- creates the internal app↔broker network definition
- generates `.env` files (incl. `ENC_KEY`, `BROKER_SHARED_SECRET`, `BROKER_SIGNING_KEY`) and the nginx site file
- prints remaining manual steps with exact values (redirect URI, IPs to whitelist)

Guide steps (each with "verify" and troubleshooting):
1. DNS A/AAAA for the MCP hostname → mailcow host.
2. `ADDITIONAL_SAN` += MCP hostname in `mailcow.conf`, restart `acme-mailcow`, verify cert.
3. mailcow UI: create OAuth2 app with redirect URI `https://<mcp-host>/oauth/mailcow/callback`.
4. mailcow UI: enable the read-write API key, "Allow API access from" = broker IP (plus any existing automation IPs).
5. mailcow UI: Fail2ban whitelist += app IP, with the explanation (all logins come from it; without it, brute force on the login page bans the container and locks out everyone).
6. `setup-mailcow.sh`, review, `--apply`, `docker compose up -d`.
7. nginx site file in mailcow's custom nginx config directory (verify mechanism per supported mailcow version):
   - upstream resolved at request time (`resolver 127.0.0.11 valid=10s; set $up http://app:8090; proxy_pass $up;`) **so mailcow's nginx still starts when the app is down**
   - mailcow certificate, `proxy_buffering off`, long read timeout, forwarded headers
   - routes only the app, never the broker
8. Back up `ENC_KEY` and `BROKER_SIGNING_KEY` outside the server.
9. Verify: `/healthz`; full login from MCP Inspector; app password appears in mailcow; mailcow UI still loads with both containers stopped; broker unreachable from outside.

Uninstall section: stop containers, delete `MCP: ` app passwords (CLI does it), remove nginx file, SAN, OAuth2 app, API key IP, Fail2ban entry.

## CI / release

- `ci.yml`: ruff, type check, unit tests, **integration tests against a real mailcow** if feasible in CI (otherwise Dovecot+Postfix test container for core + a mocked mailcow API/OAuth for broker contract tests), OAuth flow tests, image build.
- `release.yml` on `vX.Y.Z`: multi-arch image (linux/amd64 + linux/arm64) to GHCR with SBOM + provenance; GitHub release with changelog.
- Dependabot for Python, base image, Actions. SemVer; breaking config only in majors, documented in `upgrading.md`.
- README states the supported mailcow versions.

## Phases (stop and report after each)

0. **Scaffold:** layout, config validation, `generate-key`, Dockerfile, CI skeleton, LICENSE, `.env.example`.
1. **MCP auth + generic password login,** empty tool list, end-to-end in MCP Inspector.
2. **Send, drafts, attachments** (all three sources), integration-tested.
3. **Read, follow-up, Junk rescue,** untrusted-content wrapping, attachment extraction.
4. **Broker + mailcow login:** OAuth with mailcow, provisioning/deprovisioning app passwords, capability tokens, cleanup job, revocation lifecycle.
5. **mailcow extras:** quarantine list/release/delete, `find_replies` over quarantine, `delivery_status`, `my_addresses`, `find_contacts`.
6. **Hardening + negative tests:** wrong/revoked credentials, deleted app password, forged capability token, broker called without secret, quarantine item of another mailbox, header injection, oversized attachment, rate limits, unauthenticated SMTP never used, nginx with containers down.
7. **Deployment kit + docs:** `setup-mailcow.sh`, generic kit, all docs incl. Czech user guide.
8. **Release + real deployment:** first tagged release, then deploy on a real mailcow following only the published guide; anything that needed outside knowledge goes into the guide.

## Acceptance test

On a mailcow host, following only `docs/deploy-mailcow.md`:
1. Connect from Claude with Google Drive enabled; sign in with mailcow; confirm the `MCP: Claude …` app password appears in mailcow.
2. "Read the Google Doc *X*, send it to *test@…* with a PDF of it attached." → `delivery_status` shows delivered.
3. Reply from the test address in a way that lands in Junk (and once in quarantine). Ask: "Did they reply? Summarize." → reply found and flagged as from spam; "Move it to my inbox" works for both.
4. Connect from one non-Claude MCP client.
5. Delete the app password in mailcow → client gets a clear reconnect message.

## Future ideas (not in v1)

Temporary aliases for one-off contacts, calendar (CalDAV) for scheduling follow-ups, Sieve out-of-office, personal access tokens for clients without OAuth.
