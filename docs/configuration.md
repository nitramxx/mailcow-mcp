# Configuration

All settings are environment variables (in the kits: `app.env`, `broker.env`). A container that
finds a missing or invalid setting doesn't start; it prints every problem at once. Empty values
count as unset. [`.env.example`](../.env.example) has the same list with comments.

Generate keys and secrets with `docker run --rm ghcr.io/nitramxx/mailcow-mcp generate-key` (or
`openssl rand -base64 32 | tr '+/' '-_'`).

## app (`mailcow-mcp serve`)

### Basics

| Variable | Default | |
|---|---|---|
| `MODE` | `mailcow` | `mailcow`: sign in with mailcow, app passwords created automatically. `generic`: password sign-in against any IMAP/SMTP server. |
| `PUBLIC_URL` | required | e.g. `https://mcp.example.com`, no path. `http://` only for `localhost`. Clients connect to `<PUBLIC_URL>/mcp`. |
| `ENC_KEY` | required | Encrypts stored credentials. Back it up. |
| `TRUSTED_PROXIES` | required | IPs/CIDRs of the reverse proxy, comma-separated (mailcow: its network, e.g. `172.22.1.0/24`). Only these may set `X-Forwarded-For`. `*` is refused. |
| `INSTANCE_NAME` | `mailcow MCP` | Shown on the sign-in page. |
| `DEFAULT_LANGUAGE` | `en` | `en` or `cs`; the browser's language is preferred when supported. |

### mailcow mode

| Variable | Default | |
|---|---|---|
| `MAILCOW_URL` | required | Public mailcow URL (the browser is sent to its login page). |
| `MAILCOW_INTERNAL_URL` | empty | e.g. `https://nginx-mailcow`: the app reaches mailcow's nginx directly for the token exchange and contacts (no hairpin NAT). Certificates are checked against `TLS_SERVER_NAME`. |
| `MAILCOW_OAUTH_CLIENT_ID`, `MAILCOW_OAUTH_CLIENT_SECRET` | required | From mailcow → OAuth2 Apps. Redirect URI there: `<PUBLIC_URL>/oauth/mailcow/callback`. |
| `BROKER_URL` | `http://mcp-broker:8091` | The broker's address; in the kits an alias only on the internal network. |
| `BROKER_SHARED_SECRET` | required | Same value as the broker's; at least 32 characters. |
| `ALLOW_PASSWORD_LOGIN` | `false` | Also offer email + password sign-in. |

### Mail servers

| Variable | Default | |
|---|---|---|
| `IMAP_HOST`, `IMAP_PORT`, `IMAP_SECURITY` | `dovecot-mailcow`, `993`, `ssl` | `ssl` (implicit TLS) or `starttls`. |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY` | `postfix-mailcow`, `587`, `starttls` | Always authenticated; nothing is sent if the server doesn't offer AUTH. |
| `SMTP_HELO_NAME` | `TLS_SERVER_NAME`, else `SMTP_HOST` | Name sent in EHLO; it appears in the Received header. |
| `TLS_SERVER_NAME` | required in mailcow mode | The name certificates are checked against, whatever host is dialled (mailcow: `MAILCOW_HOSTNAME`). Generic mode: optional. |
| `TLS_VERIFY` | `true` | Only for testing. |
| `TLS_CA_FILE` | empty | PEM file with a private CA, trusted in addition to the system CAs. |
| `CARDDAV_URL` | mailcow: `<MAILCOW_INTERNAL_URL or MAILCOW_URL>/SOGo/dav/` | For `find_contacts`. Generic mode: unset disables the tool. |
| `FOLDER_SENT`, `FOLDER_DRAFTS`, `FOLDER_JUNK`, `FOLDER_TRASH` | empty | Folders are found by their SPECIAL-USE flag, then by these names, then by common names. |

### Behaviour and limits

| Variable | Default | |
|---|---|---|
| `ALLOWED_DOMAINS` | empty (any) | Comma-separated domains allowed to sign in. |
| `FROM_NAMES` | empty | Default display names in From when a client gives no `from_name`: `jan@example.com=Jan Novák; sales@example.com=Sales` (or one per line). `my_addresses` returns them. |
| `TIMEZONE` | system (UTC in the container) | Time zone of the Date header, e.g. `Europe/Prague`. The mailcow kit copies mailcow's `TZ`. |
| `SAVE_SENT` | `always` | `always`, `never`, or `auto` (skip for servers that file sent mail themselves, e.g. Gmail). |
| `SEND_LIMIT_HOUR`, `SEND_LIMIT_DAY` | `30`, `300` | Messages per mailbox. |
| `MAX_MESSAGE_MB` | `15` | Largest outgoing message, attachments included (1–100). |

### Runtime

| Variable | Default | |
|---|---|---|
| `DATA_DIR` | `/data` | Database and audit log. Must be writable. |
| `PORT` | `8090` | |
| `HOST` | `0.0.0.0` | Address to listen on. |

## broker (`mailcow-mcp broker`)

| Variable | Default | |
|---|---|---|
| `MAILCOW_API_URL` | required | Internal URL of mailcow's nginx, e.g. `https://nginx-mailcow`; https only. |
| `TLS_SERVER_NAME` | required | mailcow's hostname, for the certificate check. |
| `TLS_VERIFY`, `TLS_CA_FILE` | `true`, empty | As for the app. |
| `MAILCOW_API_KEY` | required | The read-write key. Restrict "Allow API access from" to the broker's address. |
| `MAILCOW_OAUTH_PROFILE_URL` | `<MAILCOW_API_URL>/oauth/profile` | Where the broker asks mailcow whose OAuth token it got. |
| `BROKER_SHARED_SECRET` | required | Same as the app's. |
| `BROKER_SIGNING_KEY` | required | Signs capability tokens. Broker only; back it up. |
| `DATA_DIR`, `PORT`, `HOST` | `/data`, `8091`, `0.0.0.0` | The kit sets `HOST` to the broker's internal-network address. |

## Fixed limits

Not configurable: access tokens 1 hour; refresh tokens 30 days since last use; sign-in requests
15 minutes; unused client registrations 24 hours; 20 registrations per IP per hour; 10 sign-in
attempts per IP per 10 minutes; 10 failed sign-ins per mailbox per 15 minutes; 10 new mailcow
connections per mailbox per hour; 50 recipients, 10 attachments and a 1,000,000-character body per
message.

## CLI

Run inside the app container (`docker compose exec app mailcow-mcp <command>`):

| Command | |
|---|---|
| `generate-key` | Print a new key. |
| `migrate` | Apply database migrations (also done on start). |
| `users` | Connected mailboxes, with clients and last use. |
| `clients` | Registered MCP clients. |
| `revoke <mailbox>` | Disconnect a mailbox (and delete its `MCP: ` app passwords). |
| `revoke --all` | Disconnect everyone (before uninstalling). |
| `healthcheck` | Exit 0 if the local server answers (used by the container health check). |
