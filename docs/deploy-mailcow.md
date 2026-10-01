# Deploying next to mailcow

This guide adds mailcow-mcp to an existing [mailcow-dockerized](https://docs.mailcow.email)
server. Afterwards your users add one URL to Claude (or another MCP client), sign in with their
mailcow account, and nothing else.

mailcow-mcp runs as its own compose project, for example in `/opt/mailcow-mcp`. **mailcow's own
files are not changed** (apart from one nginx file you add in step 7), so mailcow's `update.sh`
keeps working.

Supported mailcow versions: **2026-07 and later** (tested against the API of 2026-09).

What you'll end up with:

```
MCP client ──HTTPS──> mailcow nginx ──> app (mcp.example.com)   ── IMAP/SMTP/CardDAV ──> dovecot, postfix, SOGo
                                         │  internal network only
                                         └─> broker ──> mailcow API (read-write key)
```

- **app**: the MCP server users connect to. It has no mailcow API key.
- **broker**: a small internal service that holds the API key and can only create and delete
  app passwords for mailboxes that signed in, and read their quarantine and delivery log. It is
  not reachable through nginx or from mailcow's network.

Throughout this guide `mcp.example.com` is the new hostname for the MCP server and
`mail.example.com` is your `MAILCOW_HOSTNAME`. Replace both.

## Before you start

- A working mailcow with admin access to its UI and a shell on the server (root or the user that
  runs mailcow).
- Docker with the compose plugin (mailcow already needs it).
- `git`, `openssl` (usually installed).

**Ownership:** keep `/opt/mailcow-dockerized` as mailcow installs it (root): mailcow's update
script and containers expect that. `/opt/mailcow-mcp` can belong to your own user; run
`setup-mailcow.sh` with `sudo` (it reads `mailcow.conf` and mailcow's certificate, and writes the
nginx file into mailcow's directory). The files it writes into `/opt/mailcow-mcp` get that
directory's owner. `docker compose` works as your user if it's in the `docker` group, which is
effectively root access, so this is about tidiness, not a security boundary.

## 1. DNS

Create `A` (and `AAAA`, if mailcow has IPv6) records for `mcp.example.com` pointing to the mailcow
server, the same addresses as `mail.example.com`.

**Verify:** `dig +short mcp.example.com` shows the server's address.

## 2. Certificate

mailcow's ACME container gets one certificate for all names. Add the new name to
`ADDITIONAL_SAN` in `mailcow.conf`:

```sh
cd /opt/mailcow-dockerized
grep ^ADDITIONAL_SAN mailcow.conf      # see what's there
# edit mailcow.conf, e.g.  ADDITIONAL_SAN=autodiscover.*,autoconfig.*,mcp.example.com
docker compose up -d                   # recreates acme-mailcow with the new setting
docker compose logs --tail=50 acme-mailcow
```

`docker compose up -d` is needed: a plain restart doesn't re-read `mailcow.conf`.

**Verify:** after a minute or two the log says the certificate was renewed, and
`echo | openssl s_client -connect mail.example.com:443 -servername mcp.example.com 2>/dev/null | openssl x509 -noout -ext subjectAltName`
lists `mcp.example.com`.

**Troubleshooting:** ACME validates over HTTP: port 80 must reach the server, and the DNS record
from step 1 must already resolve. Forcing a new attempt:
`touch data/assets/ssl/force_renew && docker compose restart acme-mailcow`.

## 3. Get the kit and run the setup helper

```sh
git clone https://github.com/nitramxx/mailcow-mcp /opt/mailcow-mcp-src
mkdir -p /opt/mailcow-mcp
cp /opt/mailcow-mcp-src/deploy/mailcow/* /opt/mailcow-mcp/
cd /opt/mailcow-mcp
./setup-mailcow.sh --hostname mcp.example.com --mailcow-dir /opt/mailcow-dockerized
```

The helper is **read-only** unless you add `--apply`. It reads `mailcow.conf`, finds mailcow's
Docker network, picks two free fixed addresses on it (one for the app, one for the broker), and
**checks every step of this guide** against mailcow's actual state: DNS, the certificate file,
the OAuth2 app and API key (in mailcow's database), the Fail2ban allowlist (in mailcow's Redis),
and whether mailcow-mcp is running. Each step shows ✓ (done), ✗ (to do) or ? (couldn't check),
and only the open steps are listed with exact values. Run it as often as you like: after each
step below, run it again to confirm.

Note the two addresses it picks (`app address`, `broker address`). They're the containers' own
fixed addresses **inside mailcow's Docker network**, not your server's public IP. You enter them
in mailcow in steps 5 and 6, and they're saved in `/opt/mailcow-mcp/.env` (`APP_IP`, `BROKER_IP`),
so they stay the same. The examples below use `172.22.1.231` (app) and `172.22.1.232` (broker),
which is what you get with mailcow's default network `172.22.1.0/24`; use the ones the helper
printed for you.

## 4. OAuth2 app in mailcow

mailcow UI → **System → Configuration → Access → OAuth2 Apps → Add OAuth2 client**.

- Redirect URI: `https://mcp.example.com/oauth/mailcow/callback` (exactly this)

You don't need to copy the client ID and secret: the helper reads them from mailcow's database
(or pass `--oauth-client-id` and `--oauth-client-secret`).

## 5. API key

mailcow UI → **System → Configuration → Access → Administrators**, section **API**:

- In **Read-Write Access**, activate the key. (The helper reads the key from mailcow's database;
  or pass `--api-key`.)
- **Allow API access from**: add the broker's address, e.g. `172.22.1.232`.

**mailcow has only one read-write API key.** If something else already uses it (backups, a
provisioning script), keep its addresses in the list and add the broker's. The key never reaches
the internet-facing app: only the broker has it, and the broker accepts requests only from the
app, with a shared secret, for mailboxes that signed in.

## 6. Fail2ban allowlist

mailcow UI → **System → Configuration → Options → Fail2ban parameters** → add the **app's**
address (e.g. `172.22.1.231`) to the allowlist.

Why: every user's IMAP and SMTP login comes from this one container. Without the allowlist,
someone guessing passwords on the MCP sign-in page would get the container banned, and everyone
would lose access. mailcow-mcp has its own limits instead (failed sign-ins per IP and per mailbox).

## 7. Write the configuration and start

```sh
cd /opt/mailcow-mcp
./setup-mailcow.sh --hostname mcp.example.com --mailcow-dir /opt/mailcow-dockerized --apply
docker compose up -d
docker compose ps                        # both healthy after ~20 s
cd /opt/mailcow-dockerized && docker compose restart nginx-mailcow
```

`--apply` writes three files **in `/opt/mailcow-mcp`, next to `docker-compose.yml`** (mode 600):

- `.env`: compose settings (image version, network, the two addresses);
- `app.env`: the app's settings, including the OAuth2 client and a fresh `ENC_KEY`;
- `broker.env`: the broker's settings, including the API key and a fresh `BROKER_SIGNING_KEY`;

and the nginx site file `data/conf/nginx/mailcow-mcp.conf` into mailcow (checked with `nginx -t`;
if nginx rejects it, it's renamed to `.disabled` so mailcow's nginx keeps working). Running it
again never replaces existing keys; it only fills in values that are still empty (for example the
OAuth2 client, once you've created it).

Then run `./setup-mailcow.sh --hostname mcp.example.com` once more: step 7 should show ✓.

The nginx file only routes `mcp.example.com` to the app, never the broker. It resolves the app at
request time, so **mailcow's nginx starts and keeps working when mailcow-mcp is stopped**: MCP
requests then get `502`, everything else is unaffected.

## 8. Back up the keys

Copy these two values somewhere off the server (a password manager):

- `ENC_KEY` in `app.env`: encrypts the stored app passwords.
- `BROKER_SIGNING_KEY` in `broker.env`: signs the broker's capability tokens.

If either is lost, every user has to reconnect (nothing else is lost).

## 9. Verify

```sh
curl -fsS https://mcp.example.com/healthz                    # {"status":"ok","role":"app",…}
curl -s -o /dev/null -w '%{http_code}\n' https://mcp.example.com/mcp   # 401: sign-in required
```

1. **Sign in from MCP Inspector:** `npx @modelcontextprotocol/inspector`, transport Streamable
   HTTP, URL `https://mcp.example.com/mcp`, Connect. You should see the consent page, then
   mailcow's own login (with 2FA if enabled), then the tool list.
2. **App password:** in mailcow, sign in as that user → **App passwords**: there is one named
   `MCP: MCP Inspector (…)`.
3. **mailcow without mailcow-mcp:** `cd /opt/mailcow-mcp && docker compose stop`; the mailcow UI
   and webmail still load, `https://mcp.example.com/healthz` gives 502. Then `docker compose start`.
4. **The broker is unreachable from outside:** from another machine,
   `curl -m 5 http://<server>:8091/` must fail (no port is published), and
   `https://mcp.example.com/v1/provision` must give 404 (nginx doesn't route it).

Then connect your MCP client: see [clients.md](clients.md).

## Troubleshooting

| Symptom | Check |
|---|---|
| Consent page: "mailcow can't be reached" | `docker compose logs app`. The app reaches mailcow at `https://nginx-mailcow` (`MAILCOW_INTERNAL_URL`); the certificate is checked against `TLS_SERVER_NAME` (your `MAILCOW_HOSTNAME`). |
| "Signing in with mailcow didn't work" | `docker compose logs app broker`. Typical: redirect URI in the OAuth2 app not exactly `https://mcp.example.com/oauth/mailcow/callback`; wrong client secret; API key not active or the broker's address missing from "Allow API access from" (the broker log says `HTTP 401`/`403`). |
| Sign-in loops back to mailcow's login | Someone is logged into the mailcow UI as **admin** in the same browser. Sign out of mailcow first, or use another browser profile. |
| `502` on `https://mcp.example.com` | The app isn't running or not healthy: `docker compose ps`, `docker compose logs app`. |
| Tools fail with "can't be reached" | IMAP/SMTP: `IMAP_HOST=dovecot-mailcow`, `SMTP_HOST=postfix-mailcow` must resolve on mailcow's network (the kit attaches the app to it). |
| Users locked out after failed logins | The app's address isn't in the Fail2ban allowlist (step 6); unban it in mailcow. |
| Container exits at start | It prints every configuration problem: `docker compose logs app`. |

Useful commands, run in `/opt/mailcow-mcp`:

```sh
docker compose exec app mailcow-mcp users        # connected mailboxes
docker compose exec app mailcow-mcp clients      # registered MCP clients
docker compose exec app mailcow-mcp revoke user@example.com   # disconnect a mailbox
docker compose logs -f app broker                # includes the audit log (JSON lines)
```

## Upgrading

See [upgrading.md](upgrading.md). In short: set `MCP_VERSION` in `.env` (or keep `latest`), then
`docker compose pull && docker compose up -d`.

## Uninstall

```sh
cd /opt/mailcow-mcp
docker compose exec app mailcow-mcp revoke --all   # deletes all "MCP: " app passwords
docker compose down -v                             # -v also deletes the data volumes
rm /opt/mailcow-dockerized/data/conf/nginx/mailcow-mcp.conf
cd /opt/mailcow-dockerized && docker compose restart nginx-mailcow
```

Then, in mailcow: delete the OAuth2 app, remove the broker's address from "Allow API access from"
(and deactivate the API key if nothing else uses it), remove the app's address from the Fail2ban
allowlist, and remove `mcp.example.com` from `ADDITIONAL_SAN` (then `docker compose up -d`).
Finally delete the DNS record.
