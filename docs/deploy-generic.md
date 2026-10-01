# Deploying in generic mode (any IMAP/SMTP server)

Generic mode runs only the app, with a password sign-in, against any IMAP/SMTP server (Dovecot,
Postfix, hosted providers that offer IMAP/SMTP). The mailcow-only tools (quarantine, delivery
status, own addresses) aren't available; contacts work if you set `CARDDAV_URL`.

The kit in `deploy/generic` runs the app behind [Caddy](https://caddyserver.com), which gets a
certificate automatically.

## Requirements

- A server with Docker and the compose plugin, ports 80 and 443 free.
- A DNS name for it, e.g. `mcp.example.org` (A/AAAA record).
- IMAP over TLS (993, or 143 with STARTTLS) and SMTP submission over TLS (465, or 587 with
  STARTTLS) with authentication. Unencrypted connections aren't supported.

## Steps

```sh
git clone https://github.com/nitramxx/mailcow-mcp /opt/mailcow-mcp-src
mkdir -p /opt/mailcow-mcp && cp -r /opt/mailcow-mcp-src/deploy/generic/. /opt/mailcow-mcp/
cd /opt/mailcow-mcp
cp .env.example .env            # set MCP_HOSTNAME
cp app.env.example app.env      # set IMAP_*, SMTP_*, ALLOWED_DOMAINS
sed -i "s|^ENC_KEY=.*|ENC_KEY=$(docker run --rm ghcr.io/nitramxx/mailcow-mcp generate-key)|" app.env
chmod 600 app.env
docker compose up -d
docker compose ps               # app healthy after ~20 s
```

**Verify:** `curl -fsS https://mcp.example.org/healthz` returns `{"status":"ok",…}`, and MCP
Inspector (see [clients.md](clients.md)) can connect to `https://mcp.example.org/mcp` and sign in.

Back up `ENC_KEY` outside the server; losing it only means every user has to sign in again.

## Notes

- **Use app passwords** if your mail server offers them. The password users type on the sign-in
  page is checked with an IMAP login and stored encrypted with `ENC_KEY`, so the server can act for
  them.
- **`ALLOWED_DOMAINS`**: set it, so only your own users can sign in. It's checked before the
  password is tried.
- **Rate limits**: failed sign-ins are limited per client IP and per mailbox. If your mail server
  bans IPs after failed logins (Fail2ban), allowlist this server's address there, or one person
  guessing passwords could lock everyone out.
- **Certificates**: the mail servers' certificates are verified against the hostnames you
  configure. For a private CA, mount the CA file and set `TLS_CA_FILE`. If IMAP and SMTP are
  reached by an internal name that isn't on the certificate, set `TLS_SERVER_NAME` to the name
  that is.
- **Gmail and similar**: `SAVE_SENT=auto` skips saving a copy of sent mail where the server does
  that itself.

## Without Caddy

Any reverse proxy works. It must:

- terminate TLS for the public hostname and forward to the app's port 8090;
- not buffer responses (server-sent events) and allow long-lived requests (1 hour);
- set `X-Forwarded-For` to the client's address, and the app's `TRUSTED_PROXIES` must list the
  proxy's address (only then is that header used).

nginx: see the `location` block in `deploy/mailcow/mailcow-mcp.conf.template`.

All settings: [configuration.md](configuration.md).
