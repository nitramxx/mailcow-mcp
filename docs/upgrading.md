# Upgrading

mailcow-mcp follows [Semantic Versioning](https://semver.org/). Before 1.0, a minor version
(`0.x.0`) may change configuration or behaviour; it's listed here and in the
[changelog](../CHANGELOG.md). Patch versions never do. From 1.0, breaking configuration changes
happen only in major versions.

Image tags: `X.Y.Z`, `X.Y` (latest patch of a minor version), from 1.0 also `X`, and `latest`.
The mailcow kit's `update` pins `MCP_VERSION` in `.env` to the exact release it installs (its
compose and nginx files belong to that version). With the generic kit you can pin `X.Y` to get
fixes without surprises.

## How to upgrade

mailcow kit:

```sh
cd /opt/mailcow-mcp
sudo ./setup-mailcow.sh update          # latest release; or: update 0.2.0
```

This replaces the kit files with the release's (verified by checksum, changes shown), pins
`MCP_VERSION` in `.env` to it, pulls, restarts and runs the checks. `.env`, `app.env` and
`broker.env` are never overwritten. `update --no-restart` only installs the files.

Generic kit (Caddy):

```sh
cd /opt/mailcow-mcp
curl -fsSL https://github.com/nitramxx/mailcow-mcp/releases/latest/download/generic-kit.tar.gz | tar xz
# set MCP_VERSION in .env to the new version (or keep latest)
docker compose pull && docker compose up -d
```

The archive contains no `.env` or `app.env`, so extracting it over an existing installation is
safe.

Database migrations run automatically on start. Downgrading to a version with an older database
schema isn't supported (an older image refuses to start on a newer database): back up the volumes
first if you might want to go back. Back up both, `app-data` and `broker-data` (without the broker's
records every connection has to sign in again):

```sh
for v in app-data broker-data; do
  docker run --rm -v "mailcow-mcp_$v:/data" -v "$PWD":/backup alpine tar czf "/backup/$v.tgz" -C /data .
done
```

## mailcow updates

mailcow's `update.sh` doesn't change mailcow-mcp's files, but mailcow-mcp's containers are attached
to mailcow's Docker network, and an update may need to remove or recreate that network (for
example when it changes IPv6 settings). Stop mailcow-mcp first:

```sh
cd /opt/mailcow-mcp && docker compose stop
cd /opt/mailcow-dockerized && sudo ./update.sh
cd /opt/mailcow-mcp && docker compose start && sudo ./setup-mailcow.sh   # checks; step 9 ✓
```

The supported mailcow versions are listed in the README.

## Version notes

### 0.1.2

The kit is now a release download with an `update` command. If you installed from a git clone,
switch once (your settings stay):

```sh
cd /opt/mailcow-mcp
curl -fsSL https://github.com/nitramxx/mailcow-mcp/releases/download/v0.1.2/mailcow-kit.tar.gz | tar xz
sudo ./setup-mailcow.sh --mailcow-dir /opt/mailcow-dockerized --apply --restart
```

Then the source clone (e.g. `/opt/mailcow-mcp-src`) is no longer needed.

### 0.1.1

Fixes sign-in in browsers. Nothing to change: `docker compose pull && docker compose up -d`.

### 0.1.0

First release; nothing to migrate.
