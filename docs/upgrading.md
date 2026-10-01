# Upgrading

mailcow-mcp follows [Semantic Versioning](https://semver.org/). Before 1.0, a minor version
(`0.x.0`) may change configuration or behaviour; it's listed here and in the
[changelog](../CHANGELOG.md). Patch versions never do. From 1.0, breaking configuration changes
happen only in major versions.

Image tags: `X.Y.Z`, `X.Y` (latest patch of a minor version), from 1.0 also `X`, and `latest`.
Pin `MCP_VERSION` in `.env` to `X.Y` to get fixes without surprises.

## How to upgrade

```sh
cd /opt/mailcow-mcp
# optional: pin or change MCP_VERSION in .env
docker compose pull
docker compose up -d
docker compose ps        # both healthy again
```

Database migrations run automatically on start. Downgrading to a version with an older database
schema isn't supported: back up the volumes first if you might want to go back
(`docker run --rm -v mailcow-mcp_app-data:/data -v "$PWD":/backup alpine tar czf /backup/app-data.tgz -C /data .`).

The kit files (`docker-compose.yml`, the nginx template, `setup-mailcow.sh`) can change between
versions too; compare them with the new release's `deploy/` folder. Your `.env`, `app.env` and
`broker.env` are never overwritten by the setup helper.

mailcow's own `update.sh` doesn't touch mailcow-mcp. After a mailcow update, check that
`https://mcp.example.com/healthz` still answers; the supported mailcow versions are listed in the
README.

## Version notes

### Unreleased → first release

First release; nothing to migrate.
