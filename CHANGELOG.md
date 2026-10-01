# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/). Breaking configuration changes happen only in major
versions and are described in `docs/upgrading.md`.

## [Unreleased]

### Added

- Project scaffold: package layout, `serve` / `broker` commands with a `/healthz` endpoint.
- Configuration validation for app and broker. A container refuses to start on a missing or
  invalid setting and lists every problem at once.
- `generate-key` command for `ENC_KEY`, `BROKER_SIGNING_KEY` and `BROKER_SHARED_SECRET`.
- Dockerfile (non-root, works with a read-only root filesystem), CI and release workflows,
  Dependabot.
