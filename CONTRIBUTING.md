# Contributing

Thanks for helping. Please open an issue to discuss larger changes before you send a pull request.
Report security problems privately, as described in [SECURITY.md](SECURITY.md).

## Setup

```sh
uv sync                       # creates .venv with runtime and dev dependencies
scripts/check                 # everything CI checks: lint, format, types, tests
uv run pytest                 # tests (integration tests need Docker)
uv run pytest -m "not integration"
uv run ruff check .           # lint
uv run ruff format .          # format
uv run mypy                   # type check (strict)
```

PDF rendering uses WeasyPrint, which needs Pango. On macOS: `brew install pango` and run tests
with `DYLD_FALLBACK_LIBRARY_PATH=/opt/homebrew/lib`. On Debian/Ubuntu:
`apt install libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0`.

Integration tests start a real Dovecot + Postfix server from `tests/mailserver` in Docker
(Docker Desktop, Colima or plain Docker; no bind mounts, so any VM setup works).

## Guidelines

- Python 3.12, fully typed. CI runs `ruff check`, `ruff format --check`, `mypy` and `pytest`.
- Dependencies are locked in `uv.lock`. Change them with `uv add` / `uv remove` and commit the lock
  file.
- Every new configuration variable goes in `.env.example` and gets validated at startup.
- Never log or store message bodies, attachment contents, passwords or tokens.
- Add a line under "Unreleased" in `CHANGELOG.md` for user-visible changes.

## Versioning

[Semantic Versioning](https://semver.org/). The version lives in `pyproject.toml` (and `uv.lock`).

- Before 1.0: a minor bump (`0.x.0`) may break configuration or behaviour; patch releases never do.
- From 1.0: breaking configuration changes only in major versions, always described in
  `docs/upgrading.md`.
- Pre-releases use a suffix, e.g. `v0.3.0-rc.1`. They become GitHub pre-releases and don't
  move the `X.Y` image tag.

Images on `ghcr.io/nitramxx/mailcow-mcp`: `X.Y.Z`, `X.Y`, from 1.0 also `X`, and `latest`.

## Releasing (maintainers)

1. On an up-to-date `main` with green CI, set the version: `uv version X.Y.Z` (updates
   `pyproject.toml` and `uv.lock`).
2. In `CHANGELOG.md`, rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD` and add a new empty
   `## [Unreleased]` above it.
3. Commit (`Release vX.Y.Z`), then tag and push:
   `git tag -a vX.Y.Z -m vX.Y.Z && git push origin main vX.Y.Z`.
4. The release workflow runs CI, checks that the tag matches `pyproject.toml` and that
   `CHANGELOG.md` has a section for the version, publishes the multi-arch image with SBOM and
   provenance, and creates the GitHub release from that changelog section.
