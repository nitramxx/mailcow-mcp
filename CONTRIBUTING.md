# Contributing

Thanks for helping. Please open an issue to discuss larger changes before you send a pull request.
Report security problems privately, as described in [SECURITY.md](SECURITY.md).

## Setup

```sh
uv sync                       # creates .venv with runtime and dev dependencies
uv run pytest                 # tests
uv run ruff check .           # lint
uv run ruff format .          # format
uv run mypy                   # type check (strict)
```

## Guidelines

- Python 3.12, fully typed. CI runs `ruff check`, `ruff format --check`, `mypy` and `pytest`.
- Dependencies are locked in `uv.lock`. Change them with `uv add` / `uv remove` and commit the lock
  file.
- Every new configuration variable goes in `.env.example` and gets validated at startup.
- Never log or store message bodies, attachment contents, passwords or tokens.
- Add a line under "Unreleased" in `CHANGELOG.md` for user-visible changes.
