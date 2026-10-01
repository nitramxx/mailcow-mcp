# mailcow MCP

A self-hosted **remote MCP server for [mailcow](https://mailcow.email)**. Connect your mailbox to any
MCP client (Claude, Cursor, VS Code, Claude Code, …) by URL, sign in with your mailcow account,
and an agent can send, draft, read and follow up on email: attachments, reply tracking, rescuing
replies from spam and quarantine, delivery status and contacts.

> **Status: early development (phase 0 of 8).** Nothing is usable yet. Only the scaffold,
> configuration validation and key generation exist. Don't deploy it.

> This is a community project. It is not affiliated with or endorsed by the mailcow team or
> The Infrastructure Company GmbH.

## How it works (planned)

- **mailcow mode** (default): users sign in on mailcow's own login page (including 2FA). The
  server then creates a scoped app password (IMAP, SMTP, DAV) for that mailbox automatically.
- **generic mode**: password login against any IMAP/SMTP server, without the mailcow-only tools.
- Two containers from one image: the internet-facing **app** has no mailcow API key. The internal
  **broker** holds the API key and runs only a fixed set of mailbox-scoped operations.

The full design is in [SPEC.md](SPEC.md).

## Development

Requires [uv](https://docs.astral.sh/uv/).

```sh
uv sync
uv run pytest
uv run ruff check . && uv run ruff format --check . && uv run mypy
uv run mailcow-mcp generate-key
```

## License

[MIT](LICENSE)
