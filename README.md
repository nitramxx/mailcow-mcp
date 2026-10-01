# mailcow MCP

A self-hosted **remote MCP server for [mailcow](https://mailcow.email)**. Connect your mailbox to any
MCP client (Claude, Cursor, VS Code, Claude Code, …) by URL, sign in with your mailcow account,
and an agent can send, draft, read and follow up on email: attachments, reply tracking, rescuing
replies from spam and quarantine, delivery status and contacts.

> **Status: early development (phase 4 of 8).** Generic and mailcow sign-in, sending, drafts,
> attachments, reading, follow-up and Junk rescue work. Don't deploy it yet.

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

Run it locally in generic mode against any IMAP server, then connect an MCP client (for example
[MCP Inspector](https://github.com/modelcontextprotocol/inspector)) to `http://localhost:8090/mcp`:

```sh
mkdir -p data
MODE=generic PUBLIC_URL=http://localhost:8090 TRUSTED_PROXIES=127.0.0.1 DATA_DIR=./data \
  IMAP_HOST=imap.example.org ENC_KEY=$(uv run mailcow-mcp generate-key) \
  uv run mailcow-mcp serve
```

## License

[MIT](LICENSE)
