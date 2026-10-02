# Connecting MCP clients

Every client needs only the server URL: `https://mcp.example.com/mcp` (your hostname). On first
use the client opens a browser window with the sign-in page; after you sign in, it's connected.
Clients register themselves automatically (OAuth dynamic client registration).

You'll see a consent page first. It shows **which app is asking** (the name the app gave itself)
and **where access goes** (the host it redirects to, or "an app on this computer"). Only continue
if you started connecting that app yourself.

## Claude (claude.ai, Claude Desktop, mobile)

Remote MCP servers are added as **custom connectors**.

- **Pro and Max:** Settings → Connectors → Add custom connector → name and URL → Add, then
  Connect.
- **Team and Enterprise:** an owner adds the connector once for the organisation (Organization
  settings → Connectors → Add custom connector); then each member opens Settings → Connectors and
  clicks Connect to sign in with their own mailbox.

Desktop and mobile use the connectors from your claude.ai account.

In a conversation, enable the connector in the tools menu. Claude asks before it uses a tool;
**keep that confirmation for sending and releasing tools** (`send_email`, `send_draft`,
`release_from_quarantine`, `delete_from_quarantine`). Read the email it's about to send. Don't
choose "always allow" for those. See [security.md](security.md) for why.

## Claude Code

```sh
claude mcp add --transport http mail https://mcp.example.com/mcp
```

Then `/mcp` in Claude Code → select `mail` → Authenticate. Your browser opens for the sign-in.

## Cursor

`~/.cursor/mcp.json` (or `.cursor/mcp.json` in a project):

```json
{
  "mcpServers": {
    "mail": { "url": "https://mcp.example.com/mcp" }
  }
}
```

Cursor shows the server in Settings → MCP; click Connect / Needs login to sign in.

## VS Code (GitHub Copilot agent mode)

Command palette → **MCP: Add Server** → HTTP → URL, or in `.vscode/mcp.json`:

```json
{
  "servers": {
    "mail": { "type": "http", "url": "https://mcp.example.com/mcp" }
  }
}
```

Start the server from the file or the MCP view; VS Code asks to sign in.

## MCP Inspector (testing)

```sh
npx @modelcontextprotocol/inspector
```

Transport **Streamable HTTP**, URL `https://mcp.example.com/mcp`, Connect.

## Several mailboxes

One connector can use several mailboxes. Ask the assistant to connect another one ("connect my
info@ mailbox too"): it gives you a link; open it, sign in with that mailbox, done. If your browser
is signed in to mailcow as another mailbox, open the link in a private window. The assistant then
sees all of them (`list_mailboxes`) and names the mailbox in every call.

## Disconnecting

- In the client: remove or disconnect the server (this revokes the connection, all its mailboxes).
- One mailbox: ask the assistant to remove it (`remove_mailbox`).
- mailcow: delete the app password named `MCP: <app> (…)` under **App passwords**; the app is
  disconnected and asked to sign in again on its next request.
- Administrators: `docker compose exec app mailcow-mcp revoke user@example.com`.

Connections end by themselves after 30 days without use.
