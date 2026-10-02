"""The connection's mailboxes: list_mailboxes, add_mailbox, remove_mailbox."""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

from mailcow_mcp.broker_client import CapabilityRejected
from mailcow_mcp.errors import MailError
from mailcow_mcp.oauth import CONNECT_PATH, CONNECT_REQUEST_TTL, MAX_MAILBOXES_PER_GRANT
from mailcow_mcp.services import Mailbox, Services
from mailcow_mcp.tools.common import NOT_DESTRUCTIVE, READ_ONLY


class ConnectedMailbox(BaseModel):
    address: str = Field(description="Use it as the mailbox parameter of the other tools.")
    name: str | None = Field(default=None, description="The mailbox's name in mailcow.")
    aliases: list[str] = Field(default=[], description="Other addresses it can send from.")
    sign_in: str = Field(description='"mailcow" or "password".')


class MailboxList(BaseModel):
    mailboxes: list[ConnectedMailbox]
    note: str


class ConnectLink(BaseModel):
    url: str
    expires_in_minutes: int
    instructions: str


class Removed(BaseModel):
    removed: str
    remaining: list[str]


def register(mcp: MCPServer[Any], services: Services) -> None:
    @mcp.tool(
        name="list_mailboxes",
        title="List mailboxes",
        description=(
            "The mailboxes connected to this connection, with their addresses, names and "
            "aliases. Every other tool works on one of them: give its address as the mailbox "
            "parameter (required when more than one is connected). Pick the mailbox the user "
            "means; ask if it isn't clear, especially before sending."
        ),
        annotations=READ_ONLY,
    )
    async def list_mailboxes(ctx: Context[Any, Any]) -> MailboxList:
        async with services.connection_tool(ctx, "list_mailboxes") as connection:
            listed = [await _describe(services, m) for m in connection.mailboxes]
            services.audit("list_mailboxes", client=connection.client_name, count=len(listed))
            return MailboxList(
                mailboxes=listed,
                note=(
                    f"Up to {MAX_MAILBOXES_PER_GRANT} mailboxes can be connected: add_mailbox "
                    "gives the user a link to sign in another one."
                ),
            )

    @mcp.tool(
        name="add_mailbox",
        title="Add mailbox",
        description=(
            "Connect another mailbox to this connection. Returns a one-time link for the user "
            "to open in a browser and sign in with that mailbox; afterwards it appears in "
            "list_mailboxes. Give the user the link and the instructions as they are."
        ),
        annotations=NOT_DESTRUCTIVE,
    )
    async def add_mailbox(ctx: Context[Any, Any]) -> ConnectLink:
        async with services.connection_tool(ctx, "add_mailbox") as connection:
            if len(connection.mailboxes) >= MAX_MAILBOXES_PER_GRANT:
                raise ToolError(
                    f"This connection already has {MAX_MAILBOXES_PER_GRANT} mailboxes; remove one "
                    "with remove_mailbox first."
                )
            code = services.provider.create_connect_request(connection.grant_id)
            services.audit("add_mailbox", client=connection.client_name, result="link")
            return ConnectLink(
                url=f"{services.config.public_url}{CONNECT_PATH}?code={code}",
                expires_in_minutes=CONNECT_REQUEST_TTL // 60,
                instructions=(
                    "Open the link and sign in with the mailbox you want to add; it works once. "
                    "If your browser is already signed in to mailcow as another mailbox, open it "
                    "in a private window (or sign out of mailcow first)."
                ),
            )

    @mcp.tool(
        name="remove_mailbox",
        title="Remove mailbox",
        description=(
            "Disconnect one mailbox from this connection (its app password is deleted). The "
            "last mailbox can't be removed: disconnect the app instead. Only when the user asks."
        ),
        annotations=ToolAnnotations(
            read_only_hint=False, destructive_hint=True, idempotent_hint=True, open_world_hint=False
        ),
    )
    async def remove_mailbox(
        ctx: Context[Any, Any],
        mailbox: Annotated[str, Field(description="The address from list_mailboxes.")],
    ) -> Removed:
        async with services.connection_tool(ctx, "remove_mailbox") as connection:
            selected = connection.select(mailbox)
            if len(connection.mailboxes) == 1:
                raise ToolError(
                    "This is the connection's only mailbox: disconnect the app in its settings "
                    "to remove it."
                )
            services.provider.remove_mailbox(
                connection.grant_id, selected.username, reason="revoked"
            )
            remaining = [m.username for m in connection.mailboxes if m != selected]
            return Removed(removed=selected.username, remaining=remaining)


async def _describe(services: Services, mailbox: Mailbox) -> ConnectedMailbox:
    entry = ConnectedMailbox(address=mailbox.username, sign_in=mailbox.login_method)
    if mailbox.capability is None:
        return entry
    try:
        profile = await services.broker_call(mailbox, "aliases")
    except CapabilityRejected:
        return entry  # its tools will report it (and disconnect it)
    except MailError:
        return entry
    entry.name = profile.get("name") or None
    entry.aliases = list(profile.get("aliases", []))
    return entry
