"""MCP tools. Each module registers its tools on the server."""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer

from mailcow_mcp.services import Services
from mailcow_mcp.tools import read, send, spam


def register_tools(mcp: MCPServer[Any], services: Services) -> None:
    send.register(mcp, services)
    read.register(mcp, services)
    spam.register(mcp, services)
