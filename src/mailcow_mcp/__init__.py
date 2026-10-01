"""mailcow-mcp: self-hosted remote MCP server for mailcow."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("mailcow-mcp")
except PackageNotFoundError:  # pragma: no cover - running from a source tree
    __version__ = "0.0.0"
