"""mcp-fleet-doctor — config-level diagnostics for MCP server fleets.

Reads the configs where MCP servers are actually declared (Claude Desktop,
Cursor, Windsurf, VS Code, Hermes, or any JSON/YAML file), and probes every
configured server the same way a real client would: spawn, MCP `initialize`
handshake, `tools/list`. Verdicts tell you not only *that* a server is broken,
but *why* — parsed from its own stderr.

Zero runtime dependencies (JSON configs). YAML configs are supported when
PyYAML happens to be installed; a minimal built-in parser is the fallback.
"""

__version__ = "0.1.0"
