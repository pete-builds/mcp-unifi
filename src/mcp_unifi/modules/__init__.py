"""Tool modules for mcp-unifi.

Each subpackage exposes ``register(mcp, settings, registry)``. The dispatcher
imports them based on ``MCP_UNIFI_MODULES_ENABLED`` (default: ``"network"``).
"""
