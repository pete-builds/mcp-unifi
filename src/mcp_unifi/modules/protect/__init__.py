"""Protect module placeholder for Phase 3.

This package exists so :mod:`mcp_unifi.dispatcher` can import
``mcp_unifi.modules.protect`` and call :func:`register` once
``MCP_UNIFI_MODULES_ENABLED`` includes ``"protect"``. Today it registers zero
tools — Phase 3 fills in cameras, motion events, doorbell controls, etc.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry


def register(
    mcp: FastMCP,
    settings: Settings,
    registry: ControllerRegistry,
) -> None:
    """No-op placeholder. Phase 3 (UniFi Protect) lands the camera tools here."""
    # Intentional no-op: args are accepted to lock the protocol Phase 3 will use.
    del mcp, settings, registry


__all__ = ["register"]
