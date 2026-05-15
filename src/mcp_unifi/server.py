"""MCP UniFi — local-API gateway management for self-hosted UniFi.

Step 3 (v0.5) refactored the per-tool wiring out of this file. ``build_server``
now does three things:

1. Build the :class:`ControllerRegistry` from ``settings.controllers``.
2. Call :func:`register_modules` to import each enabled module
   (default: ``"network"``) and let it wire its own tools.
3. Hand back the FastMCP instance.

Tool definitions live under :mod:`mcp_unifi.modules.<name>`.

Stub mode (``STUB_MODE=true``, default) returns realistic mock payloads so the
server is useful before the gateway hardware is on the network. Flip
``STUB_MODE=false`` and supply ``UNIFI_HOST`` plus ``UNIFI_API_KEY`` (or a
``MCP_UNIFI_CONTROLLERS_FILE``) to talk to real UCG-Fiber, UDM Pro, or other
UniFi OS gateways.

Transport: Streamable HTTP via FastMCP (current MCP spec).
"""

from __future__ import annotations

import logging

from fastmcp import FastMCP

from mcp_unifi.backends import Backend, RealBackend, StubBackend
from mcp_unifi.clients.stubs import StubState
from mcp_unifi.clients.unifi import UniFiClient
from mcp_unifi.config import Settings, load_settings
from mcp_unifi.dispatcher import build_registry, register_modules
from mcp_unifi.logging_setup import configure_logging

logger = logging.getLogger("mcp_unifi.server")


def build_server(
    settings: Settings,
    *,
    stub: StubState | None = None,
    unifi: UniFiClient | None = None,
) -> FastMCP:
    """Construct a FastMCP instance with all modules registered.

    Args:
        settings: Validated runtime configuration. Must have at least one
            controller in ``settings.controllers``.
        stub: Optional :class:`StubState` injected as the ``"default"``
            controller's backend. Used by tests to assert against a known
            seeded state. Only honored when ``settings.stub_mode`` is True.
        unifi: Optional :class:`UniFiClient` injected as the ``"default"``
            controller's backend. Used by tests to mock HTTP via respx. Only
            honored when ``settings.stub_mode`` is False.
    """
    stub_overrides: dict[str, Backend] | None = (
        {"default": StubBackend(stub)} if stub is not None else None
    )
    real_overrides: dict[str, Backend] | None = (
        {"default": RealBackend(unifi)} if unifi is not None else None
    )

    registry = build_registry(
        settings,
        stub_overrides=stub_overrides,
        real_overrides=real_overrides,
    )

    mcp = FastMCP("UniFi")
    register_modules(mcp, settings, registry)
    return mcp


def main() -> None:
    """CLI entrypoint. Dispatches on MCP_TRANSPORT.

    - ``streamable-http`` (default): long-running container / multi-client.
    - ``stdio``: per-session subprocess (Claude Desktop, ``uvx mcp-unifi``).
    """
    settings = load_settings()
    configure_logging(level=settings.log_level, fmt=settings.log_format)
    logger.info("MCP UniFi starting", extra={"config": settings.safe_repr()})
    server = build_server(settings)

    if settings.mcp_transport == "stdio":
        # stdio transport owns stdout for the JSON-RPC framing. Logging is
        # already on stderr (see logging_setup.configure_logging).
        server.run(transport="stdio")
    else:
        server.run(
            transport="streamable-http",
            host=settings.mcp_host,
            port=settings.mcp_port,
        )


if __name__ == "__main__":
    main()
