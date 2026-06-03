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
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier
from starlette.requests import Request
from starlette.responses import JSONResponse

from mcp_unifi import __version__
from mcp_unifi.backends import (
    AccessBackend,
    AccessRealBackend,
    AccessStubBackend,
    Backend,
    ProtectBackend,
    ProtectRealBackend,
    ProtectStubBackend,
    RealBackend,
    StubBackend,
)
from mcp_unifi.clients.access import AccessClient
from mcp_unifi.clients.access_stubs import AccessStubState
from mcp_unifi.clients.protect import ProtectClient
from mcp_unifi.clients.protect_stubs import ProtectStubState
from mcp_unifi.clients.stubs import StubState
from mcp_unifi.clients.unifi import UniFiClient
from mcp_unifi.config import Settings, load_settings
from mcp_unifi.dispatcher import build_registry, register_modules
from mcp_unifi.logging_setup import configure_logging

logger = logging.getLogger("mcp_unifi.server")


def _resolve_version() -> str:
    """Best-effort running-version string for the ``/health`` echo.

    Prefers the installed package metadata (the version baked into the wheel
    at image-build time, i.e. what is actually running), and falls back to the
    in-tree ``__version__`` when the package is not installed (editable/source
    runs that never ran ``pip install``).
    """
    try:
        return _pkg_version("mcp-unifi")
    except PackageNotFoundError:
        return __version__


def build_server(
    settings: Settings,
    *,
    stub: StubState | None = None,
    unifi: UniFiClient | None = None,
    protect_stub: ProtectStubState | None = None,
    protect: ProtectClient | None = None,
    access_stub: AccessStubState | None = None,
    access: AccessClient | None = None,
) -> FastMCP:
    """Construct a FastMCP instance with all modules registered.

    Args:
        settings: Validated runtime configuration. Must have at least one
            controller in ``settings.controllers``.
        stub: Optional :class:`StubState` injected as the ``"default"``
            controller's Network backend. Used by tests to assert against a
            known seeded state. Only honored when ``settings.stub_mode`` is True.
        unifi: Optional :class:`UniFiClient` injected as the ``"default"``
            controller's Network backend. Used by tests to mock HTTP via respx.
            Only honored when ``settings.stub_mode`` is False.
        protect_stub: Optional :class:`ProtectStubState` injected as the
            ``"default"`` controller's Protect backend. Mirrors ``stub`` for
            the Protect module.
        protect: Optional :class:`ProtectClient` injected as the ``"default"``
            controller's Protect backend. Mirrors ``unifi`` for the Protect
            module.
        access_stub: Optional :class:`AccessStubState` injected as the
            ``"default"`` controller's Access backend. Mirrors ``protect_stub``
            for the Access module.
        access: Optional :class:`AccessClient` injected as the ``"default"``
            controller's Access backend. Mirrors ``protect`` for the Access
            module.
    """
    stub_overrides: dict[str, Backend] | None = (
        {"default": StubBackend(stub)} if stub is not None else None
    )
    real_overrides: dict[str, Backend] | None = (
        {"default": RealBackend(unifi)} if unifi is not None else None
    )
    protect_stub_overrides: dict[str, ProtectBackend] | None = (
        {"default": ProtectStubBackend(protect_stub)} if protect_stub is not None else None
    )
    protect_real_overrides: dict[str, ProtectBackend] | None = (
        {"default": ProtectRealBackend(protect)} if protect is not None else None
    )
    access_stub_overrides: dict[str, AccessBackend] | None = (
        {"default": AccessStubBackend(access_stub)} if access_stub is not None else None
    )
    access_real_overrides: dict[str, AccessBackend] | None = (
        {"default": AccessRealBackend(access)} if access is not None else None
    )

    registry = build_registry(
        settings,
        stub_overrides=stub_overrides,
        real_overrides=real_overrides,
        protect_stub_overrides=protect_stub_overrides,
        protect_real_overrides=protect_real_overrides,
        access_stub_overrides=access_stub_overrides,
        access_real_overrides=access_real_overrides,
    )

    auth_provider = _build_auth_provider(settings)
    mcp = FastMCP("UniFi", auth=auth_provider)

    @mcp.custom_route("/health", methods=["GET"])
    async def health(_request: Request) -> JSONResponse:
        """Lightweight liveness endpoint for Docker / Kubernetes healthchecks.

        Returns 200 OK without touching the MCP transport, so the streamable-
        http server doesn't log 406 noise every healthcheck interval. The body
        echoes the running version so deploy checks can read it in one line:
        ``curl .../health | jq .version``. The Docker HEALTHCHECK gates on the
        200 status code, not the body, so the JSON shape is safe.
        """
        return JSONResponse({"status": "ok", "version": _resolve_version()})

    register_modules(mcp, settings, registry)
    return mcp


def _build_auth_provider(settings: Settings) -> StaticTokenVerifier | None:
    """Construct the FastMCP auth provider for the active transport.

    Returns ``None`` on stdio (parent process owns the security boundary, so
    layering bearer-token auth on top is theatre). On HTTP transport: if
    tokens are configured, wraps them in :class:`StaticTokenVerifier`. If no
    tokens and ``auth_required=True`` (the default), raises so the server
    refuses to start unauthenticated. The escape hatch is
    ``MCP_UNIFI_AUTH_REQUIRED=false`` for the single-host trusted-boundary case.
    """
    if settings.mcp_transport == "stdio":
        return None
    tokens = settings.auth_token_map
    if not tokens:
        if settings.auth_required:
            raise ValueError(
                "HTTP transport requires MCP_UNIFI_AUTH_TOKENS. Generate a "
                "token with `openssl rand -hex 32` and set the env var. To "
                "opt out (NOT RECOMMENDED beyond a single-host trusted "
                "boundary), set MCP_UNIFI_AUTH_REQUIRED=false."
            )
        logger.warning(
            "HTTP transport running WITHOUT authentication "
            "(MCP_UNIFI_AUTH_REQUIRED=false). Every connected client has "
            "admin-equivalent access to the UniFi controller."
        )
        return None
    logger.info(
        "HTTP transport authentication enabled",
        extra={"client_ids": sorted(meta["client_id"] for meta in tokens.values())},
    )
    return StaticTokenVerifier(tokens=tokens)


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
