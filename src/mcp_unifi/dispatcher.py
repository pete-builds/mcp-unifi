"""Controller registry and module loader for mcp-unifi.

The :class:`ControllerRegistry` holds one :class:`Backend` per named
controller. Tools fetch a backend by name (``controller="default"``) instead
of branching on ``settings.stub_mode`` or hard-wiring a single client.

:func:`register_modules` reads ``MCP_UNIFI_MODULES_ENABLED`` (CSV, default
``"network"``) and imports the matching ``mcp_unifi.modules.<name>`` package,
calling its ``register(mcp, settings, registry)`` entrypoint. This keeps the
phase-3 Protect module out of the import path until it's wired in.
"""

from __future__ import annotations

import importlib
import logging
import os
from collections.abc import Callable
from typing import TYPE_CHECKING, Literal, overload

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
from mcp_unifi.clients.access_stubs import make_access_stub_state
from mcp_unifi.clients.protect import ProtectClient
from mcp_unifi.clients.protect_stubs import make_protect_stub_state
from mcp_unifi.clients.stubs import make_stub_state
from mcp_unifi.clients.unifi import UniFiClient, UniFiError

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.config import Settings

logger = logging.getLogger("mcp_unifi.dispatcher")

#: Default module set when ``MCP_UNIFI_MODULES_ENABLED`` is unset.
DEFAULT_MODULES = ("network",)

#: All modules the dispatcher knows how to import. Keep this in sync with the
#: ``src/mcp_unifi/modules/<name>/__init__.py`` packages on disk.
KNOWN_MODULES = frozenset({"network", "protect", "access"})


class UnknownControllerError(KeyError):
    """Raised when a tool requests a controller name that wasn't configured."""


class UnknownModuleError(ValueError):
    """Raised when ``MCP_UNIFI_MODULES_ENABLED`` references an unknown module."""


class ProtectNotAvailableError(RuntimeError):
    """Raised when a Protect tool runs on a registry built without Protect backends.

    The Protect module is opt-in. When ``MCP_UNIFI_MODULES_ENABLED`` does not
    include ``"protect"``, :func:`build_registry` still constructs Protect
    backends so module registration is deterministic; but if a caller wires the
    registry manually without them, this error surfaces a clean message instead
    of an ``AttributeError`` deep inside a tool body.
    """


class AccessNotAvailableError(RuntimeError):
    """Raised when an Access tool runs on a registry built without Access backends.

    The Access module is opt-in (``MCP_UNIFI_MODULES_ENABLED`` must include
    ``"access"``) and additionally requires Access-specific config: either
    ``UNIFI_ACCESS_HOST`` + ``UNIFI_ACCESS_API_KEY`` or per-controller
    ``access_*`` fields in the YAML controllers file. If the module is
    enabled but no controller has Access config, :class:`AccessStubBackend`
    is still wired in stub mode, but real mode raises this on first call so
    the operator sees a clean message.
    """


class ControllerRegistry:
    """Map of controller name → :class:`Backend`.

    Built once at startup from ``settings.controllers`` (and optional injected
    overrides for tests). Tools call ``registry.get(name)`` to route a request
    to the right controller.
    """

    def __init__(
        self,
        backends: dict[str, Backend],
        *,
        protect_backends: dict[str, ProtectBackend] | None = None,
        access_backends: dict[str, AccessBackend] | None = None,
    ) -> None:
        if not backends:
            raise ValueError("ControllerRegistry requires at least one backend.")
        self._backends = dict(backends)
        self._protect_backends: dict[str, ProtectBackend] = (
            dict(protect_backends) if protect_backends else {}
        )
        self._access_backends: dict[str, AccessBackend] = (
            dict(access_backends) if access_backends else {}
        )

    def get(self, name: str) -> Backend:
        try:
            return self._backends[name]
        except KeyError as exc:
            available = ", ".join(sorted(self._backends)) or "(none)"
            raise UnknownControllerError(
                f"Unknown controller '{name}'. Available: {available}."
            ) from exc

    def get_protect(self, name: str) -> ProtectBackend:
        """Return the Protect backend registered for ``name``.

        Raises:
            ProtectNotAvailableError: this registry was built without Protect
                backends (e.g. the Protect module wasn't enabled at startup).
            UnknownControllerError: the controller name is unknown to the
                registry's network backends (the universe of controller names
                is the union of Network and Protect; we surface the same error
                shape either way).
        """
        if not self._protect_backends:
            raise ProtectNotAvailableError(
                "Protect backends are not configured on this registry. "
                "Enable the 'protect' module via MCP_UNIFI_MODULES_ENABLED."
            )
        try:
            return self._protect_backends[name]
        except KeyError as exc:
            available = ", ".join(sorted(self._protect_backends)) or "(none)"
            raise UnknownControllerError(
                f"Unknown controller '{name}'. Available (Protect): {available}."
            ) from exc

    def get_access(self, name: str) -> AccessBackend:
        """Return the Access backend registered for ``name``.

        Raises:
            AccessNotAvailableError: this registry was built without Access
                backends (the Access module wasn't enabled, or the controller
                has no ``access_*`` config in real mode).
            UnknownControllerError: the controller name is unknown to the
                registry's Access backends.
        """
        if not self._access_backends:
            raise AccessNotAvailableError(
                "Access backends are not configured on this registry. "
                "Enable the 'access' module via MCP_UNIFI_MODULES_ENABLED and "
                "set UNIFI_ACCESS_HOST + UNIFI_ACCESS_API_KEY (or per-controller "
                "access_* fields in the controllers YAML)."
            )
        try:
            return self._access_backends[name]
        except KeyError as exc:
            available = ", ".join(sorted(self._access_backends)) or "(none)"
            raise UnknownControllerError(
                f"Unknown controller '{name}'. Available (Access): {available}."
            ) from exc

    def names(self) -> list[str]:
        return sorted(self._backends)

    def __len__(self) -> int:
        return len(self._backends)

    def __contains__(self, name: object) -> bool:
        return name in self._backends


def build_registry(
    settings: Settings,
    *,
    stub_overrides: dict[str, Backend] | None = None,
    real_overrides: dict[str, Backend] | None = None,
    protect_stub_overrides: dict[str, ProtectBackend] | None = None,
    protect_real_overrides: dict[str, ProtectBackend] | None = None,
    access_stub_overrides: dict[str, AccessBackend] | None = None,
    access_real_overrides: dict[str, AccessBackend] | None = None,
) -> ControllerRegistry:
    """Construct a :class:`ControllerRegistry` from settings.

    In stub mode each configured controller gets its own fresh
    :class:`StubBackend` and :class:`ProtectStubBackend` (state is
    per-controller, not shared). In real mode each gets a :class:`RealBackend`
    and :class:`ProtectRealBackend` wrapping per-controller clients.

    Phase 3 (Protect) is always wired into the registry even when the
    ``protect`` module isn't enabled — building the backends is cheap and
    leaves the door open for ad-hoc tools to call ``registry.get_protect(...)``.

    Args:
        settings: Validated :class:`Settings` instance. Must have at least one
            entry in ``settings.controllers``.
        stub_overrides: Optional ``{name: Backend}`` map that wins over the
            stub defaults for the matching names. Used by tests to inject a
            specific :class:`StubState`.
        real_overrides: Optional ``{name: Backend}`` map for real mode (used
            by tests passing a respx-mocked :class:`UniFiClient`).
        protect_stub_overrides: Optional ``{name: ProtectBackend}`` map that
            wins over the Protect stub defaults. Used by tests to inject a
            specific :class:`ProtectStubState`.
        protect_real_overrides: Optional ``{name: ProtectBackend}`` map for
            real-mode Protect tests (respx-mocked :class:`ProtectClient`).
        access_stub_overrides: Optional ``{name: AccessBackend}`` map that
            wins over the Access stub defaults. Used by tests to inject a
            specific :class:`AccessStubState`.
        access_real_overrides: Optional ``{name: AccessBackend}`` map for
            real-mode Access tests (respx-mocked :class:`AccessClient`).
    """
    backends: dict[str, Backend] = {}
    protect_backends: dict[str, ProtectBackend] = {}
    access_backends: dict[str, AccessBackend] = {}
    overrides = (stub_overrides if settings.stub_mode else real_overrides) or {}
    protect_overrides = (
        protect_stub_overrides if settings.stub_mode else protect_real_overrides
    ) or {}
    access_overrides = (
        access_stub_overrides if settings.stub_mode else access_real_overrides
    ) or {}

    for ctrl in settings.controllers:
        if ctrl.name in overrides:
            backends[ctrl.name] = overrides[ctrl.name]
        elif settings.stub_mode:
            backends[ctrl.name] = StubBackend(make_stub_state())
        else:
            client = UniFiClient(
                host=ctrl.host,
                api_key=ctrl.api_key.get_secret_value(),
                port=ctrl.port,
                site=ctrl.site,
                verify_ssl=ctrl.verify_ssl,
            )
            backends[ctrl.name] = RealBackend(client)

        if ctrl.name in protect_overrides:
            protect_backends[ctrl.name] = protect_overrides[ctrl.name]
        elif settings.stub_mode:
            protect_backends[ctrl.name] = ProtectStubBackend(make_protect_stub_state())
        else:
            protect_client = ProtectClient(
                host=ctrl.host,
                api_key=ctrl.api_key.get_secret_value(),
                port=ctrl.port,
                verify_ssl=ctrl.verify_ssl,
            )
            protect_backends[ctrl.name] = ProtectRealBackend(protect_client)

        # Access is configured per-controller and may legitimately be absent
        # in real mode if the operator has no Access hub. Stub mode always
        # gets a backend so the dispatcher can register Access tools without
        # branching on hardware presence.
        if ctrl.name in access_overrides:
            access_backends[ctrl.name] = access_overrides[ctrl.name]
        elif settings.stub_mode:
            access_backends[ctrl.name] = AccessStubBackend(make_access_stub_state())
        elif ctrl.access_host and ctrl.access_api_key:
            access_client = AccessClient(
                host=ctrl.access_host,
                api_key=ctrl.access_api_key.get_secret_value(),
                port=ctrl.access_port,
                verify_ssl=ctrl.verify_ssl,
            )
            access_backends[ctrl.name] = AccessRealBackend(access_client)

    return ControllerRegistry(
        backends,
        protect_backends=protect_backends,
        access_backends=access_backends,
    )


@overload
def resolve_backend(
    registry: ControllerRegistry, controller: str, kind: Literal["network"] = ...
) -> Backend: ...
@overload
def resolve_backend(
    registry: ControllerRegistry, controller: str, kind: Literal["protect"]
) -> ProtectBackend: ...
@overload
def resolve_backend(
    registry: ControllerRegistry, controller: str, kind: Literal["access"]
) -> AccessBackend: ...
def resolve_backend(
    registry: ControllerRegistry,
    controller: str,
    kind: Literal["network", "protect", "access"] = "network",
) -> Backend | ProtectBackend | AccessBackend:
    """Resolve a controller backend for a tool, mapping resolution failures to UniFiError.

    Every tool body wraps its work in ``except UniFiError`` and returns a
    formatted ``err(...)`` envelope. The registry getters, however, raise
    dispatcher-layer errors that are *siblings* of :class:`UniFiError` (all
    subclass :class:`RuntimeError`, none subclass the others), so they would
    otherwise escape the tool's handler and surface as a raw framework error:

    * :class:`AccessNotAvailableError` / :class:`ProtectNotAvailableError` when
      the module is enabled but the registry holds no backend for it (e.g. the
      ``access`` module is on but no controller has ``access_*`` config in real
      mode).
    * :class:`UnknownControllerError` when ``controller`` names a controller the
      registry doesn't know (a typo'd or stale ``controller`` argument).

    Translating them to :class:`UniFiError` here lets every current and future
    tool handle a missing module or unknown controller through the
    ``except UniFiError`` path it already has, with no per-tool change. Callers
    that want the typed errors (tests, non-tool code) keep using the registry
    getters directly.
    """
    getters: dict[str, Callable[[str], Backend | ProtectBackend | AccessBackend]] = {
        "network": registry.get,
        "protect": registry.get_protect,
        "access": registry.get_access,
    }
    try:
        return getters[kind](controller)
    except (
        ProtectNotAvailableError,
        AccessNotAvailableError,
        UnknownControllerError,
    ) as exc:
        raise UniFiError(str(exc)) from exc


def _enabled_modules() -> tuple[str, ...]:
    raw = os.environ.get("MCP_UNIFI_MODULES_ENABLED", "").strip()
    if not raw:
        return DEFAULT_MODULES
    parts = tuple(p.strip() for p in raw.split(",") if p.strip())
    return parts or DEFAULT_MODULES


def register_modules(
    mcp: FastMCP, settings: Settings, registry: ControllerRegistry
) -> tuple[str, ...]:
    """Import each enabled module and call its ``register`` entrypoint.

    Returns the tuple of module names actually registered (in order).

    Raises:
        UnknownModuleError: ``MCP_UNIFI_MODULES_ENABLED`` references a module
            that doesn't exist in ``mcp_unifi.modules``.
    """
    enabled = _enabled_modules()
    registered: list[str] = []
    for name in enabled:
        if name not in KNOWN_MODULES:
            raise UnknownModuleError(f"Unknown module '{name}'. Known: {sorted(KNOWN_MODULES)}")
        module = importlib.import_module(f"mcp_unifi.modules.{name}")
        register_fn = module.register
        register_fn(mcp, settings, registry)
        registered.append(name)
    logger.info(
        "registered modules",
        extra={"modules": registered, "controllers": registry.names()},
    )
    return tuple(registered)


__all__ = [
    "DEFAULT_MODULES",
    "KNOWN_MODULES",
    "AccessNotAvailableError",
    "ControllerRegistry",
    "ProtectNotAvailableError",
    "UnknownControllerError",
    "UnknownModuleError",
    "build_registry",
    "register_modules",
    "resolve_backend",
]
