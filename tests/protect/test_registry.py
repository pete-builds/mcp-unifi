"""Tests for :class:`ControllerRegistry` Protect-specific behaviour.

The registry is the single seam tools cross to reach a backend. These tests
pin the edges: protect-not-configured, unknown-controller, and the happy path
that ``build_registry`` always wires Protect alongside Network.
"""

from __future__ import annotations

import pytest

from mcp_unifi.backends import ProtectStubBackend, StubBackend
from mcp_unifi.clients.protect_stubs import make_protect_stub_state
from mcp_unifi.clients.stubs import make_stub_state
from mcp_unifi.config import ControllerConfig, Settings
from mcp_unifi.dispatcher import (
    ControllerRegistry,
    ProtectNotAvailableError,
    UnknownControllerError,
    build_registry,
)


def test_registry_without_protect_raises() -> None:
    """A registry built with only Network backends raises a clean error."""
    registry = ControllerRegistry(
        {"default": StubBackend(make_stub_state())},
    )
    with pytest.raises(ProtectNotAvailableError):
        registry.get_protect("default")


def test_registry_unknown_controller_raises() -> None:
    """Unknown name on the Protect side surfaces the standard error class."""
    registry = ControllerRegistry(
        {"default": StubBackend(make_stub_state())},
        protect_backends={"default": ProtectStubBackend(make_protect_stub_state())},
    )
    # Known controller for Protect.
    assert registry.get_protect("default") is not None
    # Unknown.
    with pytest.raises(UnknownControllerError):
        registry.get_protect("home")


def test_build_registry_stub_mode_wires_protect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """In stub mode, ``build_registry`` always builds Protect backends."""
    for var in (
        "MCP_UNIFI_CONTROLLERS_FILE",
        "UNIFI_HOST",
        "UNIFI_API_KEY",
    ):
        monkeypatch.delenv(var, raising=False)
    settings = Settings(stub_mode=True, log_format="text")
    registry = build_registry(settings)
    pb = registry.get_protect("default")
    assert isinstance(pb, ProtectStubBackend)


def test_build_registry_real_mode_wires_protect_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Real mode builds a ``ProtectRealBackend`` per controller."""
    for var in ("MCP_UNIFI_CONTROLLERS_FILE",):
        monkeypatch.delenv(var, raising=False)
    settings = Settings(
        stub_mode=False,
        log_format="text",
        controllers=[ControllerConfig(name="default", host="example", api_key="k", port=443)],
    )
    registry = build_registry(settings)
    from mcp_unifi.backends import ProtectRealBackend

    assert isinstance(registry.get_protect("default"), ProtectRealBackend)
