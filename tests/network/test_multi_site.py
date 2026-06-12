"""Multi-site smoke tests (Step 5, Part B).

Exercises the dispatcher's per-controller routing through the FastMCP tool
layer. Uses two named controllers ('home', 'office') with distinct stub state
so we can prove tools called with ``controller="home"`` only see home state.

Coverage targets:
1. Tools route to the right controller's backend.
2. Mutations on one controller do NOT bleed into the other.
3. Unknown controller surfaces a clear error (no silent default fallback).
4. Default behavior (``controller`` arg omitted) still works against a
   single-controller stub.
5. Backward compat: legacy ``UNIFI_HOST`` + ``UNIFI_API_KEY`` env still
   produces a working single-controller registry.
"""

from __future__ import annotations

import pytest
from fastmcp import FastMCP

from mcp_unifi.clients.stubs import StubState
from mcp_unifi.config import Settings
from mcp_unifi.server import build_server
from tests.network.conftest import _call


async def test_list_devices_isolated_per_controller(
    multi_site_server: FastMCP,
    two_controller_states: dict[str, StubState],
) -> None:
    """``list_devices`` against home and office returns each controller's data."""
    home_devices = await _call(multi_site_server, "list_devices", {"controller": "home"})
    office_devices = await _call(multi_site_server, "list_devices", {"controller": "office"})

    home_names = {d["name"] for d in home_devices}
    office_names = {d["name"] for d in office_devices}

    assert "Home Gateway" in home_names
    assert "Office Gateway" in office_names
    # Per-controller markers must NOT appear in the other controller's data.
    assert "Office Gateway" not in home_names
    assert "Home Gateway" not in office_names


async def test_create_vlan_does_not_leak_across_controllers(
    multi_site_server: FastMCP,
) -> None:
    """A VLAN created on home is not visible from office."""
    created = await _call(
        multi_site_server,
        "create_vlan",
        {
            "name": "HomeIoT",
            "vlan_id": 50,
            "subnet": "10.0.50.0/24",
            "controller": "home",
        },
    )
    assert created["vlan"] == 50

    home_nets = await _call(multi_site_server, "list_networks", {"controller": "home"})
    office_nets = await _call(multi_site_server, "list_networks", {"controller": "office"})

    home_vlans = {n.get("vlan") for n in home_nets}
    office_vlans = {n.get("vlan") for n in office_nets}

    assert 50 in home_vlans
    assert 50 not in office_vlans
    # Office should still only have its seed networks (LAN + WAN, no vlan tag).
    assert len(office_nets) == 2


async def test_unknown_controller_returns_clear_error(
    multi_site_server: FastMCP,
) -> None:
    """Calling a tool with an unconfigured controller name surfaces a clear error.

    Behavior must NOT silently fall back to ``"default"`` — that would let a
    typo silently target the wrong site. As of the ``resolve_backend()`` helper,
    the dispatcher's ``UnknownControllerError`` is normalised to a ``UniFiError``
    and returned through the tool's standard ``err()`` envelope rather than
    raised, so the caller sees a structured error instead of a transport-level
    exception.
    """
    result = await _call(multi_site_server, "list_devices", {"controller": "ghost"})
    msg = result["error"]
    assert "ghost" in msg
    assert "home" in msg and "office" in msg  # available controllers listed


async def test_default_controller_works_when_arg_omitted(
    stub_server: FastMCP,
) -> None:
    """Single-controller stub: omitting ``controller`` uses the ``"default"`` backend."""
    devices = await _call(stub_server, "list_devices")
    assert any(d["model"] == "UCGFiber" for d in devices)
    # Same call with explicit controller="default" must return the same data.
    devices_default = await _call(stub_server, "list_devices", {"controller": "default"})
    assert {d["mac"] for d in devices} == {d["mac"] for d in devices_default}


async def test_legacy_single_controller_env_still_works(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``UNIFI_HOST`` + ``UNIFI_API_KEY`` env auto-promotes to controllers=[default].

    The pre-v0.5 deployment shape (single controller, no YAML file) must keep
    booting unchanged. ``Settings._assemble_controllers`` handles the promotion.
    """
    for var in (
        "STUB_MODE",
        "UNIFI_HOST",
        "UNIFI_API_KEY",
        "UNIFI_PORT",
        "UNIFI_SITE",
        "UNIFI_VERIFY_SSL",
        "MCP_UNIFI_CONTROLLERS_FILE",
        "MCP_UNIFI_AUTH_TOKENS",
        "MCP_UNIFI_AUTH_REQUIRED",
    ):
        monkeypatch.delenv(var, raising=False)

    monkeypatch.setenv("UNIFI_HOST", "legacy.example.com")
    monkeypatch.setenv("UNIFI_API_KEY", "legacy-key-from-env")
    monkeypatch.setenv("STUB_MODE", "true")

    settings = Settings(log_format="text", auth_required=False)
    assert len(settings.controllers) == 1
    assert settings.controllers[0].name == "default"
    assert settings.controllers[0].host == "legacy.example.com"
    assert settings.controllers[0].api_key.get_secret_value() == "legacy-key-from-env"

    server = build_server(settings)
    devices = await _call(server, "list_devices")
    assert any(d["model"] == "UCGFiber" for d in devices)
