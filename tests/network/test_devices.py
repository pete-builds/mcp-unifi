"""Tests for ``mcp_unifi.modules.network.devices``.

Split from the pre-Step-5 ``tests/test_tools.py``. Bodies are unchanged.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import httpx
import pytest
import respx
from fastmcp import FastMCP

from mcp_unifi.clients.stubs import StubState
from mcp_unifi.modules.network import devices
from tests.network.conftest import BASE, _call

# ---------------------------------------------------------------------------
# Stub mode
# ---------------------------------------------------------------------------


async def test_list_devices_stub(stub_server: FastMCP) -> None:
    devices = await _call(stub_server, "list_devices")
    assert any(d["model"] == "UCGFiber" for d in devices)


async def test_list_devices_compact_keeps_only_identity_fields(stub_server: FastMCP) -> None:
    """Full device records run to ~35 KB each (issue #124, item 12). The
    opt-in compact view carries what an inventory question needs and the
    default stays the full record so existing callers are untouched."""
    compact = await _call(stub_server, "list_devices", {"compact": True})
    full = await _call(stub_server, "list_devices")
    assert len(compact) == len(full)
    allowed = {"_id", "name", "mac", "model", "type", "ip", "state"}
    for record in compact:
        assert set(record) <= allowed
        assert record["mac"]
    assert any("version" in d for d in full), "default output must stay the full record"


async def test_list_devices_description_explains_compact(stub_server: FastMCP) -> None:
    """The prose above ``Args:`` is all FastMCP sends; the return shape of
    both modes has to survive there."""
    tools = {t.name: t for t in await stub_server.list_tools()}
    description = tools["list_devices"].description or ""
    assert "compact=True" in description
    assert "full controller record" in description


async def test_restart_device_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "restart_device", {"mac": "f4:e2:c6:00:00:01"})
    assert result["restarted"] is True


async def test_restart_device_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "restart_device", {"mac": "00:00:00:00:00:00"})
    assert "not found" in result["error"]


async def test_locate_device_on_then_off(stub_server: FastMCP) -> None:
    on = await _call(stub_server, "locate_device", {"mac": "f4:e2:c6:00:00:02", "on": True})
    assert on["locating"] is True
    off = await _call(stub_server, "locate_device", {"mac": "f4:e2:c6:00:00:02", "on": False})
    assert off["locating"] is False


async def test_locate_device_missing(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "locate_device", {"mac": "00:00:00:00:00:00"})
    assert "not found" in result["error"]


async def test_set_port_state_stub(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "set_port_state",
        {"device_mac": "f4:e2:c6:00:00:03", "port_idx": 5, "enable": False, "poe_mode": "off"},
    )
    assert result["enable"] is False
    assert result["poe_mode"] == "off"


async def test_set_port_state_no_args(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "set_port_state",
        {"device_mac": "f4:e2:c6:00:00:03", "port_idx": 5},
    )
    assert "at least one of" in result["error"]


async def test_set_port_state_unknown_device(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "set_port_state",
        {"device_mac": "00:00:00:00:00:00", "port_idx": 1, "enable": True},
    )
    assert "not found" in result["error"]


# ---------------------------------------------------------------------------
# Real mode
# ---------------------------------------------------------------------------

#: A real switch record lists its ports in ``port_table``; set_port_state
#: validates ``port_idx`` against it before writing.
SWITCH_PORT_TABLE = [{"port_idx": i} for i in range(1, 9)]

#: ``/stat/device`` answer for the restart/locate tests, which resolve the
#: MAC before sending the devmgr command.
GW_AP_STAT = {
    "data": [
        {"_id": "gw-1", "mac": "f4:e2:c6:00:00:01", "type": "ugw"},
        {"_id": "ap-1", "mac": "f4:e2:c6:00:00:02", "type": "uap"},
    ]
}


@respx.mock
async def test_real_list_devices(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/device").mock(
        return_value=httpx.Response(200, json={"data": [{"_id": "x", "model": "UCGFiber"}]})
    )
    devices = await _call(real_server, "list_devices")
    assert devices[0]["model"] == "UCGFiber"


@respx.mock
async def test_real_list_devices_error_returns_structured_error(
    real_server: FastMCP,
) -> None:
    respx.get(f"{BASE}/stat/device").mock(return_value=httpx.Response(401, text="Unauthorized"))
    result = await _call(real_server, "list_devices")
    assert "error" in result
    assert "401" in result["error"]
    assert result["stub_mode"] is False


@respx.mock
async def test_real_restart_device(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/device").mock(return_value=httpx.Response(200, json=GW_AP_STAT))
    respx.post(f"{BASE}/cmd/devmgr").mock(return_value=httpx.Response(200, json={"data": []}))
    result = await _call(real_server, "restart_device", {"mac": "f4:e2:c6:00:00:01"})
    assert result["restarted"] is True


@respx.mock
async def test_real_locate_device(real_server: FastMCP) -> None:
    captured: dict[str, Any] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"data": []})

    respx.get(f"{BASE}/stat/device").mock(return_value=httpx.Response(200, json=GW_AP_STAT))
    respx.post(f"{BASE}/cmd/devmgr").mock(side_effect=capture)
    result = await _call(real_server, "locate_device", {"mac": "f4:e2:c6:00:00:02", "on": True})
    assert result["locating"] is True
    assert captured["body"]["cmd"] == "set-locate"


@respx.mock
async def test_real_set_port_state(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/device").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "_id": "switch-1",
                        "mac": "f4:e2:c6:00:00:03",
                        "port_overrides": [{"port_idx": 1, "enable": True}],
                        "port_table": SWITCH_PORT_TABLE,
                    }
                ]
            },
        )
    )
    captured: dict[str, Any] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "_id": "switch-1",
                        "port_overrides": captured["body"]["port_overrides"],
                    }
                ]
            },
        )

    respx.put(f"{BASE}/rest/device/switch-1").mock(side_effect=capture)
    result = await _call(
        real_server,
        "set_port_state",
        {"device_mac": "f4:e2:c6:00:00:03", "port_idx": 5, "poe_mode": "off"},
    )
    assert result["_id"] == "switch-1"
    overrides = {o["port_idx"]: o for o in captured["body"]["port_overrides"]}
    assert overrides[5]["poe_mode"] == "off"
    assert 1 in overrides  # existing override preserved


@respx.mock
async def test_real_set_port_state_unknown_device(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/device").mock(return_value=httpx.Response(200, json={"data": []}))
    result = await _call(
        real_server,
        "set_port_state",
        {"device_mac": "ff:ff:ff:ff:ff:ff", "port_idx": 1, "enable": True},
    )
    assert "not found" in result["error"]


# ---------------------------------------------------------------------------
# Radio tools (v0.13.0): get_device_radios, set_radio_tx_power,
# set_radio_min_rssi, set_radio_channel, rename_device
# ---------------------------------------------------------------------------

AP_MAC = "f4:e2:c6:00:00:02"
GW_MAC = "f4:e2:c6:00:00:01"


async def test_get_device_radios_stub(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_device_radios", {"device_mac": AP_MAC})
    assert result["mac"] == AP_MAC
    radios = {r["radio"]: r for r in result["radios"]}
    assert set(radios) == {"ng", "na", "6e"}
    assert radios["ng"]["band"] == "2g"
    assert radios["na"]["band"] == "5g"
    assert radios["6e"]["band"] == "6g"
    assert radios["ng"]["channel"] == 6
    # Unset on the seed: surfaces as auto / defaults, not KeyError.
    assert radios["na"]["tx_power_mode"] == "auto"
    assert radios["na"]["min_rssi_enabled"] is False


async def test_get_device_radios_unknown_device(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_device_radios", {"device_mac": "00:00:00:00:00:00"})
    assert "not found" in result["error"]


async def test_get_device_radios_no_radios(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "get_device_radios", {"device_mac": GW_MAC})
    assert "no radios" in result["error"]


async def test_set_radio_tx_power_stub(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "set_radio_tx_power",
        {"device_mac": AP_MAC, "band": "5g", "mode": "medium"},
    )
    assert result["updated"] is True
    assert result["radio"] == "na"
    assert result["after"]["tx_power_mode"] == "medium"
    assert result["before"].get("tx_power_mode") is None
    # Other radios untouched.
    radios = await _call(stub_server, "get_device_radios", {"device_mac": AP_MAC})
    by_radio = {r["radio"]: r for r in radios["radios"]}
    assert by_radio["na"]["tx_power_mode"] == "medium"
    assert by_radio["ng"]["tx_power_mode"] == "auto"


async def test_set_radio_tx_power_custom(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "set_radio_tx_power",
        {"device_mac": AP_MAC, "band": "2g", "mode": "custom", "power_dbm": 8},
    )
    assert result["after"]["tx_power_mode"] == "custom"
    assert result["after"]["tx_power"] == 8


async def test_set_radio_tx_power_custom_requires_power(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "set_radio_tx_power",
        {"device_mac": AP_MAC, "band": "2g", "mode": "custom"},
    )
    assert "power_dbm" in result["error"]


async def test_set_radio_tx_power_invalid_mode(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "set_radio_tx_power",
        {"device_mac": AP_MAC, "band": "2g", "mode": "loud"},
    )
    assert "mode" in result["error"]


async def test_set_radio_tx_power_invalid_band(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "set_radio_tx_power",
        {"device_mac": AP_MAC, "band": "7g", "mode": "low"},
    )
    assert "band" in result["error"]


async def test_set_radio_tx_power_band_not_on_device(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "set_radio_tx_power",
        {"device_mac": GW_MAC, "band": "5g", "mode": "low"},
    )
    assert "error" in result


async def test_set_radio_tx_power_unknown_device(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "set_radio_tx_power",
        {"device_mac": "00:00:00:00:00:00", "band": "5g", "mode": "low"},
    )
    assert "not found" in result["error"]


async def test_set_radio_tx_power_dry_run(stub_server: FastMCP) -> None:
    preview = await _call(
        stub_server,
        "set_radio_tx_power",
        {"device_mac": AP_MAC, "band": "5g", "mode": "medium", "dry_run": True},
    )
    assert preview["dry_run"] is True
    assert preview["would_apply"]["after"]["tx_power_mode"] == "medium"
    # Nothing changed.
    radios = await _call(stub_server, "get_device_radios", {"device_mac": AP_MAC})
    by_radio = {r["radio"]: r for r in radios["radios"]}
    assert by_radio["na"]["tx_power_mode"] == "auto"


async def test_set_radio_min_rssi_enable(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "set_radio_min_rssi",
        {"device_mac": AP_MAC, "band": "5g", "enabled": True, "rssi_dbm": -75},
    )
    assert result["after"]["min_rssi_enabled"] is True
    assert result["after"]["min_rssi"] == -75


async def test_set_radio_min_rssi_disable(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "set_radio_min_rssi",
        {"device_mac": AP_MAC, "band": "5g", "enabled": False},
    )
    assert result["after"]["min_rssi_enabled"] is False


async def test_set_radio_min_rssi_requires_threshold(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "set_radio_min_rssi",
        {"device_mac": AP_MAC, "band": "5g", "enabled": True},
    )
    assert "rssi_dbm" in result["error"]


async def test_set_radio_min_rssi_invalid_threshold(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "set_radio_min_rssi",
        {"device_mac": AP_MAC, "band": "5g", "enabled": True, "rssi_dbm": 10},
    )
    assert "rssi_dbm" in result["error"]


async def test_set_radio_channel_stub(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "set_radio_channel",
        {"device_mac": AP_MAC, "band": "5g", "channel": "157", "width_mhz": 40},
    )
    assert result["after"]["channel"] == 157
    assert str(result["after"]["ht"]) == "40"


async def test_set_radio_channel_auto(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "set_radio_channel",
        {"device_mac": AP_MAC, "band": "5g", "channel": "auto"},
    )
    assert result["after"]["channel"] == "auto"
    # Width untouched.
    assert str(result["after"]["ht"]) == "80"


async def test_set_radio_channel_invalid_width(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "set_radio_channel",
        {"device_mac": AP_MAC, "band": "5g", "channel": "36", "width_mhz": 33},
    )
    assert "width_mhz" in result["error"]


async def test_set_radio_channel_requires_change(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "set_radio_channel",
        {"device_mac": AP_MAC, "band": "5g"},
    )
    assert "at least one" in result["error"]


async def test_set_radio_channel_invalid_channel(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "set_radio_channel",
        {"device_mac": AP_MAC, "band": "5g", "channel": "albatross"},
    )
    assert "channel" in result["error"]


async def test_rename_device_stub(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "rename_device",
        {"device_mac": AP_MAC, "name": "Bedroom AP"},
    )
    assert result["updated"] is True
    assert result["before"]["name"] == "U7 Pro - Living Room"
    assert result["after"]["name"] == "Bedroom AP"
    devices = await _call(stub_server, "list_devices")
    assert any(d.get("name") == "Bedroom AP" for d in devices)


async def test_rename_device_empty_name(stub_server: FastMCP) -> None:
    result = await _call(stub_server, "rename_device", {"device_mac": AP_MAC, "name": "  "})
    assert "name" in result["error"]


async def test_rename_device_unknown_device(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "rename_device",
        {"device_mac": "00:00:00:00:00:00", "name": "X"},
    )
    assert "not found" in result["error"]


async def test_rename_device_dry_run(stub_server: FastMCP) -> None:
    preview = await _call(
        stub_server,
        "rename_device",
        {"device_mac": AP_MAC, "name": "Bedroom AP", "dry_run": True},
    )
    assert preview["dry_run"] is True
    devices = await _call(stub_server, "list_devices")
    assert not any(d.get("name") == "Bedroom AP" for d in devices)


# ----- Radio tools, real mode ----------------------------------------------

AP_STAT = {
    "data": [
        {
            "_id": "ap-1",
            "mac": AP_MAC,
            "name": "U6 Lite",
            "model": "UAL6",
            "type": "uap",
            "state": 1,
            "radio_table": [
                {"radio": "ng", "channel": 1, "ht": "20", "max_txpower": 23, "min_txpower": 6},
                {"radio": "na", "channel": 157, "ht": "80", "max_txpower": 23, "min_txpower": 6},
            ],
        }
    ]
}


@respx.mock
async def test_real_get_device_radios(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/device").mock(return_value=httpx.Response(200, json=AP_STAT))
    result = await _call(real_server, "get_device_radios", {"device_mac": AP_MAC})
    radios = {r["radio"]: r for r in result["radios"]}
    assert radios["na"]["channel"] == 157
    assert radios["na"]["band"] == "5g"
    assert radios["na"]["max_txpower"] == 23


@respx.mock
async def test_real_set_radio_tx_power(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/device").mock(return_value=httpx.Response(200, json=AP_STAT))
    captured: dict[str, Any] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"data": [{"_id": "ap-1", **captured["body"]}]})

    respx.put(f"{BASE}/rest/device/ap-1").mock(side_effect=capture)
    result = await _call(
        real_server,
        "set_radio_tx_power",
        {"device_mac": AP_MAC, "band": "5g", "mode": "medium"},
    )
    assert result["updated"] is True
    # The PUT patches radio_table only — read-modify-write semantics.
    assert set(captured["body"]) == {"radio_table"}
    table = {r["radio"]: r for r in captured["body"]["radio_table"]}
    assert table["na"]["tx_power_mode"] == "medium"
    # Untargeted radio and existing fields preserved.
    assert "tx_power_mode" not in table["ng"]
    assert table["na"]["ht"] == "80"
    assert table["na"]["channel"] == 157


@respx.mock
async def test_real_set_radio_min_rssi(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/device").mock(return_value=httpx.Response(200, json=AP_STAT))
    captured: dict[str, Any] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"data": [{"_id": "ap-1", **captured["body"]}]})

    respx.put(f"{BASE}/rest/device/ap-1").mock(side_effect=capture)
    result = await _call(
        real_server,
        "set_radio_min_rssi",
        {"device_mac": AP_MAC, "band": "5g", "enabled": True, "rssi_dbm": -72},
    )
    assert result["updated"] is True
    table = {r["radio"]: r for r in captured["body"]["radio_table"]}
    assert table["na"]["min_rssi_enabled"] is True
    assert table["na"]["min_rssi"] == -72


@respx.mock
async def test_real_set_radio_channel(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/device").mock(return_value=httpx.Response(200, json=AP_STAT))
    captured: dict[str, Any] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"data": [{"_id": "ap-1", **captured["body"]}]})

    respx.put(f"{BASE}/rest/device/ap-1").mock(side_effect=capture)
    result = await _call(
        real_server,
        "set_radio_channel",
        {"device_mac": AP_MAC, "band": "5g", "channel": "36", "width_mhz": 40},
    )
    assert result["updated"] is True
    table = {r["radio"]: r for r in captured["body"]["radio_table"]}
    assert table["na"]["channel"] == 36
    assert table["na"]["ht"] == "40"


@respx.mock
async def test_real_rename_device(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/device").mock(return_value=httpx.Response(200, json=AP_STAT))
    captured: dict[str, Any] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"data": [{"_id": "ap-1", **captured["body"]}]})

    respx.put(f"{BASE}/rest/device/ap-1").mock(side_effect=capture)
    result = await _call(
        real_server,
        "rename_device",
        {"device_mac": AP_MAC, "name": "Bedroom AP"},
    )
    assert result["updated"] is True
    assert captured["body"] == {"name": "Bedroom AP"}


@respx.mock
async def test_real_set_radio_unknown_device(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/device").mock(return_value=httpx.Response(200, json={"data": []}))
    result = await _call(
        real_server,
        "set_radio_tx_power",
        {"device_mac": "ff:ff:ff:ff:ff:ff", "band": "5g", "mode": "low"},
    )
    assert "not found" in result["error"]


@respx.mock
async def test_real_set_radio_put_error_is_structured(real_server: FastMCP) -> None:
    """A 404 on the device PUT (route absent / wrong id) fails safe.

    No partial mutation is possible — the controller rejected the whole
    write — and the caller gets the standard error envelope.
    """
    respx.get(f"{BASE}/stat/device").mock(return_value=httpx.Response(200, json=AP_STAT))
    respx.put(f"{BASE}/rest/device/ap-1").mock(
        return_value=httpx.Response(404, text='{"meta":{"rc":"error","msg":"api.err.NotFound"}}')
    )
    result = await _call(
        real_server,
        "set_radio_tx_power",
        {"device_mac": AP_MAC, "band": "5g", "mode": "medium"},
    )
    assert "404" in result["error"]
    assert result["stub_mode"] is False


# ---------------------------------------------------------------------------
# Read-path redaction
#
# The interesting part of this section is why the module was cleared in the
# 0.19.2 sweep and should not have been. Device records carry ``x_authkey``
# (management/inform key) and ``x_vwirekey`` (mesh uplink key). Neither
# matched any entry in SENSITIVE_KEY_PATTERNS, so a reviewer checking
# "does any field here match a pattern?" got "no" and moved on — and wrapping
# these tools in ``redact`` alone would have been a no-op that read as a fix.
# The patterns and the wiring only mean anything together.
# ---------------------------------------------------------------------------

DEVICE_SECRETS = {
    "x_authkey": "device-authkey-do-not-leak",
    "x_vwirekey": "device-vwirekey-do-not-leak",
}


async def test_list_devices_redacts_device_credentials(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    stub_state.devices[0].update(DEVICE_SECRETS)

    devices = await _call(stub_server, "list_devices")
    gateway = next(d for d in devices if d["mac"] == "f4:e2:c6:00:00:01")

    for key in DEVICE_SECRETS:
        assert gateway[key] == "[REDACTED]", f"{key} leaked from list_devices"
    assert "do-not-leak" not in json.dumps(devices)

    # Inventory fields survive, so this is redaction and not a drop.
    assert gateway["model"] == "UCGFiber"
    assert gateway["ip"] == "192.168.1.1"
    assert gateway["adopted"] is True


async def test_get_device_radios_redacts_when_the_projection_widens(
    stub_server: FastMCP, stub_state: StubState, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``_project_radio_view`` is an allowlist; the redaction must not depend on it.

    Monkeypatching the projection to a passthrough is exactly what an innocent
    "surface one more device field" edit amounts to. The response has to come
    back redacted anyway, which it only does because the tool calls ``redact``
    rather than trusting the allowlist.
    """
    ap = next(d for d in stub_state.devices if d["mac"] == AP_MAC)
    ap.update(DEVICE_SECRETS)

    monkeypatch.setattr(
        devices,
        "_project_radio_view",
        lambda device_mac, device, radio_table: {"mac": device_mac, **device},
    )

    result = await _call(stub_server, "get_device_radios", {"device_mac": AP_MAC})

    for key in DEVICE_SECRETS:
        assert result[key] == "[REDACTED]", f"{key} leaked from get_device_radios"
    assert "do-not-leak" not in json.dumps(result)
    assert result["model"] == "U7Pro"


@respx.mock
async def test_real_set_port_state_redacts_device_credentials(real_server: FastMCP) -> None:
    """The real backend returns the device record the PUT echoed back.

    The stub returns just the port entry, so only real mode exercises this.
    """
    respx.get(f"{BASE}/stat/device").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "_id": "switch-1",
                        "mac": "f4:e2:c6:00:00:03",
                        "port_overrides": [{"port_idx": 1, "enable": True}],
                        "port_table": SWITCH_PORT_TABLE,
                        **DEVICE_SECRETS,
                    }
                ]
            },
        )
    )

    def capture(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "data": [
                    {
                        "_id": "switch-1",
                        "mac": "f4:e2:c6:00:00:03",
                        "port_overrides": body["port_overrides"],
                        **DEVICE_SECRETS,
                    }
                ]
            },
        )

    respx.put(f"{BASE}/rest/device/switch-1").mock(side_effect=capture)

    result = await _call(
        real_server,
        "set_port_state",
        {"device_mac": "f4:e2:c6:00:00:03", "port_idx": 5, "poe_mode": "off"},
    )

    for key in DEVICE_SECRETS:
        assert result[key] == "[REDACTED]", f"{key} leaked from set_port_state"
    assert "do-not-leak" not in json.dumps(result)
    # The write result is still legible.
    assert result["_id"] == "switch-1"
    overrides = {o["port_idx"]: o for o in result["port_overrides"]}
    assert overrides[5]["poe_mode"] == "off"


async def test_set_radio_tx_power_redacts_radio_table_secrets(
    stub_server: FastMCP, stub_state: StubState
) -> None:
    """``before``/``after`` are ``radio_table`` entries, emitted verbatim.

    They are device-record subtrees, so they get the same treatment as the
    record itself rather than a case-by-case judgement about which firmware
    puts what in the table.
    """
    ap = next(d for d in stub_state.devices if d["mac"] == AP_MAC)
    ap["radio_table"][1]["x_vwirekey"] = "radio-vwirekey-do-not-leak"

    preview = await _call(
        stub_server,
        "set_radio_tx_power",
        {"device_mac": AP_MAC, "band": "5g", "mode": "low", "dry_run": True},
    )
    assert preview["would_apply"]["before"]["x_vwirekey"] == "[REDACTED]"
    assert preview["would_apply"]["after"]["x_vwirekey"] == "[REDACTED]"
    assert "do-not-leak" not in json.dumps(preview)
    # The RF diff the preview exists to show is untouched.
    assert preview["would_apply"]["before"]["channel"] == 36
    assert preview["would_apply"]["after"]["tx_power_mode"] == "low"

    applied = await _call(
        stub_server,
        "set_radio_tx_power",
        {"device_mac": AP_MAC, "band": "5g", "mode": "low"},
    )
    assert applied["before"]["x_vwirekey"] == "[REDACTED]"
    assert applied["after"]["x_vwirekey"] == "[REDACTED]"
    assert "do-not-leak" not in json.dumps(applied)
    assert applied["after"]["tx_power_mode"] == "low"


@respx.mock
async def test_real_set_port_state_keeps_other_fields_on_same_port(real_server: FastMCP) -> None:
    """The controller replaces port_overrides wholesale. Changing one field on
    port 5 must send port 5's existing profile, PoE mode and name back with it,
    or they revert to defaults (a camera port could jump VLANs on a disable)."""
    respx.get(f"{BASE}/stat/device").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": [
                    {
                        "_id": "switch-1",
                        "mac": "f4:e2:c6:00:00:03",
                        "port_overrides": [
                            {"port_idx": 6, "portconf_id": "prof-ap"},
                            {
                                "port_idx": 5,
                                "portconf_id": "prof-cam",
                                "poe_mode": "auto",
                                "name": "cam-front",
                            },
                        ],
                        "port_table": SWITCH_PORT_TABLE,
                    }
                ]
            },
        )
    )
    captured: dict[str, Any] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "data": [{"_id": "switch-1", "port_overrides": captured["body"]["port_overrides"]}]
            },
        )

    respx.put(f"{BASE}/rest/device/switch-1").mock(side_effect=capture)
    await _call(
        real_server,
        "set_port_state",
        {"device_mac": "f4:e2:c6:00:00:03", "port_idx": 5, "enable": False},
    )
    overrides = {o["port_idx"]: o for o in captured["body"]["port_overrides"]}
    assert overrides[5] == {
        "port_idx": 5,
        "portconf_id": "prof-cam",
        "poe_mode": "auto",
        "name": "cam-front",
        "enable": False,
    }
    assert overrides[6] == {"port_idx": 6, "portconf_id": "prof-ap"}
    assert len(captured["body"]["port_overrides"]) == 2


# ---------------------------------------------------------------------------
# MAC lookups accept any case and separator (review finding D2)
# ---------------------------------------------------------------------------

SWITCH_MAC = "f4:e2:c6:00:00:03"


@pytest.mark.parametrize(
    "typed",
    ["F4:E2:C6:00:00:02", "f4-e2-c6-00-00-02", "F4E2.C600.0002", "f4e2c6000002"],
)
async def test_device_tools_find_the_device_whatever_the_mac_form(
    stub_server: FastMCP, typed: str
) -> None:
    """Only the stats tools lower-cased the MAC; every other device tool
    compared it verbatim and answered "not found" for an upper-case or
    dash-separated MAC copied off a label."""
    cases: list[tuple[str, dict[str, Any]]] = [
        ("get_device_radios", {"device_mac": typed}),
        ("rename_device", {"device_mac": typed, "name": "x", "dry_run": True}),
        ("set_radio_channel", {"device_mac": typed, "band": "5g", "channel": "40"}),
        ("restart_device", {"mac": typed, "dry_run": True}),
        ("locate_device", {"mac": typed}),
        ("get_device_stats", {"mac": typed}),
    ]
    for tool, args in cases:
        result = await _call(stub_server, tool, args)
        assert "error" not in result, (tool, result)


async def test_set_port_state_finds_the_switch_by_upper_case_mac(stub_server: FastMCP) -> None:
    result = await _call(
        stub_server,
        "set_port_state",
        {"device_mac": SWITCH_MAC.upper(), "port_idx": 2, "enable": False},
    )
    assert result["enable"] is False


@respx.mock
async def test_real_device_lookup_accepts_upper_case_mac(real_server: FastMCP) -> None:
    respx.get(f"{BASE}/stat/device").mock(return_value=httpx.Response(200, json=AP_STAT))
    result = await _call(real_server, "get_device_radios", {"device_mac": AP_MAC.upper()})
    assert result["name"] == "U6 Lite"


@respx.mock
async def test_real_restart_sends_the_controllers_own_mac(real_server: FastMCP) -> None:
    """The devmgr command carries the MAC as the controller stores it, not
    the upper-case form the caller typed."""
    respx.get(f"{BASE}/stat/device").mock(return_value=httpx.Response(200, json=GW_AP_STAT))
    captured: dict[str, Any] = {}

    def capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"data": []})

    respx.post(f"{BASE}/cmd/devmgr").mock(side_effect=capture)
    result = await _call(real_server, "restart_device", {"mac": "F4-E2-C6-00-00-01"})
    assert result == {"restarted": True, "mac": "f4:e2:c6:00:00:01"}
    assert captured["body"] == {"cmd": "restart", "mac": "f4:e2:c6:00:00:01"}


# ---------------------------------------------------------------------------
# Unknown targets: dry runs and real calls agree (D6, D7, D11)
# ---------------------------------------------------------------------------

GHOST_MAC = "de:ad:be:ef:00:00"


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("restart_device", {"mac": GHOST_MAC}),
        ("locate_device", {"mac": GHOST_MAC}),
        ("set_port_state", {"device_mac": GHOST_MAC, "port_idx": 1, "enable": False}),
        ("set_port_state", {"device_mac": SWITCH_MAC, "port_idx": 999, "enable": False}),
        ("set_port_state", {"device_mac": AP_MAC, "port_idx": 1, "enable": False}),
    ],
)
async def test_dry_run_reports_the_not_found_the_real_call_reports(
    stub_server: FastMCP, stub_state: StubState, tool: str, args: dict[str, Any]
) -> None:
    """A dry run used to preview success for a device or port that does not
    exist, while the real call said "not found"."""
    dry = await _call(stub_server, tool, {**args, "dry_run": True})
    real = await _call(stub_server, tool, args)
    assert "not found" in dry.get("error", ""), dry
    assert "not found" in real.get("error", ""), real
    assert dry["error"] == real["error"]
    assert stub_state.audit_log == []


@respx.mock
@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("restart_device", {"mac": GHOST_MAC}),
        ("locate_device", {"mac": GHOST_MAC, "on": True}),
    ],
)
async def test_real_restart_and_locate_report_unknown_device(
    real_server: FastMCP, tool: str, args: dict[str, Any]
) -> None:
    """The real path treated any devmgr answer as success, so it always said
    it had restarted or located a device that does not exist."""
    respx.get(f"{BASE}/stat/device").mock(return_value=httpx.Response(200, json=GW_AP_STAT))
    devmgr = respx.post(f"{BASE}/cmd/devmgr").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    result = await _call(real_server, tool, args)
    assert result["error"] == f"device {GHOST_MAC} not found"
    assert not devmgr.called


def _switch_stat(**extra: Any) -> dict[str, Any]:
    return {
        "data": [
            {
                "_id": "switch-1",
                "mac": SWITCH_MAC,
                "type": "usw",
                "port_overrides": [{"port_idx": 2, "portconf_id": "P", "name": "cam"}],
                **extra,
            }
        ]
    }


@respx.mock
@pytest.mark.parametrize(
    "stat",
    [
        _switch_stat(port_table=SWITCH_PORT_TABLE),  # port 999 is not in the table
        _switch_stat(),  # no port table at all
    ],
)
async def test_real_set_port_state_refuses_a_port_the_device_does_not_have(
    real_server: FastMCP, stat: dict[str, Any]
) -> None:
    """The real path appended an override for any port number to any device
    and PUT it. The device's own port table is now the authority."""
    respx.get(f"{BASE}/stat/device").mock(return_value=httpx.Response(200, json=stat))
    put = respx.put(f"{BASE}/rest/device/switch-1").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    result = await _call(
        real_server,
        "set_port_state",
        {"device_mac": SWITCH_MAC, "port_idx": 999, "enable": False},
    )
    assert "not found" in result["error"]
    assert not put.called


# ---------------------------------------------------------------------------
# Radio input validation (D9)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("band", "channel", "width"),
    [
        ("2g", "36", 0),
        ("2g", "0", 0),
        ("2g", "15", 0),
        ("5g", "6", 0),
        ("5g", "38", 0),
        ("5g", "169", 0),
        ("6g", "9999", 0),
        ("6g", "3", 0),
        ("2g", "", 80),
        ("2g", "", 320),
        ("5g", "", 320),
    ],
)
async def test_set_radio_channel_rejects_numbers_not_on_the_band(
    stub_server: FastMCP, stub_state: StubState, band: str, channel: str, width: int
) -> None:
    before = copy.deepcopy(stub_state.devices)
    args: dict[str, Any] = {"device_mac": AP_MAC, "band": band}
    if channel:
        args["channel"] = channel
    if width:
        args["width_mhz"] = width
    for dry_run in (True, False):
        result = await _call(stub_server, "set_radio_channel", {**args, "dry_run": dry_run})
        assert "error" in result, (args, result)
    assert stub_state.devices == before


@pytest.mark.parametrize(
    ("band", "channel", "width"),
    [
        ("2g", "1", 20),
        ("2g", "14", 40),
        ("5g", "36", 80),
        ("5g", "100", 160),
        ("5g", "165", 20),
        ("5g", "auto", 240),
        ("6g", "1", 320),
        ("6g", "233", 20),
    ],
)
async def test_set_radio_channel_accepts_standard_channels(
    stub_server: FastMCP, band: str, channel: str, width: int
) -> None:
    result = await _call(
        stub_server,
        "set_radio_channel",
        {"device_mac": AP_MAC, "band": band, "channel": channel, "width_mhz": width},
    )
    assert result.get("updated") is True, result


@respx.mock
@pytest.mark.parametrize("power", [5, 24, 200])
async def test_real_set_radio_tx_power_refuses_power_outside_radio_range(
    real_server: FastMCP, power: int
) -> None:
    """``AP_STAT``'s 5 GHz radio reports ``min_txpower`` 6 and ``max_txpower``
    23. The guard existed but nothing tested it."""
    respx.get(f"{BASE}/stat/device").mock(return_value=httpx.Response(200, json=AP_STAT))
    put = respx.put(f"{BASE}/rest/device/ap-1").mock(
        return_value=httpx.Response(200, json={"data": []})
    )
    result = await _call(
        real_server,
        "set_radio_tx_power",
        {"device_mac": AP_MAC, "band": "5g", "mode": "custom", "power_dbm": power},
    )
    assert result["error"] == f"power_dbm {power} outside the radio's supported range 6-23 dBm"
    assert not put.called


@respx.mock
@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("rename_device", {"device_mac": AP_MAC, "name": "Bedroom AP"}),
        ("set_radio_tx_power", {"device_mac": AP_MAC, "band": "5g", "mode": "low"}),
    ],
)
async def test_real_device_write_with_empty_data_is_success(
    real_server: FastMCP, tool: str, args: dict[str, Any]
) -> None:
    """A 2xx PUT whose ``data`` list is empty applied the write, but the
    backend returned None and the tool said "device not found" (B7)."""
    respx.get(f"{BASE}/stat/device").mock(return_value=httpx.Response(200, json=AP_STAT))
    put = respx.put(f"{BASE}/rest/device/ap-1").mock(
        return_value=httpx.Response(200, json={"meta": {"rc": "ok"}, "data": []})
    )
    result = await _call(real_server, tool, args)
    assert put.called
    assert result.get("updated") is True, result


@respx.mock
async def test_real_device_write_with_empty_data_and_no_reread(real_server: FastMCP) -> None:
    """If the re-read after an empty-``data`` PUT does not list the device
    either, the write still counts as applied."""
    respx.get(f"{BASE}/stat/device").mock(
        side_effect=[
            httpx.Response(200, json=AP_STAT),
            httpx.Response(200, json={"data": []}),
        ]
    )
    respx.put(f"{BASE}/rest/device/ap-1").mock(return_value=httpx.Response(200, json={"data": []}))
    result = await _call(real_server, "rename_device", {"device_mac": AP_MAC, "name": "Den AP"})
    assert result["updated"] is True
    assert result["after"] == {"name": "Den AP"}
