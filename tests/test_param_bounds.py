"""Free-text / secret tool parameters must publish a ``maxLength`` bound.

FastMCP derives each tool's JSON input schema from its signature, so annotating
a parameter as ``Annotated[str, Field(max_length=N)]`` (see
``mcp_unifi.modules._params``) emits ``maxLength`` in the schema. This guards
the UniFi controller from an unbounded free-text value (e.g. a 10 KB ``name``).

These tests pin the contract so a future signature edit that drops the bound is
caught in CI.
"""

from __future__ import annotations

import pytest

from mcp_unifi.config import Settings
from mcp_unifi.server import build_server

# (tool_name, param_name) -> expected maxLength
EXPECTED_BOUNDS: dict[tuple[str, str], int] = {
    ("create_vlan", "name"): 128,
    ("create_vlan", "purpose"): 128,
    ("create_wlan", "name"): 128,
    ("create_wlan", "passphrase"): 128,
    ("create_guest_network", "ssid"): 32,
    ("rename_device", "name"): 128,
    ("create_dynamic_dns", "password"): 128,
    ("create_dynamic_dns", "host_name"): 253,
    ("restore_config", "backup_json"): 5_000_000,
    ("audit_network_drift", "spec_yaml"): 200_000,
}


async def _tool_schemas() -> dict[str, dict]:
    settings = Settings(
        stub_mode=True, log_format="text", mcp_transport="stdio", auth_required=False
    )
    server = build_server(settings)
    tools = await server.list_tools()
    items = tools.values() if isinstance(tools, dict) else tools
    return {t.name: t.parameters for t in items}


@pytest.mark.asyncio
async def test_free_text_params_have_maxlength() -> None:
    schemas = await _tool_schemas()
    for (tool_name, param), expected in EXPECTED_BOUNDS.items():
        assert tool_name in schemas, f"tool {tool_name} not registered"
        props = schemas[tool_name].get("properties", {})
        assert param in props, f"{tool_name} has no param {param}"
        actual = props[param].get("maxLength")
        assert actual == expected, (
            f"{tool_name}.{param} maxLength = {actual!r}, expected {expected}"
        )


@pytest.mark.asyncio
async def test_bounded_string_params_are_strings() -> None:
    """A bounded param must still be a plain string in the schema (no type drift)."""
    schemas = await _tool_schemas()
    for (tool_name, param), _ in EXPECTED_BOUNDS.items():
        prop = schemas[tool_name]["properties"][param]
        assert prop.get("type") == "string", f"{tool_name}.{param} is not a string"
