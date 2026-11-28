"""One error contract for every tool, every refusal, and every client era.

The guarantee, stated in ``mcp_unifi.responses`` ("The error contract") and in
the docs site's tool-contract page:

1. A tool failure, a read-only refusal, and a scope denial all return the same
   JSON envelope, ``{"error": "<message>", "stub_mode": <bool>, ...}``, as the
   text block.
2. The MCP result for every one of them has ``isError: true``.
3. A refusal is indistinguishable from any other error to the caller; only the
   audit record's ``denied_by`` says which control refused it.

Before this file, a stub-mode sweep of 141 tools found 137 of them returning
the envelope with ``isError: false`` (a client keying on ``isError`` read a
failed write as a success), and a scope denial came back as a bare raised
``ToolError`` in plain text.

The sweep below drives every registered tool into a domain error and asserts
its own coverage, so a new tool that bypasses the contract fails here the day
it is added.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import respx
from fastmcp import Client, FastMCP

from mcp_unifi.audit import AuditLog, FileSink, set_audit_log
from mcp_unifi.backends import StubBackend
from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.config import Settings
from mcp_unifi.responses import (
    AdaptiveResponseMiddleware,
    is_error_envelope,
    supports_structured_content,
)
from mcp_unifi.scoping import DENIED_BY_READONLY, DENIED_BY_SCOPE
from mcp_unifi.server import build_server

ALL_MODULES = "network,protect,access"

#: The unknown controller every tool is pointed at. Each tool resolves the
#: controller before it does anything else, so this is the one domain error a
#: sweep can reach generically.
NOPE = "nope"

#: Tools whose generated arguments would fail FastMCP's own schema validation
#: before the tool body runs. The values are valid, so the call reaches the
#: tool and fails on the controller name instead.
ARG_OVERRIDES: dict[str, dict[str, Any]] = {
    "update_clients": {"updates": [{"mac": "aa:bb:cc:dd:ee:ff", "name": "x"}]},
}

#: Tools that answer canned data in stub mode without reading ``controller``.
#: They are driven against a real-mode server instead, where an unknown
#: controller is refused before any HTTP request (respx refuses all traffic).
REAL_MODE_TOOLS = frozenset({"get_console_health", "get_console_info", "get_console_firmware"})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dummy(schema: dict[str, Any], defs: dict[str, Any]) -> Any:
    """A minimal value that satisfies ``schema``, for required arguments."""
    if "$ref" in schema:
        return _dummy(defs[schema["$ref"].rsplit("/", 1)[-1]], defs)
    if "enum" in schema:
        return schema["enum"][0]
    if "const" in schema:
        return schema["const"]
    for key in ("anyOf", "oneOf"):
        if key in schema:
            options = [o for o in schema[key] if o.get("type") != "null"]
            return _dummy(options[0], defs)
    kind = schema.get("type")
    if kind == "string":
        return "x" * max(1, int(schema.get("minLength", 1)))
    if kind == "integer":
        return int(schema.get("minimum", 1))
    if kind == "number":
        return float(schema.get("minimum", 1))
    if kind == "boolean":
        return False
    if kind == "array":
        item = schema.get("items", {"type": "string"})
        return [_dummy(item, defs) for _ in range(int(schema.get("minItems", 0)))]
    if kind == "object":
        props = schema.get("properties", {})
        return {name: _dummy(props[name], defs) for name in schema.get("required", [])}
    return "x"


def _error_args(tool: Any) -> dict[str, Any]:
    """Arguments that reach ``tool``'s body and make it fail."""
    params = tool.parameters
    props = params.get("properties", {})
    defs = params.get("$defs", {})
    args = {name: _dummy(props[name], defs) for name in params.get("required", [])}
    args.update(ARG_OVERRIDES.get(tool.name, {}))
    if "controller" in props:
        args["controller"] = NOPE
    return args


def _assert_envelope(result: Any, *, where: str) -> dict[str, Any]:
    """Assert the contract on one MCP result; return the parsed envelope."""
    assert result.is_error is True, f"{where}: isError is not true"
    text = result.content[0].text
    payload = json.loads(text)
    assert is_error_envelope(payload), f"{where}: text is not the error envelope: {text[:200]}"
    assert isinstance(payload["error"], str) and payload["error"]
    assert isinstance(payload["stub_mode"], bool)
    return dict(payload)


MANIFEST_PATH = Path(__file__).resolve().parent.parent / "docs/site/src/data/tool-manifest.json"


def _manifest_tool_names() -> set[str]:
    """Tool names from the committed manifest (every module, generated from the server)."""
    data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    names = {str(tool["name"]) for tool in data["tools"]}
    assert len(names) == data["tool_count"]
    return names


@pytest.fixture
def all_modules(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MCP_UNIFI_MODULES_ENABLED", ALL_MODULES)


@pytest.fixture
def audit_path(tmp_path: Path) -> Iterator[Path]:
    path = tmp_path / "audit.jsonl"
    set_audit_log(AuditLog(sink=FileSink(path)))
    yield path
    set_audit_log(None)


def _records(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# ---------------------------------------------------------------------------
# The sweep: every registered tool, both client eras
# ---------------------------------------------------------------------------


async def test_every_tool_reports_a_domain_error_with_the_envelope_and_is_error(
    all_modules: None, stub_settings: Settings, real_settings: Settings
) -> None:
    """Every registered tool, driven into a domain error, honours the contract.

    Two eras per tool: ``server.call_tool`` has no negotiated session, which
    the response middleware treats as an old, text-only client; the in-memory
    ``Client`` negotiates a revision that carries ``structuredContent``.
    """
    stub_server = build_server(stub_settings.model_copy(update={"mcp_transport": "stdio"}))
    real_server = build_server(real_settings.model_copy(update={"mcp_transport": "stdio"}))
    registered = {t.name: t for t in await stub_server.list_tools()}
    assert len(registered) > 100, "the sweep did not see the full tool surface"
    assert set(registered) >= REAL_MODE_TOOLS
    assert set(ARG_OVERRIDES) <= set(registered)

    exercised: set[str] = set()
    failures: list[str] = []

    # respx with no routes: any HTTP request from the real-mode server raises,
    # so the real-mode leg can never reach a network, real or fake.
    with respx.mock(assert_all_called=False, assert_all_mocked=True):
        for server, names in (
            (stub_server, sorted(set(registered) - REAL_MODE_TOOLS)),
            (real_server, sorted(REAL_MODE_TOOLS)),
        ):
            async with Client(server) as client:
                assert supports_structured_content(client.protocol_version)
                for name in names:
                    args = _error_args(registered[name])
                    try:
                        old = await server.call_tool(name, args)
                        old_env = _assert_envelope(old, where=f"{name} (text-only era)")
                        # Proves this leg took the old-client path: no parsed
                        # structuredContent was substituted.
                        assert old.structured_content != old_env
                        new = await client.call_tool(name, args, raise_on_error=False)
                        new_env = _assert_envelope(new, where=f"{name} (structured era)")
                        assert new.structured_content == new_env
                        assert new_env["error"] == old_env["error"]
                    except AssertionError as exc:
                        failures.append(str(exc).splitlines()[0])
                    exercised.add(name)

    assert failures == [], f"{len(failures)} tool(s) broke the error contract: {failures}"
    # Coverage asserts itself: nothing registered was skipped.
    # Coverage is checked against a list the sweep did not produce: the
    # committed tool manifest, which tests/test_tool_manifest.py keeps in step
    # with the server. A tool that registered without reaching list_tools, or
    # a sweep that silently dropped one, fails here.
    manifest = _manifest_tool_names()
    assert len(manifest) > 100
    assert exercised == manifest, (
        f"not exercised: {sorted(manifest - exercised)}; "
        f"not in the manifest: {sorted(exercised - manifest)}"
    )


# ---------------------------------------------------------------------------
# Refusals: the write gate and the scope gate, through the whole stack
# ---------------------------------------------------------------------------


@pytest.fixture
def readonly_server(stub_settings: Settings) -> FastMCP:
    return build_server(
        stub_settings.model_copy(update={"mcp_transport": "stdio", "readonly": True})
    )


async def test_read_only_refusal_is_an_error_envelope_in_both_eras(
    readonly_server: FastMCP, audit_path: Path
) -> None:
    args = {"network_id": "5f54c89b4b794a09a3509a33"}
    old = await readonly_server.call_tool("delete_vlan", args)
    old_env = _assert_envelope(old, where="read-only refusal (text-only era)")
    assert set(old_env) == {"error", "stub_mode"}
    assert "read-only mode" in old_env["error"]

    async with Client(readonly_server) as client:
        new = await client.call_tool("delete_vlan", args, raise_on_error=False)
    assert _assert_envelope(new, where="read-only refusal (structured era)") == old_env
    assert new.structured_content == old_env

    denials = [r for r in _records(audit_path) if r.get("tool") == "delete_vlan"]
    assert [r["denied_by"] for r in denials] == [DENIED_BY_READONLY, DENIED_BY_READONLY]
    assert all(r["success"] is False for r in denials)


@pytest.fixture
def scoped_server(stub_settings: Settings) -> FastMCP:
    """HTTP settings with one client scoped to Protect, so ScopeMiddleware is on."""
    return build_server(
        stub_settings.model_copy(
            update={
                "mcp_transport": "streamable-http",
                "auth_required": True,
                "auth_tokens": "admin:tok-a,ro:tok-r:protect",
            }
        )
    )


async def test_scope_denial_is_the_same_envelope_with_a_vague_message(
    scoped_server: FastMCP, audit_path: Path
) -> None:
    """Shape of any error, message that names nothing, detail only in the audit log."""
    with patch("mcp_unifi.scoping._current_client_id", return_value="ro"):
        denied = await scoped_server.call_tool("list_networks", {})
        # A name that does not exist must be indistinguishable from one that
        # exists outside the caller's scope, or names could be enumerated.
        unknown = await scoped_server.call_tool("no_such_tool", {})
        async with Client(scoped_server) as client:
            modern = await client.call_tool("list_networks", {}, raise_on_error=False)

    env = _assert_envelope(denied, where="scope denial (text-only era)")
    assert env == {
        "error": "Tool 'list_networks' is not available to this client.",
        "stub_mode": True,
    }
    unknown_env = _assert_envelope(unknown, where="scope denial of an unknown name")
    assert unknown_env == {
        "error": "Tool 'no_such_tool' is not available to this client.",
        "stub_mode": True,
    }
    for text in (denied.content[0].text, unknown.content[0].text):
        assert "network" not in text.replace("list_networks", "")
        assert "protect" not in text and "scope" not in text.lower()
    assert _assert_envelope(modern, where="scope denial (structured era)") == env
    assert modern.structured_content == env

    records = _records(audit_path)
    assert {r["tool"] for r in records} == {"list_networks", "no_such_tool"}
    assert all(r["denied_by"] == DENIED_BY_SCOPE for r in records)
    assert all(r["success"] is False for r in records)
    # The operator's record keeps the detail the caller does not get.
    assert all("MCP_UNIFI_AUTH_TOKENS" in r["error"] for r in records)


async def test_scope_denial_reports_real_mode_honestly(
    real_settings: Settings, audit_path: Path
) -> None:
    """A real-mode server's denial says stub_mode false, and nothing is sent."""
    server = build_server(
        real_settings.model_copy(
            update={
                "mcp_transport": "streamable-http",
                "auth_required": True,
                "auth_tokens": "admin:tok-a,ro:tok-r:protect",
            }
        )
    )
    with (
        respx.mock(assert_all_called=False, assert_all_mocked=True) as router,
        patch("mcp_unifi.scoping._current_client_id", return_value="ro"),
    ):
        result = await server.call_tool("list_networks", {})
    env = _assert_envelope(result, where="scope denial (real mode)")
    assert env == {
        "error": "Tool 'list_networks' is not available to this client.",
        "stub_mode": False,
    }
    assert router.calls.call_count == 0
    assert [r["denied_by"] for r in _records(audit_path)] == [DENIED_BY_SCOPE]


async def test_scope_permitted_call_is_untouched(scoped_server: FastMCP) -> None:
    with patch("mcp_unifi.scoping._current_client_id", return_value="admin"):
        result = await scoped_server.call_tool("list_networks", {})
    assert result.is_error is False
    assert isinstance(json.loads(result.content[0].text), list)


# ---------------------------------------------------------------------------
# Success payloads that carry an ``error`` key of their own are not failures
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        # update_clients partial failure: per-item error inside results.
        {"updated": 1, "failed": 1, "results": [{"mac": "aa", "status": "failed", "error": "x"}]},
        # audit_open_ports when the zone-based firewall read failed.
        {"port_forwards": [], "firewall_policies_error": "HTTP 500", "summary": "s"},
        # get_console_health probe records and observability source lists.
        {"checks": [{"path": "/api/system", "status": None, "error": "timeout"}]},
        {"sources": [{"endpoint": "flows", "ok": False, "error": "404"}]},
        # restore_config per-action rollback entries.
        {"rolled_back": [{"type": "networks", "id": "n1", "error": "boom"}]},
        # A raw controller record with its own top-level error field: no
        # controller record carries stub_mode.
        {"_id": "abc", "error": "link down"},
        {"rc": "error", "msg": "api.err.Invalid"},
        # Not an envelope: an empty message, a non-string error, a non-bool flag.
        {"error": "", "stub_mode": True},
        {"error": "   ", "stub_mode": False},
        {"error": {"code": 1}, "stub_mode": True},
        {"error": "x", "stub_mode": "true"},
        [{"error": "x", "stub_mode": True}],
        "error",
        None,
    ],
)
def test_non_envelopes_are_not_errors(payload: Any) -> None:
    assert is_error_envelope(payload) is False


@pytest.mark.parametrize(
    "payload",
    [
        {"error": "Unknown controller 'nope'. Available: default.", "stub_mode": True},
        {"error": "x", "stub_mode": False},
        # Composite failure envelopes carry extra keys and are still errors.
        {"error": "create_iot_network failed at wlan: x", "stub_mode": True, "partial": {}},
        {"error": "update_clients changed nothing", "stub_mode": False, "results": []},
    ],
)
def test_envelopes_are_errors(payload: Any) -> None:
    assert is_error_envelope(payload) is True


async def test_partial_success_payloads_with_nested_errors_stay_successes(
    stub_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two real tools whose success output carries an error field, end to end."""
    server = build_server(stub_settings.model_copy(update={"mcp_transport": "stdio"}))

    async def policies_fail(_self: Any) -> list[Any]:
        raise UniFiError("HTTP 500 from the zone-based firewall")

    monkeypatch.setattr(StubBackend, "list_firewall_policies", policies_fail)

    clients = json.loads((await server.call_tool("list_clients", {})).content[0].text)
    macs = [c["mac"] for c in clients if c.get("mac")][:2]
    assert len(macs) == 2
    original_update_user = StubBackend.update_user
    refused: set[str] = set()

    async def update_user_refuses_one(self: Any, user_id: str, patch_: dict[str, Any]) -> Any:
        # The first user written is refused on every call; the other lands.
        if not refused:
            refused.add(user_id)
        if user_id in refused:
            raise UniFiError("controller refused the write")
        return await original_update_user(self, user_id, patch_)

    monkeypatch.setattr(StubBackend, "update_user", update_user_refuses_one)

    async with Client(server) as client:
        for name, args, nested in (
            ("audit_open_ports", {}, "firewall_policies_error"),
            (
                "update_clients",
                {"updates": [{"mac": m, "note": "contract"} for m in macs]},
                "results",
            ),
        ):
            old = await server.call_tool(name, args)
            new = await client.call_tool(name, args, raise_on_error=False)
            for result in (old, new):
                payload = json.loads(result.content[0].text)
                assert nested in payload, f"{name} did not produce the nested error case"
                assert "error" not in payload, f"{name} unexpectedly failed outright"
                assert result.is_error is False, f"{name} partial success flagged as an error"
            assert new.structured_content == json.loads(new.content[0].text)

    # Second run: one write refused again, the other already matches.
    update_payload = json.loads(new.content[0].text)
    assert update_payload["failed"] == 1
    assert update_payload["updated"] + update_payload["unchanged"] == 1
    assert any("error" in r for r in update_payload["results"])


# ---------------------------------------------------------------------------
# The middleware unit: every mode, every era
# ---------------------------------------------------------------------------


class _Session:
    def __init__(self, revision: str | None) -> None:
        self.client_params = (
            None if revision is None else type("P", (), {"protocolVersion": revision})()
        )


class _Ctx:
    def __init__(self, revision: str | None) -> None:
        self.fastmcp_context = type("F", (), {"session": _Session(revision)})()
        self.message = type("M", (), {"name": "update_vlan"})()


def _envelope_result(text: str) -> Any:
    from fastmcp.tools import ToolResult
    from mcp import types as mt

    return ToolResult(
        content=[mt.TextContent(type="text", text=text)],
        structured_content={"result": text},
    )


ENVELOPE_TEXT = json.dumps(
    {
        "error": "network ghost not found",
        "stub_mode": True,
        "partial": {"x_passphrase": "[REDACTED]"},
    },
    indent=2,
)


@pytest.mark.parametrize("revision", [None, "2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"])
@pytest.mark.parametrize(
    "middleware",
    [
        AdaptiveResponseMiddleware(),
        AdaptiveResponseMiddleware(compact=True),
        AdaptiveResponseMiddleware(force_full_text=True),
    ],
    ids=["default", "compact", "force_full_text"],
)
async def test_middleware_flags_the_envelope_in_every_mode_and_era(
    middleware: AdaptiveResponseMiddleware, revision: str | None
) -> None:
    async def call_next(_ctx: Any) -> Any:
        return _envelope_result(ENVELOPE_TEXT)

    result = await middleware.on_call_tool(_Ctx(revision), call_next)
    assert result.is_error is True
    # The text block is the envelope, byte for byte, in every mode: compact
    # mode does not summarise an error, and redaction already applied is kept.
    assert result.content[0].text == ENVELOPE_TEXT
    wire = result.to_mcp_result()
    assert wire.is_error is True


async def test_middleware_leaves_a_success_unflagged() -> None:
    async def call_next(_ctx: Any) -> Any:
        return _envelope_result(json.dumps({"results": [{"error": "x"}], "stub_mode": True}))

    for revision in (None, "2025-11-25"):
        result = await AdaptiveResponseMiddleware().on_call_tool(_Ctx(revision), call_next)
        assert result.is_error is False


# ---------------------------------------------------------------------------
# A composite's own failure envelope, not the unknown-controller path
# ---------------------------------------------------------------------------

GUEST_SECRET = "guest-passphrase-must-not-leak"


async def test_composite_rollback_failure_is_an_error_with_secrets_redacted(
    stub_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """create_guest_network fails after the WLAN step; the rollback envelope is an error.

    The sweep only drives the unknown-controller path, which every tool shares.
    This is the other kind of producer: a composite's ``_fail`` envelope, with
    ``partial`` and ``rolled_back`` beside ``error``. The WLAN it created holds
    the passphrase, so the envelope also has to stay redacted on both channels.
    """

    async def refuse(_self: Any, _payload: Any) -> Any:
        raise UniFiError("controller refused the isolation rule")

    # Whichever firewall model the stub site uses, the step after the WLAN fails.
    monkeypatch.setattr(StubBackend, "create_firewall_rule", refuse)
    monkeypatch.setattr(StubBackend, "create_v1_firewall_policy", refuse)
    server = build_server(stub_settings.model_copy(update={"mcp_transport": "stdio"}))
    args = {"name": "Guests", "ssid": "Guests", "passphrase": GUEST_SECRET, "vlan_id": 77}

    old = await server.call_tool("create_guest_network", args)
    async with Client(server) as client:
        new = await client.call_tool("create_guest_network", args, raise_on_error=False)

    for result, era in ((old, "text-only era"), (new, "structured era")):
        env = _assert_envelope(result, where=f"create_guest_network rollback ({era})")
        assert env["error"].startswith("create_guest_network failed at firewall_"), env["error"]
        assert env["stub_mode"] is True
        # The full envelope is the text, not a summary: the WLAN that was
        # created and the rollback record are both there for the caller.
        assert "wlan" in env["partial"], env["partial"]
        assert env["rolled_back"], "the rollback actions were not reported"
        assert env["partial"]["wlan"].get("x_passphrase") == "[REDACTED]"
        assert GUEST_SECRET not in result.content[0].text
    assert new.structured_content == json.loads(new.content[0].text)
    assert GUEST_SECRET not in json.dumps(new.structured_content)


# ---------------------------------------------------------------------------
# diagnose_site: a failed read inside a successful diagnosis is not an error
# ---------------------------------------------------------------------------


async def test_diagnose_site_with_a_failed_read_is_a_success(
    stub_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The read's error sits inside ``checks``; the diagnosis itself succeeded.

    tests/test_error_envelope_producers.py exempts ``check["error"] = ...`` in
    ``build_report`` by name. This proves at runtime that the exemption is
    right: the result is not an envelope and must not set isError.
    """

    async def clients_fail(_self: Any) -> Any:
        raise UniFiError("HTTP 500 reading clients")

    monkeypatch.setattr(StubBackend, "list_clients", clients_fail)
    server = build_server(stub_settings.model_copy(update={"mcp_transport": "stdio"}))
    old = await server.call_tool("diagnose_site", {})
    async with Client(server) as client:
        new = await client.call_tool("diagnose_site", {}, raise_on_error=False)
    for result in (old, new):
        assert result.is_error is False
        payload = json.loads(result.content[0].text)
        assert "error" not in payload
        failed = [c for c in payload["checks"] if not c["ok"]]
        assert [c["source"] for c in failed] == ["list_clients"], payload["checks"]
        assert "HTTP 500 reading clients" in failed[0]["error"]


async def test_diagnose_site_unknown_controller_is_an_error(stub_settings: Settings) -> None:
    server = build_server(stub_settings.model_copy(update={"mcp_transport": "stdio"}))
    old = await server.call_tool("diagnose_site", {"controller": NOPE})
    async with Client(server) as client:
        new = await client.call_tool("diagnose_site", {"controller": NOPE}, raise_on_error=False)
    for result, era in ((old, "text-only era"), (new, "structured era")):
        env = _assert_envelope(result, where=f"diagnose_site unknown controller ({era})")
        assert "nope" in env["error"]
