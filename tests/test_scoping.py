"""Per-client tool scoping (v0.17+).

Covers three layers:

* :meth:`Settings.auth_client_scopes` parses the extended
  ``client_id:token:module1|module2`` token form into
  ``{client_id: allowed_modules}``. Bare tokens and two-part
  ``id:token`` entries stay backward-compatible with the pre-scoping
  wildcard behavior.
* :func:`register_modules` tags every registered tool with its module
  name (``"network"``, ``"protect"``, ``"access"``) via ``tool.tags``.
* :class:`ScopeMiddleware` filters ``tools/list`` and rejects
  ``tools/call`` on out-of-scope tools when the caller's allowed set
  does not include the tool's module.

The middleware tests drive it directly (unit-test shape) rather than
spinning up an HTTP transport, because the interesting logic lives in
the middleware itself and hitting real HTTP would just add flakiness.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
from fastmcp.exceptions import ToolError

from mcp_unifi.config import Settings
from mcp_unifi.scoping import WILDCARD, ScopeMiddleware
from mcp_unifi.server import build_server

# ---------------------------------------------------------------------------
# Settings: auth_client_scopes parser
# ---------------------------------------------------------------------------


def _scopes(tokens: str) -> dict[str, set[str]]:
    return Settings(stub_mode=True, auth_required=False, auth_tokens=tokens).auth_client_scopes


def test_auth_client_scopes_empty_when_unset() -> None:
    assert _scopes("") == {}


def test_bare_token_gets_wildcard_scope() -> None:
    """Bare tokens are the pre-scoping shape — no restriction."""
    assert _scopes("tok-aaa,tok-bbb") == {
        "client-0": {WILDCARD},
        "client-1": {WILDCARD},
    }


def test_two_part_named_token_gets_wildcard_scope() -> None:
    """id:token (pre-scoping) still permits every module."""
    assert _scopes("claude:tok-aaa,n8n:tok-bbb") == {
        "claude": {WILDCARD},
        "n8n": {WILDCARD},
    }


def test_three_part_token_parses_module_allowlist() -> None:
    """Concrete scope narrows the client to the listed modules."""
    result = _scopes("readonly:tok-r:network,writer:tok-w:network|protect")
    assert result == {"readonly": {"network"}, "writer": {"network", "protect"}}


def test_three_part_token_star_scope_stays_wildcard() -> None:
    """Explicit ``*`` collapses to the wildcard set (no accidental restriction)."""
    result = _scopes("admin:tok-a:*")
    assert result == {"admin": {WILDCARD}}


def test_three_part_token_star_dominates_named_modules() -> None:
    """Mixing ``*`` with named modules collapses to wildcard — never over-restrict."""
    result = _scopes("admin:tok-a:*|network")
    assert result == {"admin": {WILDCARD}}


def test_three_part_token_tolerates_whitespace() -> None:
    result = _scopes("  ops : tok-o : network | protect  ")
    assert result == {"ops": {"network", "protect"}}


def test_three_part_token_empty_scope_rejected() -> None:
    """`readonly:tok:` (trailing colon, empty scope) must fail loudly, not silently
    collapse to wildcard access. The three-part form is an explicit scoping request.
    """
    with pytest.raises(ValueError, match="empty scope list"):
        _scopes("readonly:tok-r:")


def test_three_part_token_whitespace_only_scope_rejected() -> None:
    with pytest.raises(ValueError, match="empty scope list"):
        _scopes("readonly:tok-r:   ")


def test_duplicate_client_ids_rejected() -> None:
    """Two entries with the same client_id would ambiguate the scope map."""
    s = Settings(
        stub_mode=True,
        auth_required=False,
        auth_tokens="dup:tok-1,dup:tok-2",
    )
    with pytest.raises(ValueError, match="reuses client_id"):
        _ = s.auth_client_scopes


def test_empty_client_id_rejected() -> None:
    s = Settings(
        stub_mode=True,
        auth_required=False,
        auth_tokens=":tok-1",
    )
    with pytest.raises(ValueError, match="empty client_id"):
        _ = s.auth_client_scopes


def test_empty_module_names_after_pipe_split_are_dropped() -> None:
    """Trailing/leading/adjacent pipes shouldn't produce empty-string 'modules'."""
    result = _scopes("ops:tok-o:network||protect|")
    assert result == {"ops": {"network", "protect"}}


def test_token_with_pipe_rejected() -> None:
    """A pipe in the token would be silently reinterpreted as a module boundary."""
    s = Settings(stub_mode=True, auth_required=False, auth_tokens="ops:tok|weird")
    with pytest.raises(ValueError, match="reserved delimiter"):
        _ = s.auth_client_scopes


def test_unknown_module_scope_rejected() -> None:
    """A typo like 'protects' or a stray colon in the intended token would
    silently produce an unknown scope. Reject at parse time so misconfig is
    loud, not silent.

    This is the fail-closed behavior the reviewer flagged: a token like
    ``ops:my:secret:network`` produces client=ops, token=my (safe), scope
    ``secret:network`` — an unknown 'module' that would give the client an
    empty allow set. Better to refuse to boot.
    """
    s = Settings(stub_mode=True, auth_required=False, auth_tokens="ops:tok:networks")
    with pytest.raises(ValueError, match=r"unknown .*module scope"):
        _ = s.auth_client_scopes


def test_colon_in_intended_token_becomes_unknown_scope_and_rejected() -> None:
    """End-to-end check on the exact ``ops:my:secret:network`` misconfig."""
    s = Settings(stub_mode=True, auth_required=False, auth_tokens="ops:my:secret:network")
    with pytest.raises(ValueError, match=r"unknown .*module scope"):
        _ = s.auth_client_scopes


def test_scope_names_match_dispatcher_known_modules() -> None:
    """The config-layer scope allowlist and dispatcher.KNOWN_MODULES must agree.

    Both are frozensets of the same three strings, duplicated to keep
    config a leaf module. If one drifts (a fourth module ships, an
    existing one is renamed), tokens either accept unknown scopes or
    reject valid ones. Catch drift here.
    """
    from mcp_unifi.config import _KNOWN_MODULE_SCOPES
    from mcp_unifi.dispatcher import KNOWN_MODULES

    assert _KNOWN_MODULE_SCOPES == KNOWN_MODULES


# ---------------------------------------------------------------------------
# Dispatcher: tools are tagged by module
# ---------------------------------------------------------------------------


@pytest.fixture()
def _all_modules_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """Enable network + protect + access via the env var the dispatcher reads.

    ``mcp_unifi.dispatcher._enabled_modules`` reads
    ``MCP_UNIFI_MODULES_ENABLED`` from ``os.environ`` directly, not from the
    Settings object. Patch it here for the tag-attribution tests.
    """
    monkeypatch.setenv("MCP_UNIFI_MODULES_ENABLED", "network,protect,access")


@pytest.mark.asyncio
async def test_all_registered_tools_carry_a_module_tag(
    _all_modules_enabled: None,
) -> None:
    """Every tool from network/protect/access must inherit its module's tag.

    If any tool comes back untagged, the scope middleware would either
    over-share (WILDCARD fallback) or under-share (empty tag intersection).
    Both are silent failures — catch here.
    """
    settings = Settings(stub_mode=True, log_format="text", mcp_transport="stdio")
    server = build_server(settings)
    tools = await server.list_tools()
    untagged = [t.name for t in tools if not (t.tags & {"network", "protect", "access"})]
    assert untagged == [], f"tools without a module tag: {untagged}"


@pytest.mark.asyncio
async def test_tool_tags_match_owning_module(_all_modules_enabled: None) -> None:
    """A network tool must not be tagged protect, and vice versa."""
    settings = Settings(stub_mode=True, log_format="text", mcp_transport="stdio")
    server = build_server(settings)
    tools = await server.list_tools()
    by_tag = {"network": 0, "protect": 0, "access": 0}
    for tool in tools:
        module_tags = tool.tags & {"network", "protect", "access"}
        # No tool should belong to more than one top-level module.
        assert len(module_tags) == 1, (
            f"{tool.name} tagged with {sorted(module_tags)} (expected exactly one)"
        )
        by_tag[next(iter(module_tags))] += 1
    assert sum(by_tag.values()) == len(tools)
    assert all(count > 0 for count in by_tag.values())


# ---------------------------------------------------------------------------
# ScopeMiddleware: list_tools filter
# ---------------------------------------------------------------------------


class _StubTool:
    """Bare-minimum stand-in for a fastmcp Tool with a name + tags."""

    def __init__(self, name: str, tags: set[str]) -> None:
        self.name = name
        self.tags = tags


class _StubListContext:
    """MiddlewareContext stand-in for the on_list_tools path."""

    def __init__(self) -> None:
        self.message = object()
        self.fastmcp_context = None


class _StubCallContext:
    """MiddlewareContext stand-in for the on_call_tool path."""

    def __init__(self, tool_name: str, tool_lookup: dict[str, _StubTool]) -> None:
        self.message = type("_Msg", (), {"name": tool_name})()

        class _StubFastmcp:
            async def get_tool(_self, name: str) -> _StubTool:
                if name in tool_lookup:
                    return tool_lookup[name]
                raise LookupError(name)

        class _StubFmCtx:
            def __init__(_self) -> None:
                _self.fastmcp = _StubFastmcp()

        self.fastmcp_context = _StubFmCtx()


def _all_tools() -> list[_StubTool]:
    return [
        _StubTool("list_networks", {"network"}),
        _StubTool("delete_vlan", {"network"}),
        _StubTool("list_cameras", {"protect"}),
        _StubTool("list_doors", {"access"}),
    ]


@pytest.mark.asyncio
async def test_list_tools_returns_everything_when_scope_is_wildcard() -> None:
    mw = ScopeMiddleware(client_scopes={"admin": {WILDCARD}})

    async def call_next(ctx: Any) -> list[_StubTool]:
        return _all_tools()

    with patch("mcp_unifi.scoping._current_client_id", return_value="admin"):
        out = await mw.on_list_tools(_StubListContext(), call_next)
    assert [t.name for t in out] == ["list_networks", "delete_vlan", "list_cameras", "list_doors"]


@pytest.mark.asyncio
async def test_list_tools_filters_to_scoped_modules() -> None:
    mw = ScopeMiddleware(client_scopes={"readonly": {"protect", "access"}})

    async def call_next(ctx: Any) -> list[_StubTool]:
        return _all_tools()

    with patch("mcp_unifi.scoping._current_client_id", return_value="readonly"):
        out = await mw.on_list_tools(_StubListContext(), call_next)
    assert sorted(t.name for t in out) == ["list_cameras", "list_doors"]


@pytest.mark.asyncio
async def test_list_tools_denies_when_client_unknown() -> None:
    """A client_id not in the scope map is an anomaly — fail closed, don't grant wildcard."""
    mw = ScopeMiddleware(client_scopes={"admin": {WILDCARD}})

    async def call_next(ctx: Any) -> list[_StubTool]:
        return _all_tools()

    with patch("mcp_unifi.scoping._current_client_id", return_value="mystery-client"):
        out = await mw.on_list_tools(_StubListContext(), call_next)
    assert out == []


@pytest.mark.asyncio
async def test_list_tools_denies_when_no_client_id_available() -> None:
    """Middleware isn't installed on stdio, so client_id=None here means the auth
    context is broken or missing — deny rather than fall through to wildcard.
    """
    mw = ScopeMiddleware(client_scopes={"readonly": {"network"}})

    async def call_next(ctx: Any) -> list[_StubTool]:
        return _all_tools()

    with patch("mcp_unifi.scoping._current_client_id", return_value=None):
        out = await mw.on_list_tools(_StubListContext(), call_next)
    assert out == []


# ---------------------------------------------------------------------------
# ScopeMiddleware: call_tool gate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_call_tool_allowed_when_scope_matches() -> None:
    mw = ScopeMiddleware(client_scopes={"readonly": {"protect"}})
    tools = {t.name: t for t in _all_tools()}

    async def call_next(ctx: Any) -> str:
        return "ok"

    with patch("mcp_unifi.scoping._current_client_id", return_value="readonly"):
        result = await mw.on_call_tool(_StubCallContext("list_cameras", tools), call_next)
    assert result == "ok"


@pytest.mark.asyncio
async def test_call_tool_rejected_when_scope_does_not_match() -> None:
    mw = ScopeMiddleware(client_scopes={"readonly": {"protect"}})
    tools = {t.name: t for t in _all_tools()}

    async def call_next(ctx: Any) -> str:
        pytest.fail("call_next must not run for a scope-denied tool")
        return "unreachable"

    with (
        patch("mcp_unifi.scoping._current_client_id", return_value="readonly"),
        pytest.raises(ToolError, match="not available"),
    ):
        await mw.on_call_tool(_StubCallContext("delete_vlan", tools), call_next)


@pytest.mark.asyncio
async def test_call_tool_wildcard_bypasses_the_gate() -> None:
    mw = ScopeMiddleware(client_scopes={"admin": {WILDCARD}})
    tools = {t.name: t for t in _all_tools()}

    async def call_next(ctx: Any) -> str:
        return "ok"

    with patch("mcp_unifi.scoping._current_client_id", return_value="admin"):
        result = await mw.on_call_tool(_StubCallContext("delete_vlan", tools), call_next)
    assert result == "ok"


@pytest.mark.asyncio
async def test_call_tool_rejection_message_does_not_leak_module_names() -> None:
    """A scoped client shouldn't be able to probe which modules exist."""
    mw = ScopeMiddleware(client_scopes={"readonly": {"network"}})
    tools = {t.name: t for t in _all_tools()}

    async def call_next(ctx: Any) -> str:
        return "unreachable"

    with (
        patch("mcp_unifi.scoping._current_client_id", return_value="readonly"),
        pytest.raises(ToolError) as exc,
    ):
        await mw.on_call_tool(_StubCallContext("list_cameras", tools), call_next)
    assert "protect" not in str(exc.value).lower()
    assert "access" not in str(exc.value).lower()


@pytest.mark.asyncio
async def test_call_tool_denied_when_client_id_is_none() -> None:
    """Unresolved identity denies calls, not silently permits them."""
    mw = ScopeMiddleware(client_scopes={"readonly": {"network"}})
    tools = {t.name: t for t in _all_tools()}

    async def call_next(ctx: Any) -> str:
        pytest.fail("call_next must not run when identity is unresolved")
        return "unreachable"

    with (
        patch("mcp_unifi.scoping._current_client_id", return_value=None),
        pytest.raises(ToolError, match="not available"),
    ):
        await mw.on_call_tool(_StubCallContext("list_vlans", tools), call_next)


@pytest.mark.asyncio
async def test_call_tool_denied_when_client_id_not_in_scope_map() -> None:
    """A configured token whose client_id isn't in the scope map is anomalous.
    Fail closed rather than treating the missing entry as wildcard.
    """
    mw = ScopeMiddleware(client_scopes={"readonly": {"network"}})
    tools = {t.name: t for t in _all_tools()}

    async def call_next(ctx: Any) -> str:
        pytest.fail("call_next must not run for a client not in the scope map")
        return "unreachable"

    with (
        patch("mcp_unifi.scoping._current_client_id", return_value="mystery-client"),
        pytest.raises(ToolError, match="not available"),
    ):
        await mw.on_call_tool(_StubCallContext("list_vlans", tools), call_next)


# ---------------------------------------------------------------------------
# build_server integration: middleware only installed when it actually filters
# ---------------------------------------------------------------------------


def _middleware_types(server: Any) -> list[str]:
    """Best-effort list of installed middleware class names."""
    mw = getattr(server, "middleware", None)
    if mw is None:
        for attr in ("_middleware", "_middlewares", "middlewares"):
            mw = getattr(server, attr, None)
            if mw is not None:
                break
    return [type(m).__name__ for m in (mw or [])]


def test_scope_middleware_not_installed_on_stdio() -> None:
    """Stdio has no authenticated clients to distinguish."""
    settings = Settings(
        stub_mode=True,
        mcp_transport="stdio",
        auth_required=False,
        auth_tokens="ops:tok-o:network",  # would install for HTTP, no-op for stdio
    )
    server = build_server(settings)
    assert "ScopeMiddleware" not in _middleware_types(server)


def test_scope_middleware_not_installed_when_every_client_is_wildcard() -> None:
    """No point paying the per-request cost when the filter would let everything through."""
    settings = Settings(
        stub_mode=True,
        mcp_transport="streamable-http",
        auth_required=True,
        auth_tokens="a:tok-1,b:tok-2:*",
    )
    server = build_server(settings)
    assert "ScopeMiddleware" not in _middleware_types(server)


def test_scope_middleware_installed_when_any_client_is_scoped() -> None:
    """Presence of at least one non-wildcard scope switches the filter on."""
    settings = Settings(
        stub_mode=True,
        mcp_transport="streamable-http",
        auth_required=True,
        auth_tokens="admin:tok-a,readonly:tok-r:protect",
    )
    server = build_server(settings)
    assert "ScopeMiddleware" in _middleware_types(server)
