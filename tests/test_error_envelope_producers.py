"""Static guard: every place that builds an ``error`` payload also says ``stub_mode``.

The response middleware recognises a failure by a top-level non-empty string
``error`` *and* a boolean ``stub_mode`` (``mcp_unifi.responses.is_error_envelope``).
Requiring both keeps a success payload with its own ``error`` field from being
misread as a failure, but it has a cost: a failure path that forgets
``stub_mode`` silently goes back to ``isError: false``. The runtime sweep in
``tests/test_error_contract.py`` only reaches the unknown-controller path, so
it cannot see a composite's rollback envelope or ``restore_config``'s apply
failure. A reviewer proved it: deleting ``stub_mode`` from either left the
whole suite green.

This test reads the source instead. It walks every module under
``src/mcp_unifi/modules`` plus ``src/mcp_unifi/scoping.py`` with ``ast`` and
finds every payload built with an ``"error"`` key:

* a dict literal (``{"error": ..., ...}``, including ``{**base, "error": ...}``);
* a ``dict(error=...)`` call, and ``x.update(error=...)``;
* a subscript store, ``x["error"] = ...``.

Each one must also carry ``"stub_mode"``, unless it is

* a logging ``extra=`` mapping, which is a log record, never tool output; or
* nested in a list, a per-item container or another dict, and listed in
  :data:`NESTED_ALLOWLIST` with the reason it is not a top-level result; or
* a module-level constant named in :data:`LOOKUP_TABLES` (a table keyed by a
  controller status word, never returned); or
* a ``var["error"] = ...`` store into the exact variable named in
  :data:`PER_ITEM_STORES` (a per-item record inside a successful result).

The last two are keyed by name, not by enclosing function, so another
``error`` payload added to the same module or function is still checked.

WHAT THIS CANNOT SEE
--------------------
* A key that is not a string constant (``{key: msg}`` where ``key == "error"``).
* An envelope built outside the walked files, or by a helper the walked code
  calls with the dict already assembled elsewhere.
* JSON text written by hand, and raw controller records passed through as a
  tool result (those are why the detector requires ``stub_mode`` at all).
* Whether ``stub_mode`` holds a bool. ``tests/test_error_contract.py`` checks
  the values at runtime.
* ``{**base, "error": x}`` where ``base`` already carries ``stub_mode``: that
  is flagged here as missing it and would need an allowlist entry.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src" / "mcp_unifi"
SCANNED: tuple[Path, ...] = (*sorted((SRC / "modules").rglob("*.py")), SRC / "scoping.py")

#: ``(file relative to src/mcp_unifi, enclosing function)`` -> why an ``error``
#: payload built there without ``stub_mode`` is not a top-level tool result.
#: A stale entry (one that no longer matches anything) fails the test too.
NESTED_ALLOWLIST: dict[tuple[str, str], str] = {
    # One entry per MAC in ``results``; the call's own failure envelope at the
    # end of update_clients carries stub_mode and is checked like any other.
    ("modules/network/clients.py", "update_clients"): "per-item results entries",
}

#: ``(file, module-level constant name)`` -> why that constant is a lookup
#: table and not a payload. Only a dict assigned straight to that name at
#: module level matches; a stale entry fails the test.
LOOKUP_TABLES: dict[tuple[str, str], str] = {
    ("modules/network/diagnose.py", "_STATUS_RANK"): "status-word rank table, never returned",
    ("modules/network/diagnose.py", "_STATUS_SEVERITY"): "status-word severity map, never returned",
}

#: ``(file, enclosing function, variable)`` -> why ``variable["error"] = ...``
#: there is a per-item record. Only that variable in that function matches, so
#: an envelope built any other way in the same function is still checked.
PER_ITEM_STORES: dict[tuple[str, str, str], str] = {
    # One entry per read in diagnose_site's ``checks`` list of a successful
    # diagnosis, like get_console_health's probe errors.
    ("modules/network/diagnose.py", "build_report", "check"): "per-read checks entry",
}

#: The producers that must be found, so the test cannot pass by scanning
#: nothing. ``(file, innermost function, outer function or "")``.
KNOWN_PRODUCERS: frozenset[tuple[str, str, str]] = frozenset(
    {
        ("modules/network/_common.py", "err", "make_err"),
        ("modules/network/composites.py", "_fail", "create_iot_network"),
        ("modules/network/composites.py", "_fail", "provision_homelab_service"),
        ("modules/network/composites.py", "_fail", "create_guest_network"),
        ("modules/network/backup.py", "_execute", "restore_config"),
        ("modules/network/clients.py", "update_clients", "register"),
        ("modules/protect/__init__.py", "_fail", "provision_camera"),
        ("scoping.py", "refusal_result", ""),
    }
)

_LIST_METHODS = frozenset({"append", "extend", "insert"})


@dataclass(frozen=True, slots=True)
class Site:
    file: str
    line: int
    functions: tuple[str, ...]  # innermost first
    has_stub_mode: bool
    is_log_extra: bool
    nested: bool
    constant: str | None = None  # module-level ``NAME = {...}`` target
    store_target: str | None = None  # ``name`` in ``name["error"] = ...``

    @property
    def where(self) -> str:
        return f"{self.file}:{self.line} in {'.'.join(reversed(self.functions)) or '<module>'}"


def _parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    out: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            out[child] = node
    return out


def _functions(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> tuple[str, ...]:
    names: list[str] = []
    while node in parents:
        node = parents[node]
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            names.append(node.name)
    return tuple(names)


def _keys(node: ast.AST) -> set[str] | None:
    """String keys of a payload-building node, or None if it builds none."""
    if isinstance(node, ast.Dict):
        return {
            k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)
        }
    if isinstance(node, ast.Call):
        func = node.func
        is_dict_call = isinstance(func, ast.Name) and func.id == "dict"
        is_update = isinstance(func, ast.Attribute) and func.attr == "update"
        if is_dict_call or is_update:
            kw = {k.arg for k in node.keywords if k.arg}
            return kw or None
    return None


def _is_log_extra(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    parent = parents.get(node)
    return isinstance(parent, ast.keyword) and parent.arg == "extra"


def _is_nested(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> bool:
    """True when the payload is an element of a list or a value inside another dict."""
    parent = parents.get(node)
    if isinstance(parent, ast.List | ast.Tuple | ast.Set | ast.ListComp | ast.GeneratorExp):
        return True
    if isinstance(parent, ast.Dict) and node in parent.values:
        return True
    return (
        isinstance(parent, ast.Call)
        and isinstance(parent.func, ast.Attribute)
        and parent.func.attr in _LIST_METHODS
    )


def _module_constant(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> str | None:
    """The name a dict is assigned to at module level, else None."""
    parent = parents.get(node)
    if isinstance(parent, ast.AnnAssign) and parent.value is node:
        targets: list[ast.expr] = [parent.target]
    elif isinstance(parent, ast.Assign) and parent.value is node:
        targets = list(parent.targets)
    else:
        return None
    if not isinstance(parents.get(parent), ast.Module):
        return None
    if len(targets) == 1 and isinstance(targets[0], ast.Name):
        return targets[0].id
    return None


def _sites() -> list[Site]:
    sites: list[Site] = []
    for path in SCANNED:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        parents = _parents(tree)
        rel = path.relative_to(SRC).as_posix()
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Subscript)
                and isinstance(node.ctx, ast.Store)
                and isinstance(node.slice, ast.Constant)
                and node.slice.value == "error"
            ):
                # ``x["error"] = ...``: the container's other keys are not
                # visible here, so it never counts as carrying stub_mode.
                target = node.value.id if isinstance(node.value, ast.Name) else None
                sites.append(
                    Site(
                        rel,
                        node.lineno,
                        _functions(node, parents),
                        False,
                        False,
                        False,
                        store_target=target,
                    )
                )
                continue
            keys = _keys(node)
            if not keys or "error" not in keys:
                continue
            sites.append(
                Site(
                    rel,
                    node.lineno,
                    _functions(node, parents),
                    "stub_mode" in keys,
                    _is_log_extra(node, parents),
                    _is_nested(node, parents),
                    constant=_module_constant(node, parents),
                )
            )
    return sites


def test_the_scan_finds_every_known_envelope_producer() -> None:
    """Non-vacuous: the scanner must see the producers it exists to guard."""
    found = {
        (s.file, s.functions[0], s.functions[1] if len(s.functions) > 1 else "")
        for s in _sites()
        if s.has_stub_mode and s.functions
    }
    missing = KNOWN_PRODUCERS - found
    assert not missing, f"scanner no longer finds these envelope producers: {sorted(missing)}"


def test_every_error_payload_carries_stub_mode() -> None:
    """A failure envelope without stub_mode would reach clients with isError false."""
    offenders: list[str] = []
    used: set[tuple[str, str]] = set()
    used_tables: set[tuple[str, str]] = set()
    used_stores: set[tuple[str, str, str]] = set()
    for site in _sites():
        if site.has_stub_mode or site.is_log_extra:
            continue
        func = site.functions[0] if site.functions else ""
        key = (site.file, func)
        if site.nested and key in NESTED_ALLOWLIST:
            used.add(key)
            continue
        if not site.functions and site.constant is not None:
            table = (site.file, site.constant)
            if table in LOOKUP_TABLES:
                used_tables.add(table)
                continue
        if site.store_target is not None:
            store = (site.file, func, site.store_target)
            if store in PER_ITEM_STORES:
                used_stores.add(store)
                continue
        offenders.append(site.where)
    assert offenders == [], (
        "these build an 'error' payload without 'stub_mode', so the response middleware "
        "will not flag them as errors. Add stub_mode, or if the dict is a nested per-item "
        f"record and not a tool result, add it to NESTED_ALLOWLIST with a reason: {offenders}"
    )
    stale = set(NESTED_ALLOWLIST) - used
    assert not stale, f"NESTED_ALLOWLIST entries that match nothing: {sorted(stale)}"
    stale_tables = set(LOOKUP_TABLES) - used_tables
    assert not stale_tables, f"LOOKUP_TABLES entries that match nothing: {sorted(stale_tables)}"
    stale_stores = set(PER_ITEM_STORES) - used_stores
    assert not stale_stores, f"PER_ITEM_STORES entries that match nothing: {sorted(stale_stores)}"


def test_nested_rule_does_not_exempt_a_top_level_payload() -> None:
    """Control for the classifier itself: shapes it must flag and must not."""
    source = (
        "def tool():\n"
        "    results.append({'error': 'x'})\n"  # nested: list element
        "    out = {'items': {'error': 'x'}}\n"  # nested: dict value
        "    logger.warning('m', extra={'error': 'x'})\n"  # log extra
        "    return format_json({'error': 'x'})\n"  # top level, no stub_mode
    )
    tree = ast.parse(source)
    parents = _parents(tree)
    shapes = [
        (_is_nested(n, parents), _is_log_extra(n, parents))
        for n in ast.walk(tree)
        if isinstance(n, ast.Dict) and "error" in (_keys(n) or set())
    ]
    assert sorted(shapes) == [(False, False), (False, True), (True, False), (True, False)]
    call = ast.parse("dict(error='x')").body[0].value  # type: ignore[attr-defined]
    assert _keys(call) == {"error"}


def test_name_keyed_exemptions_do_not_cover_their_neighbours() -> None:
    """Control: the two name-keyed tables exempt exactly the named target."""
    source = (
        "_STATUS_RANK = {'error': 0}\n"  # listed constant
        "OTHER = {'error': 'x'}\n"  # module constant, not listed
        "def build_report():\n"
        "    check['error'] = 'x'\n"  # listed store
        "    report['error'] = 'x'\n"  # same function, other variable
        "    local = {'error': 'x'}\n"  # same function, a literal
    )
    tree = ast.parse(source)
    parents = _parents(tree)
    constants = sorted(
        str(_module_constant(n, parents))
        for n in ast.walk(tree)
        if isinstance(n, ast.Dict) and "error" in (_keys(n) or set())
    )
    # ``local`` sits inside a function, so it is not a module constant.
    assert constants == ["None", "OTHER", "_STATUS_RANK"]
    stores = sorted(
        n.value.id
        for n in ast.walk(tree)
        if isinstance(n, ast.Subscript)
        and isinstance(n.ctx, ast.Store)
        and isinstance(n.value, ast.Name)
    )
    assert stores == ["check", "report"]
    assert ("modules/network/diagnose.py", "build_report", "report") not in PER_ITEM_STORES
