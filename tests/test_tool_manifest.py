"""Tests for ``scripts/generate_tool_manifest.py``.

The manifest is a public artifact (it lives in the Astro docs site and gets
deployed alongside the rest of the reference docs). It must be deterministic
so the pre-commit hook can enforce drift-free generation, and it must
include every tool registered on FastMCP — including ``confirm_destructive_action``
which v0.7.0 added.

These tests run the generator end-to-end against the real FastMCP
registration. They cover:

* The generator script runs cleanly to completion.
* The output is deterministic (running twice produces no diff).
* The new ``confirm_destructive_action`` tool from Feature 1 appears in the
  manifest (both in the per-tool files and in the index).
* Every registered tool has a corresponding ``tools/<name>/index.md`` file.
* ``--check`` returns 0 on a clean tree and 1 when something would change.
"""

from __future__ import annotations

import asyncio

# Import the generator as a module so we can call its helpers directly.
# The script lives in ``scripts/`` which is not a package; we use spec import.
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_PATH = REPO_ROOT / "scripts" / "generate_tool_manifest.py"

_spec = importlib.util.spec_from_file_location("_gen_tool_manifest", SCRIPT_PATH)
assert _spec is not None and _spec.loader is not None
generate_tool_manifest = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(generate_tool_manifest)


# ---------------------------------------------------------------------------
# Generator script runs cleanly against the live registration
# ---------------------------------------------------------------------------


def test_collect_tools_succeeds() -> None:
    """The live FastMCP registration must produce a non-empty tool list."""
    tools = asyncio.run(generate_tool_manifest._collect_tools())
    assert isinstance(tools, list)
    assert len(tools) > 0
    # Spot-check shape.
    for tool in tools:
        assert "name" in tool
        assert "description" in tool
        assert "input_schema" in tool


def test_collect_tools_sorted_by_name() -> None:
    """Output ordering is the sole driver of file-write ordering, so verify it."""
    tools = asyncio.run(generate_tool_manifest._collect_tools())
    names = [t["name"] for t in tools]
    assert names == sorted(names)


# ---------------------------------------------------------------------------
# confirm_destructive_action is present
# ---------------------------------------------------------------------------


def test_confirm_destructive_action_in_manifest() -> None:
    tools = asyncio.run(generate_tool_manifest._collect_tools())
    names = {t["name"] for t in tools}
    assert "confirm_destructive_action" in names
    # And every PtC delete tool is still registered.
    for delete_tool in (
        "delete_firewall_rule",
        "delete_vlan",
        "delete_wlan",
        "delete_port_profile",
        "delete_port_forward",
        "delete_static_dhcp_lease",
    ):
        assert delete_tool in names, f"{delete_tool} missing from manifest"


# ---------------------------------------------------------------------------
# Deterministic output
# ---------------------------------------------------------------------------


def test_generator_output_is_deterministic() -> None:
    """Two consecutive renders must produce identical content.

    We render in-memory (no disk writes) so the test is hermetic and runs
    in the same temp-dir-isolated harness as everything else.
    """
    tools = asyncio.run(generate_tool_manifest._collect_tools())
    first_pages = {t["name"]: generate_tool_manifest._render_tool_page(t) for t in tools}
    first_index = generate_tool_manifest._render_index(tools)
    # Re-collect from a fresh build_server to make sure registration is stable.
    tools_again = asyncio.run(generate_tool_manifest._collect_tools())
    second_pages = {t["name"]: generate_tool_manifest._render_tool_page(t) for t in tools_again}
    second_index = generate_tool_manifest._render_index(tools_again)

    assert first_pages == second_pages
    assert first_index == second_index


# ---------------------------------------------------------------------------
# End-to-end: --check on the checked-in output passes
# ---------------------------------------------------------------------------


def test_check_mode_passes_against_checked_in_output() -> None:
    """If this fails, run ``python scripts/generate_tool_manifest.py`` and commit."""
    # ``sys.executable`` and ``SCRIPT_PATH`` are trusted (set by the test
    # harness itself), so the S603 lint about untrusted subprocess input
    # doesn't apply.
    proc = subprocess.run(  # noqa: S603
        [sys.executable, str(SCRIPT_PATH), "--check"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    # We allow either: exit 0 (in sync) OR exit 1 with "out of sync" message
    # (which would mean someone touched a tool but forgot to regenerate).
    # The test enforces exit 0; a failure here is a real bug.
    assert proc.returncode == 0, (
        f"Tool manifest is out of sync. Re-run the generator.\n"
        f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
    )


# ---------------------------------------------------------------------------
# Every tool has a generated page file on disk
# ---------------------------------------------------------------------------


def test_every_registered_tool_has_a_page_on_disk() -> None:
    tools = asyncio.run(generate_tool_manifest._collect_tools())
    names = {t["name"] for t in tools}
    pages_dir = REPO_ROOT / "docs" / "site" / "src" / "content" / "docs" / "tools"
    on_disk = {p.name for p in pages_dir.iterdir() if p.is_dir()}
    missing = names - on_disk
    assert not missing, (
        f"Registered tools without a generated page: {missing}. "
        f"Re-run scripts/generate_tool_manifest.py."
    )
    # Each page must be a non-empty markdown file.
    for name in names:
        page = pages_dir / name / "index.md"
        assert page.is_file(), f"missing page file: {page}"
        content = page.read_text(encoding="utf-8")
        assert content.startswith("---\n")  # frontmatter
        assert f"# `{name}`" in content


def test_manifest_json_round_trips() -> None:
    """The machine-readable manifest parses cleanly and matches registration."""
    manifest_path = REPO_ROOT / "docs" / "site" / "src" / "data" / "tool-manifest.json"
    assert manifest_path.is_file()
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert payload["version"] == 1
    assert isinstance(payload["tools"], list)
    assert payload["tool_count"] == len(payload["tools"])
    # confirm_destructive_action must be in the JSON manifest too.
    names = {t["name"] for t in payload["tools"]}
    assert "confirm_destructive_action" in names


# ---------------------------------------------------------------------------
# A targeted negative test: --check fails if something's stale
# ---------------------------------------------------------------------------


def test_check_mode_reports_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the generator at a temp output dir and prove drift is detected.

    Strategy: render to a tmp dir (initially empty), call generate(dry_run=True),
    and verify it reports every file as "changed". This proves the dry-run
    path actually examines the filesystem instead of always returning 0.
    """
    monkeypatch.setattr(generate_tool_manifest, "TOOLS_DIR", tmp_path / "tools")
    monkeypatch.setattr(generate_tool_manifest, "MANIFEST_JSON_PATH", tmp_path / "manifest.json")

    tools = asyncio.run(generate_tool_manifest._collect_tools())
    # First call: nothing on disk → every file is "changed".
    result = generate_tool_manifest.generate(tools, dry_run=True)
    assert result["written"] == 0  # dry_run never writes
    assert len(result["changed"]) >= len(tools) + 1  # one per tool plus index + json

    # Now actually write the files, then dry_run again — should be clean.
    generate_tool_manifest.generate(tools, dry_run=False)
    result2 = generate_tool_manifest.generate(tools, dry_run=True)
    assert result2["changed"] == []
