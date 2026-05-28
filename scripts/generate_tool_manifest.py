"""Generate per-tool reference docs for the Astro docs site.

This script introspects the live FastMCP registration (stub mode, with
Network, Protect, and Access modules enabled) and writes one markdown
file per registered tool under ``docs/site/src/content/docs/tools/``. It
also writes a manifest index at ``docs/site/src/content/docs/tools/index.md``
and a single machine-readable ``manifest.json`` next to the generator
output so external consumers (LLM tool selection, third-party tooling)
can read the full surface without parsing markdown.

Design notes
------------
* **Deterministic output.** Tools are sorted by name; JSON is dumped with
  ``sort_keys=True``; line endings normalised to ``\\n``. A re-run on
  the same source produces byte-identical files. The pre-commit hook
  relies on this.
* **Source of truth is the FastMCP registration**, not the on-disk
  docstrings. Same approach the existing ``scripts/dump_tool_schemas.py``
  uses for the Step 3 schema diff. If a tool's signature drifts, the
  manifest drifts with it on the next run.
* **Docstring extraction.** Descriptions come from FastMCP's
  ``tool.description`` (which already pulls the docstring). The script
  also extracts the single-line ``Example:`` block — every tool in this
  codebase carries one, and it's the most useful field for LLM tool
  selection. Parameter docstrings come from the JSON schema's
  ``properties[*].description`` (FastMCP populates these from the
  Args-section of the docstring via its standard parser).
* **Output format.** Each tool's page is a Starlight-compatible
  markdown file with frontmatter (title, description, draft=false). The
  body has a Side Effects / Example / Parameters layout.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

# Stub mode = deterministic registration. All modules enabled = full surface.
os.environ.setdefault("STUB_MODE", "true")
os.environ.setdefault("MCP_UNIFI_MODULES_ENABLED", "network,protect,access")

# Imports must come *after* env var setup so the modules see the right state
# at registration time.
# (ruff E402 silenced via noqa; this is intentional.)
from mcp_unifi.config import Settings
from mcp_unifi.server import build_server

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_ROOT = REPO_ROOT / "docs" / "site" / "src" / "content" / "docs"
TOOLS_DIR = DOCS_ROOT / "tools"
# Machine-readable manifest lives next to the markdown pages (inside the
# Astro public/ tree would be cleaner, but Starlight rejects non-content
# files under content/docs/. Keep it in docs/site/ alongside the rendered
# pages so a future ``scripts/deploy-docs.sh`` can copy it out as a
# top-level public asset if needed.)
MANIFEST_JSON_PATH = (
    REPO_ROOT / "docs" / "site" / "src" / "data" / "tool-manifest.json"
)

# Crude module attribution. The dispatcher imports tools by package, so a
# tool's module is one of two values. We classify by name prefix only when
# the schema doesn't carry the info (which it doesn't, at present).
NETWORK_TOOL_NAMES: frozenset[str] = frozenset()  # populated at runtime
PROTECT_TOOL_NAMES: frozenset[str] = frozenset()  # populated at runtime


# ---------------------------------------------------------------------------
# Introspection
# ---------------------------------------------------------------------------


def _serialise_schema(raw_schema: Any) -> dict[str, Any] | None:
    """Coerce a FastMCP input schema into a plain dict.

    Mirrors :func:`scripts.dump_tool_schemas._serialise_tool` so both
    generators agree on the schema shape they ingest.
    """
    if raw_schema is None:
        return None
    if hasattr(raw_schema, "model_dump"):
        result = raw_schema.model_dump()
        return result if isinstance(result, dict) else None
    if isinstance(raw_schema, dict):
        return raw_schema
    parsed = json.loads(json.dumps(raw_schema, default=str))
    return parsed if isinstance(parsed, dict) else None


def _serialise_tool(tool: Any) -> dict[str, Any]:
    raw_schema = getattr(tool, "parameters", None) or getattr(tool, "input_schema", None)
    name: str = getattr(tool, "name", None) or getattr(tool, "key", "<unknown>")
    description: str = (getattr(tool, "description", "") or "").strip()
    schema = _serialise_schema(raw_schema)
    return {
        "name": name,
        "description": description,
        "input_schema": schema,
    }


async def _collect_tools() -> list[dict[str, Any]]:
    # stdio transport bypasses the HTTP auth gate; this generator only
    # introspects tool metadata and never serves traffic.
    settings = Settings(stub_mode=True, log_format="text", mcp_transport="stdio")
    server = build_server(settings)
    tools_obj = await server.list_tools()
    tools_iter = tools_obj.values() if isinstance(tools_obj, dict) else tools_obj
    out = [_serialise_tool(t) for t in tools_iter]
    out.sort(key=lambda t: t["name"])
    return out


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


EXAMPLE_RE = re.compile(r"^\s*Example:\s*(.+?)$", re.MULTILINE)


def _extract_example(description: str) -> str | None:
    """Pull the first ``Example: <call>`` line out of the description."""
    match = EXAMPLE_RE.search(description)
    if not match:
        return None
    return match.group(1).strip()


def _extract_summary(description: str) -> str:
    """Return the first non-empty paragraph of the description.

    Used as the frontmatter ``description`` and the H1 lede. Strips any
    embedded ``Example:`` block so the summary stays clean.
    """
    cleaned = EXAMPLE_RE.sub("", description).strip()
    for paragraph in cleaned.split("\n\n"):
        first = paragraph.strip()
        if first:
            # First line of the paragraph is the summary line.
            return first.split("\n", 1)[0].strip()
    return ""


def _format_default(value: Any) -> str:
    """Render a JSON schema default value the way a caller would type it."""
    if isinstance(value, str):
        return f'"{value}"'
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    return json.dumps(value, sort_keys=True)


def _format_type(prop: dict[str, Any]) -> str:
    """Best-effort JSON-schema-to-python-ish type label."""
    if "type" in prop:
        t = prop["type"]
        if isinstance(t, list):
            return " | ".join(str(x) for x in t)
        return str(t)
    if "anyOf" in prop:
        parts = [_format_type(sub) for sub in prop["anyOf"]]
        return " | ".join(parts)
    if "$ref" in prop:
        return str(prop["$ref"]).rsplit("/", 1)[-1]
    return "any"


def _render_parameters_table(schema: dict[str, Any] | None) -> str:
    """Render the input schema as a markdown table.

    Returns an empty string when there are no parameters. The table layout
    is: ``Name | Type | Required | Default | Description``.
    """
    if not schema:
        return ""
    properties = schema.get("properties") or {}
    if not properties:
        return ""
    required: set[str] = set(schema.get("required") or [])
    lines = [
        "| Parameter | Type | Required | Default | Description |",
        "|---|---|---|---|---|",
    ]
    # Preserve the schema's own ordering (matches the function signature)
    # so callers reading the docs see params in the same order as the code.
    for name, prop in properties.items():
        if not isinstance(prop, dict):
            continue
        type_label = _format_type(prop)
        req = "yes" if name in required else "no"
        default = (
            _format_default(prop["default"]) if "default" in prop else "—"
        )
        desc = (prop.get("description") or "").strip().replace("\n", " ")
        # Pipe characters in descriptions would break the table; escape them.
        desc = desc.replace("|", r"\|")
        lines.append(f"| `{name}` | `{type_label}` | {req} | {default} | {desc} |")
    return "\n".join(lines)


def _strip_args_section(description: str) -> str:
    """Drop the Args: section from the docstring body.

    The parameters table renders the same info more compactly; keeping
    both would duplicate every param description.
    """
    # The docstrings in this repo end with an Args: block. Cut from the
    # first ``Args:`` (at the start of a line) to the end.
    match = re.search(r"^\s*Args:\s*$", description, re.MULTILINE)
    if not match:
        return description.strip()
    return description[: match.start()].rstrip()


def _render_tool_page(tool: dict[str, Any]) -> str:
    name = tool["name"]
    description = tool["description"]
    summary = _extract_summary(description)
    example = _extract_example(description)
    body_description = EXAMPLE_RE.sub("", description)
    body_description = _strip_args_section(body_description).strip()

    # Frontmatter description: Starlight quotes are picky. Strip any double
    # quotes and collapse newlines to keep YAML parsers happy.
    fm_description = summary.replace('"', "'").replace("\n", " ")
    if not fm_description:
        fm_description = f"{name} tool reference."

    parts: list[str] = []
    parts.append("---")
    parts.append(f"title: {name}")
    parts.append(f'description: "{fm_description}"')
    parts.append("draft: false")
    parts.append("---")
    parts.append("")
    parts.append(f"# `{name}`")
    parts.append("")
    if body_description:
        parts.append(body_description)
        parts.append("")
    if example:
        parts.append("## Example")
        parts.append("")
        parts.append("```python")
        parts.append(example)
        parts.append("```")
        parts.append("")
    params_table = _render_parameters_table(tool.get("input_schema"))
    if params_table:
        parts.append("## Parameters")
        parts.append("")
        parts.append(params_table)
        parts.append("")
    # Trailing comment so anyone hand-editing knows the file is generated.
    parts.append("<!-- Generated by scripts/generate_tool_manifest.py. Do not edit by hand. -->")
    parts.append("")
    return "\n".join(parts)


def _render_index(tools: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    parts.append("---")
    parts.append("title: Tool Manifest")
    parts.append(
        'description: "Auto-generated index of every MCP tool registered by mcp-unifi."'
    )
    parts.append("draft: false")
    parts.append("---")
    parts.append("")
    parts.append(
        "Auto-generated by `scripts/generate_tool_manifest.py`. One row per "
        "registered tool, sorted alphabetically. Re-run the generator after "
        "changing any tool's registration; the pre-commit hook enforces this."
    )
    parts.append("")
    parts.append(f"**Total tools:** {len(tools)}")
    parts.append("")
    parts.append("| Tool | Summary |")
    parts.append("|---|---|")
    for tool in tools:
        summary = _extract_summary(tool["description"]).replace("|", r"\|")
        parts.append(f"| [`{tool['name']}`](./{tool['name']}/) | {summary} |")
    parts.append("")
    parts.append("<!-- Generated by scripts/generate_tool_manifest.py. Do not edit by hand. -->")
    parts.append("")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Write outputs
# ---------------------------------------------------------------------------


def _write_if_changed(path: Path, content: str) -> bool:
    """Write ``content`` to ``path`` only if it differs from existing.

    Returns True when the file was created or modified, False when the
    content was already correct. The ``--check`` mode of the CLI uses this
    to decide whether to fail.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        existing = path.read_text(encoding="utf-8")
        if existing == content:
            return False
    path.write_text(content, encoding="utf-8")
    return True


def generate(tools: list[dict[str, Any]], *, dry_run: bool = False) -> dict[str, Any]:
    """Render and write every output file.

    Args:
        tools: Sorted list of serialised tool dicts (output of
            :func:`_collect_tools`).
        dry_run: When True, compute what would change without writing.

    Returns:
        Dict with ``changed`` (list of relative paths that differ) and
        ``written`` (count of files actually written, 0 when dry_run).
    """
    changed: list[str] = []
    written = 0

    # Per-tool pages.
    expected_files: set[Path] = set()
    for tool in tools:
        name = tool["name"]
        page_path = TOOLS_DIR / name / "index.md"
        expected_files.add(page_path)
        content = _render_tool_page(tool)
        if dry_run:
            if not page_path.exists() or page_path.read_text(encoding="utf-8") != content:
                changed.append(_rel(page_path))
        else:
            if _write_if_changed(page_path, content):
                changed.append(_rel(page_path))
                written += 1

    # Index page.
    index_path = TOOLS_DIR / "index.md"
    expected_files.add(index_path)
    index_content = _render_index(tools)
    if dry_run:
        if not index_path.exists() or index_path.read_text(encoding="utf-8") != index_content:
            changed.append(_rel(index_path))
    else:
        if _write_if_changed(index_path, index_content):
            changed.append(_rel(index_path))
            written += 1

    # Machine-readable manifest, alongside the script (kept out of docs/site
    # so the Astro build doesn't try to render it).
    manifest_payload = {
        "version": 1,
        "tool_count": len(tools),
        "tools": tools,
    }
    manifest_text = json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n"
    if dry_run:
        if (
            not MANIFEST_JSON_PATH.exists()
            or MANIFEST_JSON_PATH.read_text(encoding="utf-8") != manifest_text
        ):
            changed.append(_rel(MANIFEST_JSON_PATH))
    else:
        if _write_if_changed(MANIFEST_JSON_PATH, manifest_text):
            changed.append(_rel(MANIFEST_JSON_PATH))
            written += 1

    # Stale-file cleanup: if a previously-generated per-tool directory now
    # has no corresponding registered tool, drop it. Only sweep our own
    # output dir (TOOLS_DIR).
    if TOOLS_DIR.exists():
        for child in TOOLS_DIR.iterdir():
            if not child.is_dir():
                continue
            page = child / "index.md"
            if page not in expected_files:
                changed.append(_rel(page) + " (stale)")
                if not dry_run:
                    # Only delete files we own; never recurse beyond index.md.
                    if page.exists():
                        page.unlink()
                    # Directory may not be empty (other files); ignore that.
                    with contextlib.suppress(OSError):
                        child.rmdir()

    return {"changed": changed, "written": written}


def _rel(path: Path) -> str:
    """Render ``path`` relative to ``REPO_ROOT`` when possible.

    Tests point ``TOOLS_DIR`` and ``MANIFEST_JSON_PATH`` at ``tmp_path``,
    which is outside the repo. Fall back to the absolute path in that case
    instead of letting ``relative_to`` raise.
    """
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "Fail (exit 1) if the generated output would differ from what's "
            "checked in. Used by the pre-commit hook to enforce sync."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_arg_parser().parse_args(argv)
    tools = asyncio.run(_collect_tools())
    result = generate(tools, dry_run=args.check)
    if args.check:
        if result["changed"]:
            sys.stderr.write(
                "Tool manifest is out of sync. Re-run "
                "`python scripts/generate_tool_manifest.py` and commit:\n"
            )
            for path in result["changed"]:
                sys.stderr.write(f"  - {path}\n")
            return 1
        sys.stdout.write("Tool manifest is in sync.\n")
        return 0
    sys.stdout.write(
        f"Generated {len(tools)} tool pages. "
        f"{result['written']} file(s) written.\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
