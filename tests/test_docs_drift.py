"""Prose drift guards for user-facing documentation.

The class of regression these guard against: docs prose that hard-codes a
tool count or a startup command drifts silently from the code, users hit
broken commands or wrong numbers, and nothing in CI notices. That's what
kept the pre-v0.9.0 quick starts broken for seven releases and what left
"62 Network tools" prose in the README long after Network had grown past
90 tools.

Scope: these are static tests over prose. They do not run the server.
Whitelisted files are historical (CHANGELOG entries, phase design docs)
where stale-at-time-of-writing counts are intentional.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_JSON_PATH = REPO_ROOT / "docs" / "site" / "src" / "data" / "tool-manifest.json"

# Files where explicit numbers describe a moment in time (release notes,
# phase design docs). Do NOT add current user-facing docs here.
HISTORICAL_ALLOWLIST: frozenset[Path] = frozenset(
    {
        REPO_ROOT / "CHANGELOG.md",
        REPO_ROOT / "docs" / "v0.10-access-module.md",
    }
)

USER_FACING_GLOBS: tuple[str, ...] = (
    "README.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "manifest.json",
    "server.json",
    "docs/site/src/content/docs/**/*.md",
    "docs/site/src/content/docs/**/*.mdx",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_manifest() -> dict[str, int]:
    """Return per-module tool counts derived from the auto-generated manifest.

    Attribution is by tool-name convention: tools that operate on Access
    concepts (doors, credentials, visitors, badge events, hubs, readers)
    are Access; tools whose names touch Protect-only concepts (camera,
    motion, recording, snapshot, thumbnail) are Protect; everything else
    is Network. Matches the module split ``build_server`` uses.
    """
    manifest = json.loads(MANIFEST_JSON_PATH.read_text(encoding="utf-8"))
    counts = {"network": 0, "protect": 0, "access": 0, "total": manifest["tool_count"]}
    for tool in manifest["tools"]:
        name = tool["name"]
        if any(
            k in name for k in ("door", "credential", "visitor", "access", "badge", "hub", "reader")
        ):
            counts["access"] += 1
        elif any(
            k in name
            for k in ("camera", "motion", "recording", "snapshot", "thumbnail", "smart_detection")
        ):
            counts["protect"] += 1
        else:
            counts["network"] += 1
    return counts


def _user_facing_files() -> list[Path]:
    """All markdown / json prose files a user might read, minus historical docs."""
    files: set[Path] = set()
    for pattern in USER_FACING_GLOBS:
        files.update(REPO_ROOT.glob(pattern))
    return sorted(f for f in files if f.is_file() and f not in HISTORICAL_ALLOWLIST)


# ---------------------------------------------------------------------------
# Test 1: no user-facing prose claims a specific per-module tool count
# ---------------------------------------------------------------------------

# Matches "62 Network tools", "11 Protect tools", "18 Access tools",
# "the 86 tools", "129 total tools", etc. Case-insensitive. Deliberately
# NOT anchored on doc-relative context so any prose slip gets caught.
_MODULE_COUNT_RE = re.compile(
    r"\b(\d{1,4})\s+(Network|Protect|Access)\s+tools?\b",
    re.IGNORECASE,
)
_TOTAL_COUNT_RE = re.compile(
    r"\b(?:the\s+)?(\d{2,4})\s+(?:total\s+)?tools?\b",
    re.IGNORECASE,
)


def test_no_stale_per_module_tool_counts() -> None:
    """User-facing docs must not hard-code per-module tool counts.

    If prose says "62 Network tools" and the manifest actually has 99, users
    trust the wrong number. If prose says "99 Network tools" and Network
    grows to 100 next release, the count is stale until someone remembers
    to bump every location. Neither is acceptable — link to the auto-generated
    Tool Manifest at ``/mcp-unifi/tools/`` instead of quoting a number.
    """
    offenders: list[str] = []
    counts = _load_manifest()
    for path in _user_facing_files():
        text = path.read_text(encoding="utf-8")
        for match in _MODULE_COUNT_RE.finditer(text):
            claimed = int(match.group(1))
            module = match.group(2).lower()
            actual = counts[module]
            snippet = _snippet(text, match.start(), match.end())
            offenders.append(
                f"  {path.relative_to(REPO_ROOT)}: "
                f"prose says {claimed} {module} tools, manifest has {actual}\n"
                f"    → {snippet}"
            )
    if offenders:
        joined = "\n".join(offenders)
        pytest.fail(
            "User-facing docs hard-code per-module tool counts. Replace with a "
            "link to the auto-generated /mcp-unifi/tools/ Tool Manifest.\n\n"
            f"{joined}"
        )


def test_no_stale_total_tool_counts() -> None:
    """User-facing docs must not hard-code a total tool count in prose.

    Same reasoning as per-module counts, plus totals decay even faster —
    every new tool in any module invalidates every "N total tools" claim
    across the site. Two-digit and larger numbers only, because catching
    "9 tools" would trip on legitimate prose about small examples.
    """
    offenders: list[str] = []
    total = _load_manifest()["total"]
    # A generous plausible range for a total tool count. Numbers outside
    # this range are almost certainly talking about something else (memory
    # sizes, timeouts, dates).
    plausible = range(20, 500)
    for path in _user_facing_files():
        text = path.read_text(encoding="utf-8")
        for match in _TOTAL_COUNT_RE.finditer(text):
            claimed = int(match.group(1))
            if claimed not in plausible:
                continue
            # Skip matches that are obviously the "Total tools: N" line the
            # auto-generated manifest index writes.
            if "Total tools" in text[max(0, match.start() - 20) : match.start() + 5]:
                continue
            if claimed == total:
                continue
            snippet = _snippet(text, match.start(), match.end())
            offenders.append(
                f"  {path.relative_to(REPO_ROOT)}: "
                f"prose says {claimed} tools, manifest has {total}\n"
                f"    → {snippet}"
            )
    if offenders:
        joined = "\n".join(offenders)
        pytest.fail(
            "User-facing docs hard-code a total tool count that disagrees with "
            "the manifest. Replace with a link to /mcp-unifi/tools/.\n\n"
            f"{joined}"
        )


# ---------------------------------------------------------------------------
# Test 2: no user-facing prose claims a specific test-suite size
# ---------------------------------------------------------------------------

_TEST_COUNT_RE = re.compile(r"\b(\d{2,4})\+?\s+tests\b", re.IGNORECASE)


def test_no_stale_test_counts() -> None:
    """Prose test counts rot in the same way tool counts do.

    A "619 tests" claim was stale within two months. This test fails on any
    exact "N tests" prose so the maintainer either writes an approximate
    ("~880 tests, run pytest --collect-only for the exact count") or drops
    the number entirely.
    """
    offenders: list[str] = []
    for path in _user_facing_files():
        text = path.read_text(encoding="utf-8")
        for match in _TEST_COUNT_RE.finditer(text):
            # An approximate "~880 tests" is fine — the tilde reads as a
            # promise the number will drift, and we don't want to nag over
            # every rounding-error update.
            start_ctx = text[max(0, match.start() - 3) : match.start()]
            if "~" in start_ctx or "about" in start_ctx.lower():
                continue
            snippet = _snippet(text, match.start(), match.end())
            offenders.append(
                f"  {path.relative_to(REPO_ROOT)}: exact test count claim\n    → {snippet}"
            )
    if offenders:
        joined = "\n".join(offenders)
        pytest.fail(
            "User-facing docs quote an exact test count. Use an approximate "
            "(prefix ~) or drop the number.\n\n"
            f"{joined}"
        )


# ---------------------------------------------------------------------------
# Test 3: every documented `docker run mcp-unifi` command carries a token
# ---------------------------------------------------------------------------

# Match ``docker run ... ghcr.io/pete-builds/mcp-unifi[:tag]`` blocks across
# multiple lines. The HTTP transport refuses to start without auth; a
# docker-run example that omits the token teaches users a command that
# cannot work.
_DOCKER_RUN_RE = re.compile(
    r"docker\s+run(?:[^\n]*\\\s*\n[^\n]*)*[^\n]*"
    r"ghcr\.io/pete-builds/mcp-unifi(?::[^\s]+)?",
)


def test_docker_run_examples_carry_auth_token() -> None:
    """Every ``docker run ...mcp-unifi`` example must supply auth.

    "Supply" means one of:
    * ``MCP_UNIFI_AUTH_TOKENS`` env passed via ``-e`` (or referenced as a
      shell variable), OR
    * ``MCP_UNIFI_AUTH_REQUIRED=false`` (explicit opt-out, only appropriate
      for loopback testing — the docs warn about this).

    Silence on both is the pre-v0.16.1 bug: the container would exit at
    startup with ``ValueError`` and the reader could not tell why.
    """
    offenders: list[str] = []
    for path in _user_facing_files():
        text = path.read_text(encoding="utf-8")
        for match in _DOCKER_RUN_RE.finditer(text):
            block = match.group(0)
            has_token = "MCP_UNIFI_AUTH_TOKENS" in block
            has_optout = "MCP_UNIFI_AUTH_REQUIRED=false" in block
            if has_token or has_optout:
                continue
            snippet = block.replace("\n", " ⏎ ")[:200]
            offenders.append(
                f"  {path.relative_to(REPO_ROOT)}: docker run without auth token\n    → {snippet}"
            )
    if offenders:
        joined = "\n".join(offenders)
        pytest.fail(
            "docker run examples must pass MCP_UNIFI_AUTH_TOKENS (or explicitly "
            "MCP_UNIFI_AUTH_REQUIRED=false with a warning). The container refuses "
            "to start over HTTP without one, so silent examples teach a broken "
            "command.\n\n"
            f"{joined}"
        )


# ---------------------------------------------------------------------------
# Test 4: docs allowlist stays honest
# ---------------------------------------------------------------------------


def test_historical_allowlist_files_exist() -> None:
    """Guard against the allowlist accreting stale entries.

    If a file moves or gets deleted, the whitelist silently protects
    nothing and future prose slips are not caught. Fail loudly instead.
    """
    missing = [p for p in HISTORICAL_ALLOWLIST if not p.exists()]
    if missing:
        joined = "\n".join(f"  {p.relative_to(REPO_ROOT)}" for p in missing)
        pytest.fail(
            "Historical allowlist references files that no longer exist. "
            "Remove the stale entries from HISTORICAL_ALLOWLIST.\n\n"
            f"{joined}"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _snippet(text: str, start: int, end: int, radius: int = 40) -> str:
    """Return a single-line context snippet around a regex match."""
    lo = max(0, start - radius)
    hi = min(len(text), end + radius)
    return text[lo:hi].replace("\n", " ").strip()
