"""Prose drift guards for user-facing documentation.

The class of regression these guard against: docs prose that hard-codes a
tool count or a startup command drifts silently from the code, users hit
broken commands or wrong numbers, and nothing in CI notices. That's what
kept the pre-v0.9.0 quick starts broken for seven releases and what left
"62 Network tools" prose in the README long after Network had grown past
90 tools. The same class later hid three more: install commands that start
the HTTP transport for a stdio client, a ``pip install`` that fetches an
unrelated PyPI package of the same name, and environment variables the code
reads that no page lists.

Scope: these are static tests over prose. They do not run the server.
Whitelisted files are historical (CHANGELOG entries, phase design docs)
where stale-at-time-of-writing counts are intentional.
"""

from __future__ import annotations

import json
import re
import shlex
from pathlib import Path

import pytest

from mcp_unifi.config import Settings

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
# Test 5: a documented stdio launch of the console script sets the transport
# ---------------------------------------------------------------------------
#
# The default transport is streamable-http, which refuses to start without
# MCP_UNIFI_AUTH_TOKENS. Nothing sets MCP_TRANSPORT=stdio for the console
# script, so a uvx / pipx command that omits it exits at startup. The docs said
# for a long time that it was "set automatically"; it is not.

_FENCE_RE = re.compile(r"^([ \t]*)```([\w-]*)[ \t]*$")
_SHELL_LANGS = frozenset({"bash", "sh", "shell", "zsh", "console"})
# A transport is "chosen" when MCP_TRANSPORT is named, or when the command
# plainly configures the HTTP transport (a token or the explicit opt-out).
_TRANSPORT_CHOSEN = ("MCP_TRANSPORT", "MCP_UNIFI_AUTH_TOKENS", "MCP_UNIFI_AUTH_REQUIRED")


def _code_blocks(text: str) -> list[tuple[str, str]]:
    """Return ``(language, body)`` for every fenced block, body dedented by its fence."""
    blocks: list[tuple[str, str]] = []
    current: list[str] | None = None
    indent = ""
    lang = ""
    for line in text.splitlines():
        fence = _FENCE_RE.match(line)
        if fence and current is None:
            current, indent, lang = [], fence.group(1), fence.group(2).lower()
        elif fence and current is not None:
            blocks.append((lang, "\n".join(current)))
            current = None
        elif current is not None:
            current.append(line[len(indent) :] if line.startswith(indent) else line)
    return blocks


def _shell_commands(block: str) -> list[str]:
    """Join backslash-continued lines, so one command is one string."""
    return re.sub(r"\\[ \t]*\n[ \t]*", " ", block).splitlines()


def _launches_console_script(command: str) -> bool:
    """True when a shell command starts the ``mcp-unifi`` console script.

    Two shapes launch it: ``uvx ... mcp-unifi`` (the last token is the script
    name, after ``--from <git url>``) and a bare ``mcp-unifi`` after any
    ``NAME=value`` assignments, which is the pipx form. ``mcp-unifi-replay``,
    ``helm install unifi mcp-unifi/mcp-unifi`` and ``--name mcp-unifi`` are not
    launches.
    """
    try:
        tokens = shlex.split(command, comments=False)
    except ValueError:
        return False
    if "uvx" in tokens:
        return tokens[-1] == "mcp-unifi" and "git+" in command
    while tokens and re.fullmatch(r"[A-Z_][A-Z0-9_]*=\S*", tokens[0]):
        tokens.pop(0)
    return bool(tokens) and tokens[0] == "mcp-unifi"


def _client_config_launches(block: str) -> list[dict[str, object]]:
    """Return the server entries in a JSON client config that run the script."""
    try:
        data = json.loads(block)
    except ValueError:
        return []
    found: list[dict[str, object]] = []
    servers = data.get("mcpServers") if isinstance(data, dict) else None
    for entry in (servers or {}).values():
        if not isinstance(entry, dict):
            continue
        args = entry.get("args") or []
        if entry.get("command") == "mcp-unifi" or (
            entry.get("command") == "uvx" and args and args[-1] == "mcp-unifi"
        ):
            found.append(entry)
    return found


def _stdio_launch_offenders(text: str) -> tuple[int, list[str]]:
    """Count console-script launches in ``text`` and list those with no transport."""
    launches = 0
    offenders: list[str] = []
    for lang, block in _code_blocks(text):
        for command in _shell_commands(block) if lang in _SHELL_LANGS else []:
            if _launches_console_script(command):
                launches += 1
                if not any(name in command for name in _TRANSPORT_CHOSEN):
                    offenders.append(command.strip()[:160])
        for entry in _client_config_launches(block) if lang == "json" else []:
            launches += 1
            env = entry.get("env")
            if not (isinstance(env, dict) and any(name in env for name in _TRANSPORT_CHOSEN)):
                offenders.append(json.dumps(entry)[:160])
    return launches, offenders


def test_console_script_launches_choose_a_transport() -> None:
    """A docs command that launches ``mcp-unifi`` must set ``MCP_TRANSPORT``.

    The console script defaults to Streamable HTTP and exits with "HTTP
    transport requires MCP_UNIFI_AUTH_TOKENS" when no token is set. uvx, pipx
    and the Claude Desktop / Cursor / Claude Code stdio configs all launch it
    as a subprocess, so each one has to say ``MCP_TRANSPORT=stdio`` (a command
    prefix, a ``--env`` flag, or the ``env`` block of a JSON config).
    """
    launches = 0
    offenders: list[str] = []
    for path in _user_facing_files():
        if path.suffix not in {".md", ".mdx"}:
            continue
        found, bad = _stdio_launch_offenders(path.read_text(encoding="utf-8"))
        launches += found
        offenders.extend(f"  {path.relative_to(REPO_ROOT)}: {cmd}" for cmd in bad)
    # A positive control: if the detector stopped recognising the install
    # commands, "no offenders" would mean nothing.
    assert launches >= 8, f"only {launches} console-script launches found; detector is blind"
    if offenders:
        joined = "\n".join(offenders)
        pytest.fail(
            "These docs commands launch the mcp-unifi console script without setting "
            "MCP_TRANSPORT. The default transport is streamable-http, which refuses to "
            "start without MCP_UNIFI_AUTH_TOKENS, so a stdio client gets a dead server. "
            "Add MCP_TRANSPORT=stdio.\n\n"
            f"{joined}"
        )


def test_stdio_launch_detector_flags_a_missing_transport() -> None:
    """Control for the test above: the detector must be able to fail."""
    bad_shell = (
        "```bash\nuvx --from git+https://github.com/pete-builds/mcp-unifi mcp-unifi\n```\n"
        "```bash\npipx install git+https://github.com/pete-builds/mcp-unifi\nmcp-unifi\n```\n"
        "```bash\nclaude mcp add --transport stdio unifi \\\n"
        "  -- uvx --from git+https://github.com/pete-builds/mcp-unifi mcp-unifi\n```\n"
    )
    launches, offenders = _stdio_launch_offenders(bad_shell)
    assert (launches, len(offenders)) == (3, 3)

    bad_json = (
        '```json\n{"mcpServers": {"unifi": {"command": "uvx", '
        '"args": ["--from", "git+https://github.com/pete-builds/mcp-unifi", "mcp-unifi"], '
        '"env": {"STUB_MODE": "true"}}}}\n```\n'
    )
    json_launches, json_offenders = _stdio_launch_offenders(bad_json)
    assert (json_launches, len(json_offenders)) == (1, 1)

    good = (
        "```bash\nMCP_TRANSPORT=stdio uvx --from git+https://github.com/pete-builds/mcp-unifi"
        " mcp-unifi\n```\n"
        "```bash\nclaude mcp add --transport stdio unifi --env MCP_TRANSPORT=stdio \\\n"
        "  -- uvx --from git+https://github.com/pete-builds/mcp-unifi mcp-unifi\n```\n"
        '```json\n{"mcpServers": {"unifi": {"command": "uvx", '
        '"args": ["--from", "git+https://github.com/pete-builds/mcp-unifi", "mcp-unifi"], '
        '"env": {"MCP_TRANSPORT": "stdio"}}}}\n```\n'
        "```bash\nmcp-unifi-replay audit.jsonl\nhelm install unifi mcp-unifi/mcp-unifi\n```\n"
    )
    assert _stdio_launch_offenders(good) == (3, [])


# ---------------------------------------------------------------------------
# Test 6: nothing tells a user to install the bare name "mcp-unifi" from PyPI
# ---------------------------------------------------------------------------
#
# This project is not published on PyPI. The PyPI project named "mcp-unifi" is
# an unrelated package by another author, so ``pip install mcp-unifi`` runs a
# stranger's code. Every install command must name the git URL.

_BARE_PYPI_INSTALL_RE = re.compile(
    r"""(?:\b(?:pip3?|pipx|uv\s+pip|uv\s+tool)\s+install\s+(?:-\S+\s+)*
          |\buvx\s+(?:-\S+\s+)*)
        ['"]?mcp-unifi(?:\[[^\]]*\])?['"]?(?=[\s`.,;:)]|$)(?!\s*@)""",
    re.VERBOSE,
)


def test_no_install_command_fetches_the_pypi_package_of_the_same_name() -> None:
    """``pip install mcp-unifi`` and ``uvx mcp-unifi`` install someone else's code."""
    offenders: list[str] = []
    candidates = set(_user_facing_files())
    candidates.update((REPO_ROOT / "docs").glob("*.md"))
    # Source files carry user-facing install hints too (the tracing warning).
    # Only the pip-family commands are checked there: a docstring may mention
    # the console script by name.
    source = set((REPO_ROOT / "src" / "mcp_unifi").rglob("*.py"))
    for path in sorted(candidates | source):
        if path in HISTORICAL_ALLOWLIST or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for match in _BARE_PYPI_INSTALL_RE.finditer(text):
            if path in source and not match.group(0).lstrip().startswith(("pip", "uv pip")):
                continue
            line_start = text.rfind("\n", 0, match.start()) + 1
            line = text[line_start : text.find("\n", match.end())]
            offenders.append(f"  {path.relative_to(REPO_ROOT)}: {line.strip()[:160]}")
    if offenders:
        joined = "\n".join(offenders)
        pytest.fail(
            "These install commands name the bare package 'mcp-unifi', which on PyPI is "
            "an unrelated project. Install from git instead, for example "
            "'mcp-unifi[extra] @ git+https://github.com/pete-builds/mcp-unifi'.\n\n"
            f"{joined}"
        )


def test_pypi_install_detector_flags_the_bare_name() -> None:
    """Control for the test above: the pattern must match the bad forms only."""
    bad = [
        "pip install mcp-unifi",
        "pip install 'mcp-unifi[otel]'",
        "pip install mcp-unifi[otel]",
        "pipx install mcp-unifi",
        "uvx mcp-unifi",
        "uv pip install -U mcp-unifi",
        "``pip install mcp-unifi[otel]``, which",
        "Install them with: pip install 'mcp-unifi[otel]'. The server",
    ]
    for text in bad:
        assert _BARE_PYPI_INSTALL_RE.search(text), text
    good = [
        "pip install 'mcp-unifi[otel] @ git+https://github.com/pete-builds/mcp-unifi'",
        "pipx install git+https://github.com/pete-builds/mcp-unifi",
        "uvx --from git+https://github.com/pete-builds/mcp-unifi mcp-unifi",
        "pip install -e .",
        "helm install unifi mcp-unifi/mcp-unifi",
    ]
    for text in good:
        assert not _BARE_PYPI_INSTALL_RE.search(text), text


# ---------------------------------------------------------------------------
# Test 7: every environment variable the server reads is on the config page
# ---------------------------------------------------------------------------

CONFIG_REFERENCE = REPO_ROOT / "docs" / "site" / "src" / "content" / "docs" / "reference"
CONFIG_REFERENCE = CONFIG_REFERENCE / "configuration.md"

# ``os.environ.get("X")`` / ``os.getenv("X")`` with a literal name, and the
# ``ENV_FOO = "X"`` constants the audit and telemetry modules read through.
_ENV_LITERAL_RE = re.compile(r"""os\.(?:environ\.get|getenv)\(\s*["']([A-Z][A-Z0-9_]+)["']""")
_ENV_CONSTANT_RE = re.compile(
    r"""^ENV_[A-Z_]+(?:\s*:\s*[\w\[\]]+)?\s*=\s*["']([A-Z][A-Z0-9_]+)["']""", re.M
)


def _env_vars_the_server_reads() -> set[str]:
    """Environment variable names read by ``Settings`` plus the direct readers."""
    names: set[str] = set()
    for field_name, field in Settings.model_fields.items():
        if field_name == "controllers":  # built from the others, not read from the env
            continue
        alias = field.validation_alias
        choices = getattr(alias, "choices", None)
        if choices:
            names.update(str(c) for c in choices if str(c).isupper())
        else:
            names.add(field_name.upper())
    for path in (REPO_ROOT / "src" / "mcp_unifi").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        names.update(_ENV_LITERAL_RE.findall(text))
        names.update(_ENV_CONSTANT_RE.findall(text))
    return names


def _undocumented(names: set[str], page: str) -> list[str]:
    return sorted(n for n in names if f"`{n}`" not in page)


def test_every_env_var_the_server_reads_is_on_the_configuration_page() -> None:
    """A variable the code reads but ``reference/configuration.md`` omits is invisible.

    The page had no ``UNIFI_OS_USERNAME`` and no ``MCP_UNIFI_OTEL_*`` for as long
    as they existed. The names come from the ``Settings`` model and from the
    modules that read ``os.environ`` directly, so adding a variable to the code
    without documenting it fails here.
    """
    names = _env_vars_the_server_reads()
    # Sanity: the enumeration must see the three groups it exists to cover.
    for expected in ("UNIFI_OS_USERNAME", "MCP_UNIFI_OTEL_ENABLED", "MCP_UNIFI_AUDIT_SINK"):
        assert expected in names, f"{expected} not enumerated; the scan is broken"
    missing = _undocumented(names, CONFIG_REFERENCE.read_text(encoding="utf-8"))
    if missing:
        joined = "\n".join(f"  {n}" for n in missing)
        pytest.fail(
            "The server reads these environment variables but "
            "docs/site/src/content/docs/reference/configuration.md does not list "
            f"them (as `NAME`):\n\n{joined}"
        )


def test_env_var_coverage_check_can_fail() -> None:
    """Control for the test above: dropping a variable from the page is caught."""
    page = CONFIG_REFERENCE.read_text(encoding="utf-8")
    names = _env_vars_the_server_reads()
    assert _undocumented(names, page) == []
    assert _undocumented(names, page.replace("`UNIFI_OS_USERNAME`", "")) == ["UNIFI_OS_USERNAME"]


# ---------------------------------------------------------------------------
# Test 8: a tool-call example passes arguments the tool actually takes
# ---------------------------------------------------------------------------
#
# The Network reference showed ``audit_network_drift`` being called with
# ``spec_path``. The tool takes ``spec_yaml`` and rejects anything else, so the
# one worked example for drift auditing could not run. Two example shapes are
# checked against the generated manifest: ``tool(arg=value, ...)`` on one line,
# and ``{ "tool": "...", "args": { ... } }`` on one line.

_CALL_EXAMPLE_RE = re.compile(r"\b([a-z][a-z0-9_]+)\(([^()]*)\)")
_CALL_KWARG_RE = re.compile(r"(?:^|,)\s*([a-z_][a-z0-9_]*)\s*=")
_JSON_EXAMPLE_RE = re.compile(r'"tool":\s*"([a-z0-9_]+)",\s*"args":\s*(\{.*\})\s*\}')


def _tool_parameters() -> dict[str, set[str]]:
    manifest = json.loads(MANIFEST_JSON_PATH.read_text(encoding="utf-8"))
    return {
        tool["name"]: set(tool["input_schema"].get("properties", {})) for tool in manifest["tools"]
    }


def _unknown_example_arguments(text: str, parameters: dict[str, set[str]]) -> tuple[int, list[str]]:
    """Return (examples seen, offences) for the tool-call examples in ``text``."""
    seen = 0
    offences: list[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for name, arguments in _CALL_EXAMPLE_RE.findall(line):
            if name not in parameters:
                continue
            seen += 1
            offences.extend(
                f"line {lineno}: {name}() takes no argument '{kwarg}'"
                for kwarg in _CALL_KWARG_RE.findall(arguments)
                if kwarg not in parameters[name]
            )
        match = _JSON_EXAMPLE_RE.search(line)
        if match and match.group(1) in parameters:
            seen += 1
            name = match.group(1)
            try:
                supplied = json.loads(match.group(2))
            except ValueError:
                offences.append(f"line {lineno}: the args of the {name} example are not JSON")
                continue
            offences.extend(
                f"line {lineno}: {name}() takes no argument '{key}'"
                for key in supplied
                if key not in parameters[name]
            )
    return seen, offences


def test_tool_call_examples_use_arguments_the_tool_takes() -> None:
    parameters = _tool_parameters()
    total = 0
    offenders: list[str] = []
    for path in _user_facing_files():
        if path.suffix not in {".md", ".mdx"}:
            continue
        seen, offences = _unknown_example_arguments(path.read_text(encoding="utf-8"), parameters)
        total += seen
        offenders.extend(f"  {path.relative_to(REPO_ROOT)}: {o}" for o in offences)
    assert total > 100, f"only {total} tool-call examples found; the scan is broken"
    if offenders:
        joined = "\n".join(offenders)
        pytest.fail(
            "These examples pass an argument the tool does not take. A caller that "
            "copies one gets a validation error. For a page under docs/.../tools/, "
            "fix the tool's docstring and regenerate the manifest.\n\n"
            f"{joined}"
        )


def test_tool_call_example_check_can_fail() -> None:
    """Control for the test above, on the example that was wrong."""
    parameters = _tool_parameters()
    bad_json = '{ "tool": "audit_network_drift", "args": { "spec_path": "./network-spec.yml" } }'
    assert _unknown_example_arguments(bad_json, parameters) == (
        1,
        ["line 1: audit_network_drift() takes no argument 'spec_path'"],
    )
    bad_call = 'Example: audit_network_drift(spec_path="./spec.yml", controller="default")'
    assert _unknown_example_arguments(bad_call, parameters) == (
        1,
        ["line 1: audit_network_drift() takes no argument 'spec_path'"],
    )
    good = (
        '{ "tool": "audit_network_drift", "args": { "spec_yaml": "networks: []" } }\n'
        'Example: audit_network_drift(spec_yaml="networks: []", controller="default")\n'
        "an unrelated call such as print(x=1) is ignored\n"
    )
    assert _unknown_example_arguments(good, parameters) == (2, [])


# ---------------------------------------------------------------------------
# Test 9: the README opens with a working, pinned "Install in Claude" config
# ---------------------------------------------------------------------------
#
# A newcomer asked how to install this into Claude (Discussion #225). The
# README opened with Docker, and the stdio configs in the docs left
# STUB_MODE at its default, which serves made-up devices even when a gateway
# is configured. The first thing on the page is now a config that reads the
# person's own network and cannot change it, pinned to the current release.

_PINNED_GIT_URL_RE = re.compile(r"git\+https://github\.com/pete-builds/mcp-unifi@v(\d+\.\d+\.\d+)")


def _pyproject_version() -> str:
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"', text, re.M)
    assert match, "pyproject.toml has no version line"
    return match.group(1)


def _stale_pins(text: str, version: str) -> tuple[int, list[str]]:
    """Count ``mcp-unifi@vX.Y.Z`` pins in ``text`` and list those not on ``version``."""
    pins = _PINNED_GIT_URL_RE.findall(text)
    return len(pins), [f"v{pin}" for pin in pins if pin != version]


def test_readme_opens_with_install_in_claude() -> None:
    text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    headings = re.findall(r"^## (.+)$", text, re.M)
    assert headings and headings[0] == "Install in Claude", headings[:3]

    section = text.split("## Install in Claude", 1)[1].split("\n## ", 1)[0]
    configs = [
        entry
        for lang, block in _code_blocks(section)
        if lang == "json"
        for entry in _client_config_launches(block)
    ]
    assert len(configs) == 1, "the section should carry exactly one claude_desktop_config block"
    env = configs[0]["env"]
    assert isinstance(env, dict)
    assert env.get("MCP_TRANSPORT") == "stdio"
    assert env.get("STUB_MODE") == "false"
    assert env.get("MCP_UNIFI_READONLY") == "true"
    args = configs[0]["args"]
    assert isinstance(args, list)
    assert any(_PINNED_GIT_URL_RE.fullmatch(str(a)) for a in args), args
    # Both config file locations and the Claude Code form are in the section.
    assert "Library/Application Support/Claude/claude_desktop_config.json" in section
    assert "%APPDATA%\\Claude\\claude_desktop_config.json" in section
    assert "claude mcp add" in section


def test_pinned_install_urls_name_the_current_release() -> None:
    """A pinned install command must pin the version this tree releases.

    The README pins the uvx install to a release tag so a newcomer gets a
    tested build, not whatever main holds. That pin is a version surface: the
    release PR that bumps pyproject.toml bumps it too, or this fails.
    """
    version = _pyproject_version()
    total = 0
    offenders: list[str] = []
    for path in _user_facing_files():
        found, stale = _stale_pins(path.read_text(encoding="utf-8"), version)
        total += found
        offenders.extend(f"  {path.relative_to(REPO_ROOT)}: {pin}" for pin in stale)
    assert total >= 2, f"only {total} pinned install URL(s) found; detector is blind"
    if offenders:
        joined = "\n".join(offenders)
        pytest.fail(
            f"These install commands pin a release other than {version} (pyproject.toml). "
            "Bump them with the other version surfaces.\n\n"
            f"{joined}"
        )


def test_stale_pin_detector_can_fail() -> None:
    """Control for the test above."""
    text = (
        "uvx --from git+https://github.com/pete-builds/mcp-unifi@v0.27.0 mcp-unifi\n"
        '"git+https://github.com/pete-builds/mcp-unifi@v1.2.3",\n'
        "uvx --from git+https://github.com/pete-builds/mcp-unifi@<tag> mcp-unifi\n"
    )
    assert _stale_pins(text, "1.2.3") == (2, ["v0.27.0"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _snippet(text: str, start: int, end: int, radius: int = 40) -> str:
    """Return a single-line context snippet around a regex match."""
    lo = max(0, start - radius)
    hi = min(len(text), end + radius)
    return text[lo:hi].replace("\n", " ").strip()
