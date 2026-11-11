"""Tests for ``scripts/check_version_surfaces.sh``.

The script gates two things: every PR (``ci.yml``) and every release tag
(``release.yml``, first step). A wrong answer from it either lets a
half-bumped release through or stops a correct one, so both directions are
pinned here.

The 0.28.0 tag run failed on a correct tree: the changelog test was
``printf "$notes" | grep -q`` under ``pipefail``. ``grep -q`` exits at the
first match, ``printf`` is still writing a long section, takes a broken
pipe, and the pipeline reports failure. It only shows once a section is
long enough to outlast the reader, which 0.28.0's was.

Each test runs the real script against a copy of the release surfaces in a
temp directory, so nothing here depends on the repo's current version.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPT = REPO_ROOT / "scripts" / "check_version_surfaces.sh"

VERSION = "9.8.7"
IMAGE = f"ghcr.io/pete-builds/mcp-unifi:{VERSION}"

BASH = shutil.which("bash")

pytestmark = pytest.mark.skipif(BASH is None, reason="needs bash")


def _tree(root: Path, changelog: str) -> Path:
    """Write every surface the script reads, all agreeing on ``VERSION``."""
    (root / "scripts").mkdir()
    shutil.copy(SCRIPT, root / "scripts" / SCRIPT.name)
    (root / "pyproject.toml").write_text(f'[project]\nversion = "{VERSION}"\n')
    (root / "src" / "mcp_unifi").mkdir(parents=True)
    (root / "src" / "mcp_unifi" / "__init__.py").write_text(f'__version__ = "{VERSION}"\n')
    (root / "manifest.json").write_text(json.dumps({"version": VERSION}))
    (root / "server.json").write_text(
        json.dumps({"version": VERSION, "packages": [{"identifier": IMAGE}]})
    )
    (root / "docker-compose.yml").write_text(f"services:\n  mcp-unifi:\n    image: {IMAGE}\n")
    (root / "charts" / "mcp-unifi").mkdir(parents=True)
    (root / "charts" / "mcp-unifi" / "Chart.yaml").write_text(f'appVersion: "{VERSION}"\n')
    (root / "CHANGELOG.md").write_text(changelog)
    return root


def _run(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    assert BASH is not None
    return subprocess.run(  # noqa: S603  (fixed argv, our own script)
        [BASH, str(root / "scripts" / SCRIPT.name), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _changelog(body: str) -> str:
    head = f"# Changelog\n\n## [Unreleased]\n\n## [{VERSION}] - 2026-01-01\n\n"
    return f"{head}{body}\n## [0.0.1]\n\n- old\n"


def test_agreeing_surfaces_pass(tmp_path: Path) -> None:
    result = _run(_tree(tmp_path, _changelog("### Fixed\n\n- one thing\n")), f"v{VERSION}")
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"non-empty [{VERSION}] section" in result.stdout


def test_a_long_changelog_section_still_passes(tmp_path: Path) -> None:
    """A section far larger than a pipe buffer must not read as "empty"."""
    body = "### Fixed\n\n" + "".join(f"- entry {i} {'x' * 200}\n" for i in range(20_000))
    assert len(body) > 4_000_000
    root = _tree(tmp_path, _changelog(body))
    for _ in range(5):
        result = _run(root, f"v{VERSION}")
        assert result.returncode == 0, result.stdout[-400:] + result.stderr[-400:]
        assert "Broken pipe" not in result.stderr


@pytest.mark.parametrize(
    "changelog",
    [
        pytest.param(_changelog(""), id="empty-section"),
        pytest.param(_changelog("   \n\t\n"), id="whitespace-only-section"),
        pytest.param("# Changelog\n\n## [0.0.1]\n\n- old\n", id="no-section"),
    ],
)
def test_a_missing_or_empty_changelog_section_fails(tmp_path: Path, changelog: str) -> None:
    result = _run(_tree(tmp_path, changelog), f"v{VERSION}")
    assert result.returncode == 1
    assert f"no non-empty '## [{VERSION}]' section" in result.stdout


def test_a_disagreeing_surface_fails_and_is_named(tmp_path: Path) -> None:
    root = _tree(tmp_path, _changelog("### Fixed\n\n- one thing\n"))
    (root / "manifest.json").write_text(json.dumps({"version": "9.8.6"}))
    result = _run(root, f"v{VERSION}")
    assert result.returncode == 1
    assert "manifest.json version is '9.8.6', expected '9.8.7'" in result.stdout


def test_version_defaults_to_pyproject(tmp_path: Path) -> None:
    result = _run(_tree(tmp_path, _changelog("### Fixed\n\n- one thing\n")))
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"matches {VERSION}" in result.stdout
