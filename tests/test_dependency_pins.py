"""Every exact pin in ``pyproject.toml`` agrees with the lock it ships with.

THE GAP THIS CLOSES
-------------------
The repo's convention is that ``pyproject.toml`` pins mirror the hash-locked
inputs: each ``name==X`` under ``[project].dependencies`` also appears as
``name==X`` in ``requirements.in``, and each one under the ``dev`` extra in
``requirements-dev.in``. The CI "Lockfile drift check" then holds every
``.in`` pin equal to its ``.lock``. Nothing compared ``pyproject.toml`` with
either file.

``pyyaml`` slipped through that gap. ``src/mcp_unifi/config.py`` imports it
directly and ``pyproject.toml`` pinned ``pyyaml==6.0.3``, but it was never
listed in ``requirements.in``, so the lock carried it only as a transitive
dependency (``via fastmcp-slim``). The lockfile recompile in #255 moved it
to 6.0.4 with every check green, leaving the package metadata asking for
6.0.3 while the image (built from ``requirements.lock``) shipped 6.0.4, and
``pip`` reporting the conflict on every install from the lock.

Ranged requirements (the ``otel`` extra) are deliberately not locked; see the
comment above them in ``pyproject.toml``. Only ``==`` pins are checked.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

#: pyproject section -> (the .in file that must repeat its pins, its lock).
PIN_SOURCES = {
    "dependencies": ("requirements.in", "requirements.lock"),
    "dev": ("requirements-dev.in", "requirements-dev.lock"),
}

_EXACT = re.compile(r"^\s*([A-Za-z0-9._-]+)(?:\[[^\]]+\])?\s*==\s*([^\s;#]+)")


def _norm(name: str) -> str:
    return re.sub(r"[._-]+", "-", name).lower()


def _pins(lines: list[str]) -> dict[str, str]:
    """``name -> version`` for every exact ``==`` pin among ``lines``."""
    found: dict[str, str] = {}
    for line in lines:
        match = _EXACT.match(line.split("#", 1)[0])
        if match:
            found[_norm(match.group(1))] = match.group(2)
    return found


def _pyproject_pins(section: str, root: Path = REPO_ROOT) -> dict[str, str]:
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    entries = (
        project["dependencies"]
        if section == "dependencies"
        else project["optional-dependencies"][section]
    )
    return _pins(list(entries))


def _file_pins(name: str, root: Path = REPO_ROOT) -> dict[str, str]:
    return _pins((root / name).read_text(encoding="utf-8").splitlines())


def mismatches(root: Path = REPO_ROOT) -> list[str]:
    """Every way ``pyproject.toml``'s exact pins disagree with the locked inputs."""
    problems: list[str] = []
    for section, (in_file, lock_file) in PIN_SOURCES.items():
        declared = _pyproject_pins(section, root)
        inputs = _file_pins(in_file, root)
        locked = _file_pins(lock_file, root)
        for name, version in sorted(declared.items()):
            if inputs.get(name) != version:
                problems.append(
                    f"pyproject [{section}] pins {name}=={version} but {in_file} "
                    f"has {name}=={inputs[name]}"
                    if name in inputs
                    else f"pyproject [{section}] pins {name}=={version} but {in_file} "
                    f"does not list it, so {lock_file} resolves it freely"
                )
            if locked.get(name) != version:
                problems.append(
                    f"pyproject [{section}] pins {name}=={version} but {lock_file} "
                    f"locks {name}=={locked.get(name, '<absent>')}"
                )
    return problems


def test_pyproject_pins_match_the_locked_inputs() -> None:
    problems = mismatches()
    assert not problems, (
        "pyproject.toml and the lockfiles disagree. Pin the package in the .in "
        "file too, set both to the locked version, and recompile with the "
        "command in the lock header:\n  " + "\n  ".join(problems)
    )


def test_the_check_reads_every_pin_it_should() -> None:
    """Guard against the check passing because it parsed nothing."""
    for section in PIN_SOURCES:
        assert _pyproject_pins(section), f"no exact pins parsed from pyproject [{section}]"
    assert "pyyaml" in _pyproject_pins("dependencies")
    assert "fastmcp" in _file_pins("requirements.lock")


@pytest.mark.parametrize(
    ("in_text", "lock_version", "expected"),
    [
        ("fastmcp==1.0\n", "1.0", None),
        ("", "1.0", "does not list it"),
        ("fastmcp==0.9\n", "1.0", "requirements.in has fastmcp==0.9"),
        ("fastmcp==1.0\n", "1.1", "requirements.lock locks fastmcp==1.1"),
    ],
)
def test_mismatches_reports_each_kind_of_drift(
    tmp_path: Path, in_text: str, lock_version: str, expected: str | None
) -> None:
    """The control: each kind of disagreement is caught on a synthetic tree."""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\ndependencies = ["fastmcp==1.0", "otel-thing>=1,<2"]\n'
        '[project.optional-dependencies]\ndev = ["pytest==9.0"]\n',
        encoding="utf-8",
    )
    (tmp_path / "requirements.in").write_text(in_text, encoding="utf-8")
    (tmp_path / "requirements.lock").write_text(
        f"fastmcp=={lock_version} \\\n    --hash=sha256:00\n", encoding="utf-8"
    )
    (tmp_path / "requirements-dev.in").write_text("-r requirements.in\npytest==9.0\n")
    (tmp_path / "requirements-dev.lock").write_text("pytest==9.0 \\\n")
    problems = mismatches(tmp_path)
    if expected is None:
        assert problems == []
    else:
        assert any(expected in p for p in problems), problems
