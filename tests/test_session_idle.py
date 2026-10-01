"""Abandoned streamable-http sessions must be reaped.

FastMCP 4 hands the SDK's session manager ``session_idle_timeout=None`` unless
``fastmcp.settings.http_session_idle_timeout`` is set, which overrides the
SDK's own 1800s default. An abandoned session (~57 KB, measured on a sibling
server) then lives for the life of the process.

Each probe runs the real ``server.main()`` in a fresh interpreter with
uvicorn's ``Server.serve`` replaced by a recorder, enters the lifespan of the
exact app uvicorn would have served, and reads the value off the LIVE session
manager rather than off a setting or a constant. The probe runs the default
streamable-http transport in stub mode, once open and once with a bearer token
configured, since auth wraps the MCP endpoint in another layer.

The override control proves an operator's ``FASTMCP_HTTP_SESSION_IDLE_TIMEOUT``
reaches the manager, so the 1800 is read from the running app.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

_PROBE = r"""
import asyncio, json
import uvicorn

captured = {}


async def _record(self, sockets=None):
    captured["app"] = self.config.app
    self.started = True  # uvicorn.run() exits with a startup failure otherwise


uvicorn.Server.serve = _record

from mcp_unifi.server import main as server_main

server_main()
app = captured["app"]


async def main():
    async with app.router.lifespan_context(app):
        for route in app.routes:
            endpoint = getattr(route, "endpoint", None)
            for candidate in (endpoint, getattr(endpoint, "app", None)):
                manager = getattr(candidate, "session_manager", None)
                if manager is not None:
                    print("IDLE " + json.dumps(manager.session_idle_timeout))
                    return
    print("IDLE " + json.dumps("no session manager found"))


asyncio.run(main())
"""


def _live_idle_timeout(tmp_path: Path, **extra_env: str) -> object:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("MCP_", "FASTMCP_"))}
    env = {k: v for k, v in env.items() if not k.startswith(("UNIFI_", "MCP_UNIFI_"))}
    env.update(
        {
            "MCP_UNIFI_AUTH_REQUIRED": "false",
            "MCP_UNIFI_AUDIT_PATH": str(tmp_path / "audit.jsonl"),
            "FASTMCP_CHECK_FOR_UPDATES": "off",
            "FASTMCP_SHOW_SERVER_BANNER": "false",
        }
    )
    env.update(extra_env)
    # The argv is this interpreter plus a constant script, nothing from input,
    # so the S603 lint about untrusted subprocess input does not apply.
    proc = subprocess.run(  # noqa: S603
        [sys.executable, "-c", _PROBE],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,  # a crashed probe is reported below with its stderr
    )
    for line in proc.stdout.splitlines():
        if line.startswith("IDLE "):
            return json.loads(line.removeprefix("IDLE "))
    pytest.fail(f"probe produced no result (rc={proc.returncode}):\n{proc.stderr[-3000:]}")


def test_idle_sessions_are_reaped_open(tmp_path: Path) -> None:
    assert _live_idle_timeout(tmp_path) == 1800


def test_idle_sessions_are_reaped_behind_bearer_auth(tmp_path: Path) -> None:
    assert (
        _live_idle_timeout(
            tmp_path, MCP_UNIFI_AUTH_REQUIRED="true", MCP_UNIFI_AUTH_TOKENS="probe:probe-token"
        )
        == 1800
    )


def test_control_idle_timeout_override_reaches_the_manager(tmp_path: Path) -> None:
    assert _live_idle_timeout(tmp_path, FASTMCP_HTTP_SESSION_IDLE_TIMEOUT="60") == 60
