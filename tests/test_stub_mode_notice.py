"""The fake-data trap: a gateway is configured, but stub mode answers.

``STUB_MODE`` defaults to true. Someone who sets ``UNIFI_HOST`` and an API key
(or a controllers file) and leaves ``STUB_MODE`` alone gets a server that
builds the controller config and then serves the simulator's made-up devices.
Nothing used to say so. The data looks plausible, so the person reading
Claude's answer had no way to tell it was not their network.

These tests pin two signals for exactly that state, and their absence
everywhere else:

* one WARNING at startup, naming the cause and the fix;
* one extra text line on every tool result, after the tool's own JSON, so the
  model (and through it the person) sees it on every answer. The JSON block is
  left byte for byte as it was, so nothing that parses it changes.

The default itself is unchanged. Flipping it is a breaking change and the
owner's decision.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path

import pytest
from fastmcp import Client, FastMCP

from mcp_unifi.config import Settings
from mcp_unifi.server import build_server

pytestmark = pytest.mark.usefixtures("clean_unifi_env")

#: Words every form of the notice must carry, checked case-insensitively, so
#: the tests pin the meaning rather than one exact sentence.
_NOTICE_WORDS = ("simulated", "stub_mode=false")


def _says_simulated(text: str) -> bool:
    lowered = text.lower()
    return all(word in lowered for word in _NOTICE_WORDS)


@pytest.fixture
def warnings_seen(caplog: pytest.LogCaptureFixture) -> Callable[[], list[str]]:
    """Every WARNING any ``mcp_unifi`` logger emitted, as messages."""
    caplog.set_level(logging.WARNING)

    def _messages() -> list[str]:
        return [
            r.getMessage()
            for r in caplog.records
            if r.name.startswith("mcp_unifi") and r.levelno >= logging.WARNING
        ]

    return _messages


def _settings_from_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, env: dict[str, str]
) -> Settings:
    """Build Settings the way the server does: from the environment, no .env."""
    monkeypatch.chdir(tmp_path)  # no stray .env in the working directory
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return Settings(mcp_transport="stdio", log_format="text", auth_required=False)


def _controllers_file(tmp_path: Path) -> Path:
    path = tmp_path / "controllers.yaml"
    path.write_text(
        "- name: home\n  host: 192.0.2.10\n  api_key: test-key-not-real\n",
        encoding="utf-8",
    )
    return path


# ---------------------------------------------------------------------------
# The trap: a gateway configured, STUB_MODE left unset
# ---------------------------------------------------------------------------


def test_gateway_env_with_stub_mode_unset_warns_at_startup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, warnings_seen: Callable[[], list[str]]
) -> None:
    settings = _settings_from_env(
        monkeypatch, tmp_path, {"UNIFI_HOST": "192.0.2.1", "UNIFI_API_KEY": "test-key-not-real"}
    )
    assert settings.stub_mode is True  # the default is untouched

    build_server(settings)

    loud = [m for m in warnings_seen() if _says_simulated(m)]
    assert len(loud) == 1, warnings_seen()
    assert "STUB_MODE is unset" in loud[0]
    assert "UNIFI_HOST" in loud[0]
    # Never the key.
    assert "test-key-not-real" not in loud[0]


def test_controllers_file_with_stub_mode_unset_warns_at_startup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, warnings_seen: Callable[[], list[str]]
) -> None:
    path = _controllers_file(tmp_path)
    settings = _settings_from_env(monkeypatch, tmp_path, {"MCP_UNIFI_CONTROLLERS_FILE": str(path)})

    build_server(settings)

    loud = [m for m in warnings_seen() if _says_simulated(m)]
    assert len(loud) == 1, warnings_seen()
    assert "MCP_UNIFI_CONTROLLERS_FILE" in loud[0]
    assert "test-key-not-real" not in loud[0]


def test_stub_mode_left_on_in_the_desktop_form_also_warns(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, warnings_seen: Callable[[], list[str]]
) -> None:
    """The .dxt form always sends STUB_MODE, ticked by default.

    Someone who fills in host and key and never unticks the box is in the same
    trap, with STUB_MODE explicitly "true" rather than unset. The warning says
    which of the two it saw.
    """
    settings = _settings_from_env(
        monkeypatch,
        tmp_path,
        {"STUB_MODE": "true", "UNIFI_HOST": "192.0.2.1", "UNIFI_API_KEY": "test-key-not-real"},
    )

    build_server(settings)

    loud = [m for m in warnings_seen() if _says_simulated(m)]
    assert len(loud) == 1, warnings_seen()
    assert "STUB_MODE is true" in loud[0]


async def test_every_tool_answer_says_the_data_is_simulated(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    settings = _settings_from_env(
        monkeypatch, tmp_path, {"UNIFI_HOST": "192.0.2.1", "UNIFI_API_KEY": "test-key-not-real"}
    )
    server = build_server(settings)

    async with Client(server) as client:
        result = await client.call_tool("list_devices", {"compact": True})

    texts = [block.text for block in result.content]
    # The tool's own JSON is still the first block, unchanged and parseable.
    devices = json.loads(texts[0])
    assert devices and devices[0]["name"] == "Gateway"
    # And a plain line after it says what the data is.
    assert any(_says_simulated(t) for t in texts[1:]), texts


async def test_an_error_answer_carries_the_notice_too(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    settings = _settings_from_env(
        monkeypatch, tmp_path, {"UNIFI_HOST": "192.0.2.1", "UNIFI_API_KEY": "test-key-not-real"}
    )
    server = build_server(settings)

    async with Client(server) as client:
        result = await client.call_tool("list_devices", {"controller": "nope"})

    texts = [block.text for block in result.content]
    assert "error" in json.loads(texts[0])
    assert any(_says_simulated(t) for t in texts[1:]), texts


# ---------------------------------------------------------------------------
# Controls: no gateway configured, or real mode, stays silent
# ---------------------------------------------------------------------------


@pytest.fixture
def plain_stub_server(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> FastMCP:
    return build_server(_settings_from_env(monkeypatch, tmp_path, {}))


def test_plain_stub_mode_does_not_warn(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, warnings_seen: Callable[[], list[str]]
) -> None:
    """Trying the server with no gateway is the documented first step, not a mistake."""
    build_server(_settings_from_env(monkeypatch, tmp_path, {}))
    assert not [m for m in warnings_seen() if _says_simulated(m)]


async def test_plain_stub_mode_answers_carry_only_the_tool_json(
    plain_stub_server: FastMCP,
) -> None:
    async with Client(plain_stub_server) as client:
        result = await client.call_tool("list_devices", {"compact": True})
    assert len(result.content) == 1
    assert not _says_simulated(result.content[0].text)


def test_real_mode_does_not_warn(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, warnings_seen: Callable[[], list[str]]
) -> None:
    settings = _settings_from_env(
        monkeypatch,
        tmp_path,
        {"STUB_MODE": "false", "UNIFI_HOST": "192.0.2.1", "UNIFI_API_KEY": "test-key-not-real"},
    )
    build_server(settings)  # builds clients; makes no request
    assert not [m for m in warnings_seen() if _says_simulated(m)]


def test_a_host_without_a_key_is_not_a_configured_gateway(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, warnings_seen: Callable[[], list[str]]
) -> None:
    """``UNIFI_HOST`` alone never built a controller, so stub mode is not hiding one."""
    build_server(_settings_from_env(monkeypatch, tmp_path, {"UNIFI_HOST": "192.0.2.1"}))
    assert not [m for m in warnings_seen() if _says_simulated(m)]
