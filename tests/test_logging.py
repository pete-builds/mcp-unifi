"""Tests for the structured logging setup."""

from __future__ import annotations

import io
import json
import logging

from mcp_unifi.logging_setup import JsonFormatter, _scrub, configure_logging


def test_scrub_replaces_known_sensitive_keys() -> None:
    payload = {
        "name": "ok",
        "passphrase": "supersecret",
        "x_passphrase": "alsosecret",
        "API_KEY": "leaky",
        "nested": {"unifi_api_key": "nope", "ok": True},
        "list": [{"password": "x"}, "plain"],
    }
    cleaned = _scrub(payload)
    assert cleaned["name"] == "ok"
    assert cleaned["passphrase"] == "[REDACTED]"
    assert cleaned["x_passphrase"] == "[REDACTED]"
    assert cleaned["API_KEY"] == "[REDACTED]"
    assert cleaned["nested"]["unifi_api_key"] == "[REDACTED]"
    assert cleaned["nested"]["ok"] is True
    assert cleaned["list"][0]["password"] == "[REDACTED]"
    assert cleaned["list"][1] == "plain"


def test_json_formatter_emits_valid_json() -> None:
    formatter = JsonFormatter()
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="x",
        lineno=1,
        msg="hello %s",
        args=("world",),
        exc_info=None,
    )
    record.extra_field = {"passphrase": "xx", "ok": 1}  # type: ignore[attr-defined]
    line = formatter.format(record)
    parsed = json.loads(line)
    assert parsed["msg"] == "hello world"
    assert parsed["level"] == "INFO"
    assert parsed["logger"] == "test"
    assert parsed["extra"]["extra_field"]["passphrase"] == "[REDACTED]"
    assert parsed["extra"]["extra_field"]["ok"] == 1


def test_configure_logging_replaces_handlers() -> None:
    configure_logging(level="DEBUG", fmt="json")
    root = logging.getLogger()
    assert root.level == logging.DEBUG
    assert len(root.handlers) == 1
    assert isinstance(root.handlers[0].formatter, JsonFormatter)

    # Calling again should not duplicate handlers.
    configure_logging(level="INFO", fmt="text")
    assert len(root.handlers) == 1


def test_configure_logging_text_format_emits_human_readable() -> None:
    buf = io.StringIO()
    configure_logging(level="INFO", fmt="text")
    handler = logging.getLogger().handlers[0]
    handler.stream = buf
    logging.getLogger("test").info("hello world")
    output = buf.getvalue()
    assert "hello world" in output
    assert "INFO" in output
