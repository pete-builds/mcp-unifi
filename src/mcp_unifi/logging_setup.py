"""Structured logging configuration for mcp-unifi.

In production we emit JSON via stdlib ``logging`` with a custom formatter so
log aggregators (Loki, Datadog, anything that ingests JSON lines) can parse
each record without regex hacks. ``log_format=text`` falls back to a plain
human-readable format for local development.

Log records never carry the API key or WLAN passphrases. The formatter scrubs a
small set of well-known sensitive keys defensively in case caller code
accidentally drops one into ``extra``.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

_SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "api_key",
        "unifi_api_key",
        "x-api-key",
        "x_api_key",
        "passphrase",
        "x_passphrase",
        "password",
    }
)

_RESERVED_LOGRECORD_FIELDS: frozenset[str] = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "message",
        "module",
        "msecs",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "thread",
        "threadName",
        "taskName",
    }
)


def _scrub(value: Any) -> Any:
    """Recursively replace sensitive values with ``[REDACTED]``."""
    if isinstance(value, dict):
        return {
            k: ("[REDACTED]" if k.lower() in _SENSITIVE_KEYS else _scrub(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_scrub(item) for item in value]
    return value


class JsonFormatter(logging.Formatter):
    """Serialise each log record as a single JSON line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        # Surface any structured extras the caller passed through.
        extras = {
            key: _scrub(value)
            for key, value in record.__dict__.items()
            if key not in _RESERVED_LOGRECORD_FIELDS and not key.startswith("_")
        }
        if extras:
            payload["extra"] = extras
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO", fmt: str = "json") -> None:
    """Configure the root logger. Idempotent — safe to call multiple times."""
    root = logging.getLogger()
    root.setLevel(level.upper())
    # Clear any handlers from prior configuration (e.g. uvicorn defaults) so we
    # never emit duplicate lines.
    for handler in list(root.handlers):
        root.removeHandler(handler)

    # stderr — never stdout. The stdio MCP transport uses stdout for the
    # JSON-RPC framing; any log line on stdout would corrupt the protocol.
    handler = logging.StreamHandler(stream=sys.stderr)
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter(
                fmt="%(asctime)s %(levelname)s %(name)s: %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S%z",
            )
        )
    root.addHandler(handler)
