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

from mcp_unifi.redaction import redact

# The canonical list lives in redaction.py, which SECURITY.md describes as
# covering "three emitters: the structured logger, the audit log, and tool
# responses". Two of those genuinely imported it; this module kept a private
# seven-key set matched by EXACT equality while the canonical one has seventeen
# patterns matched by SUBSTRING. Of the nineteen secret spellings SECURITY.md
# enumerates, this logger caught five -- so `x_password`, `passwd`, `token`,
# `wpa_psk`, `x_ipsec_pre_shared_key` and the rest passed straight through.
#
# No reachable leak today: the API key travels in an X-API-Key header rather
# than a URL, the client deliberately raises type(exc).__name__ instead of
# str(exc), and every extra={} in the package carries a benign identifier. This
# is a false assurance being made true, not a live exposure being closed.

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
    """Recursively replace sensitive values with ``[REDACTED]``.

    Delegates to redaction.redact so the logger, the audit log and tool responses
    share one definition of "sensitive". redact() is used rather than scrub()
    specifically to keep this module's existing "[REDACTED]" sentinel -- scrub()
    writes "***" -- so the only behaviour change here is that MORE keys are
    caught, not that existing output changes shape. redact() also walks tuples
    and sets, which the private implementation did not.
    """
    return redact(value)


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
