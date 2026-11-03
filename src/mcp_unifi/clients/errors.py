"""Exception types shared by every controller client.

They lived in :mod:`mcp_unifi.clients.unifi` until the identifier validator in
:mod:`mcp_unifi.clients.ids` needed to raise one; that module is imported by
``unifi.py``, so the base class had to move out to break the cycle. The names
are still re-exported from ``mcp_unifi.clients.unifi`` for existing imports.

:func:`describe_error_body` lives here too, so every client (Network legacy
and v2, Integration, Protect, Access) describes a failed response the same way.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mcp_unifi.redaction import redact

if TYPE_CHECKING:
    import httpx

#: Longest controller message kept in an error string.
MAX_ERROR_DETAIL_CHARS = 200


class UniFiError(RuntimeError):
    """Raised on any non-2xx response or transport failure."""


class UniFiUnsupportedError(UniFiError):
    """Raised when the controller firmware does not expose the requested route.

    Distinct from a generic :class:`UniFiError` so callers can tell "this
    controller version cannot answer that question" apart from "the call
    failed". Both surface to the operator as an error — which is the entire
    point. See :meth:`UniFiClient._get_or_unsupported` for why.
    """


def _first_str(payload: dict[str, object], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def describe_error_body(resp: httpx.Response) -> str:
    """Describe an error body without pasting raw response text into a result.

    The returned suffix goes into a :class:`UniFiError` message, which reaches
    a tool result and from there an agent's context and the audit log. Raw
    body text is never copied: a controller that echoes a rejected record
    back (a WLAN with its ``x_passphrase``, a network with its VPN key) would
    otherwise hand the secret straight to the model.

    Only the named error fields are kept, because they are what an operator
    needs and what callers match on (``api.err.MacUsed``,
    ``api.err.InvalidObject``):

    * legacy Network envelope: ``meta.msg``
    * v2 and Integration API: ``code`` and ``message``
    * Protect and Access: ``message``, ``error`` or ``detail``

    The parsed body goes through :func:`redact` before anything is read, and
    each kept value is cut to :data:`MAX_ERROR_DETAIL_CHARS`. A body that is
    not JSON (a mid-upgrade HTML page, a reverse proxy's own error) is
    reported by content type and size only. Returns ``""`` for an empty body,
    otherwise a string starting with ``": "`` or ``" ("``.
    """
    try:
        payload = resp.json()
    except Exception:
        payload = None

    if isinstance(payload, dict):
        safe = redact(payload)
        meta = safe.get("meta")
        if isinstance(meta, dict):
            msg = _first_str(meta, ("msg",))
            if msg is not None:
                return f": {msg[:MAX_ERROR_DETAIL_CHARS]}"
        code = _first_str(safe, ("code", "errorCode"))
        message = _first_str(safe, ("message", "error", "detail"))
        parts = [p[:MAX_ERROR_DETAIL_CHARS] for p in (code, message) if p is not None]
        if parts:
            return ": " + ": ".join(parts)

    if not resp.content:
        return ""
    content_type = resp.headers.get("content-type", "unknown")
    return f" (unrecognised body: {content_type}, {len(resp.content)} bytes)"


__all__ = [
    "MAX_ERROR_DETAIL_CHARS",
    "UniFiError",
    "UniFiUnsupportedError",
    "describe_error_body",
]
