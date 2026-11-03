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

from mcp_unifi.redaction import REDACTED_OUTPUT, is_sensitive, redact

if TYPE_CHECKING:
    import httpx

#: Longest controller message kept in an error string.
MAX_ERROR_DETAIL_CHARS = 200

#: Shortest sent secret that is masked inside error text.
MIN_MASKED_SECRET_CHARS = 4


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


def _strings_under(value: object, out: list[str]) -> None:
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, int | float) and not isinstance(value, bool):
        out.append(str(value))
    elif isinstance(value, dict):
        for item in value.values():
            _strings_under(item, out)
    elif isinstance(value, list | tuple):
        for item in value:
            _strings_under(item, out)


def sent_secrets(sent: object) -> list[str]:
    """Every value the request carried under a sensitive key, longest first.

    These are the values a controller can echo back inside free text ("invalid
    passphrase hunter2"), where key-based :func:`redact` cannot see them. Values
    shorter than :data:`MIN_MASKED_SECRET_CHARS` are skipped: masking every
    ``1`` in a message would destroy it, and no UniFi credential is that short.
    """
    found: list[str] = []

    def walk(value: object) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                if is_sensitive(str(key)):
                    _strings_under(item, found)
                else:
                    walk(item)
        elif isinstance(value, list | tuple):
            for item in value:
                walk(item)

    walk(sent)
    unique = {v for v in found if len(v) >= MIN_MASKED_SECRET_CHARS}
    return sorted(unique, key=len, reverse=True)


def _clean(text: str, secrets: list[str]) -> str:
    """Mask echoed secrets, then bound. Masking first, so a cut cannot split one."""
    for secret in secrets:
        text = text.replace(secret, REDACTED_OUTPUT)
    return text[:MAX_ERROR_DETAIL_CHARS]


def error_fields(resp: httpx.Response, sent: object = None) -> tuple[str | None, str | None]:
    """Return ``(code, message)`` from an error body, safe to log or show.

    Only the named error fields are read, because they are what an operator
    needs and what callers match on (``api.err.MacUsed``,
    ``api.err.InvalidObject``, Integration ``code``):

    * legacy Network envelope: ``meta.msg`` (returned as the code)
    * v2 and Integration API: ``code`` and ``message``
    * Protect and Access: ``message``, ``error`` or ``detail``

    The parsed body goes through :func:`redact` first, so a record nested
    under one of those keys loses its secret fields. Then every value the
    request sent under a sensitive key (:func:`sent_secrets`) is masked
    wherever it appears in the text, and each field is cut to
    :data:`MAX_ERROR_DETAIL_CHARS`.

    Limit, stated plainly: a secret the controller holds but this request did
    not send cannot be recognised inside free text. No UniFi error message
    seen so far carries one; if one ever does, it needs its own rule here.
    """
    try:
        payload = resp.json()
    except Exception:
        return None, None
    if not isinstance(payload, dict):
        return None, None

    secrets = sent_secrets(sent)
    safe = redact(payload)
    meta = safe.get("meta")
    if isinstance(meta, dict):
        msg = _first_str(meta, ("msg",))
        if msg is not None:
            return _clean(msg, secrets), None
    code = _first_str(safe, ("code", "errorCode"))
    message = _first_str(safe, ("message", "error", "detail"))
    return (
        _clean(code, secrets) if code is not None else None,
        _clean(message, secrets) if message is not None else None,
    )


def describe_error_body(resp: httpx.Response, sent: object = None) -> str:
    """Describe an error body without pasting raw response text into a result.

    The returned suffix goes into a :class:`UniFiError` message, which reaches
    a tool result and from there an agent's context and the audit log. Raw
    body text is never copied: a controller that echoes a rejected record
    back (a WLAN with its ``x_passphrase``, a network with its VPN key) would
    otherwise hand the secret straight to the model. ``sent`` is the request's
    JSON body; see :func:`error_fields` for what is kept and what is masked.

    A body with no recognised error field (a mid-upgrade HTML page, a reverse
    proxy's own error, an echoed record) is reported by content type and size
    only. Returns ``""`` for an empty body, otherwise a string starting with
    ``": "`` or ``" ("``.
    """
    code, message = error_fields(resp, sent)
    parts = [p for p in (code, message) if p]
    if parts:
        return ": " + ": ".join(parts)
    if not resp.content:
        return ""
    content_type = resp.headers.get("content-type", "unknown")
    return f" (unrecognised body: {content_type}, {len(resp.content)} bytes)"


__all__ = [
    "MAX_ERROR_DETAIL_CHARS",
    "MIN_MASKED_SECRET_CHARS",
    "UniFiError",
    "UniFiUnsupportedError",
    "describe_error_body",
    "error_fields",
    "sent_secrets",
]
