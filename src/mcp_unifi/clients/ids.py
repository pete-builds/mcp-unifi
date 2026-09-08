"""Single-path-segment validation for caller-supplied identifiers.

Every tool that takes a resource id (``camera_id``, ``wlan_id``, ``door_id``,
a settings ``key``) ends up interpolating it into a URL path or query string
inside one of the controller clients. A free-text id that contains ``/``, a
dot segment, ``?``, ``#`` or ``&`` therefore changes which route the request
hits: httpx normalises ``..`` before sending, so a Protect camera id of
``../../../network/api/s/default/rest/wlanconf`` was answered by the Network
app's ``wlanconf`` route with the shared API key, from a client scoped to
Protect only.

:func:`path_segment` is the one control on that boundary. Every client method
that builds a path or query from an id calls it, so the check cannot be
forgotten per tool. Rejections raise :class:`InvalidIdentifierError`, a
:class:`UniFiError`, so the existing ``except UniFiError`` in every tool turns
it into the normal error envelope.

The allowlist is deliberately narrow. UniFi ids are 24-hex-character Mongo
ids, MACs are colon-separated hex, settings keys are short lowercase words,
and Protect and Access ids are the same shapes. Nothing legitimate needs a
slash, a space, or a percent sign.
"""

from __future__ import annotations

import re

from mcp_unifi.clients.errors import UniFiError

#: Characters a single path segment may contain. Anchored with ``\A``/``\Z``
#: rather than ``^``/``$``: Python's ``$`` also matches just before a trailing
#: newline, so ``"abc\n"`` would satisfy an allowlist documented as strict.
#: Colon is included for MAC
#: addresses (``AA:BB:CC:DD:EE:FF``), which some device routes take in place of
#: an ``_id``. Dot is included because a few controller keys contain one, and
#: the bare ``.`` / ``..`` segments are refused separately below.
_SEGMENT = re.compile(r"\A[A-Za-z0-9_.:-]+\Z")

#: Longest id the gateway is known to issue is 24 characters; MACs are 17.
#: A generous ceiling still stops a pathological argument from becoming a
#: pathological URL.
MAX_SEGMENT_LENGTH = 128


class InvalidIdentifierError(UniFiError):
    """A caller-supplied id is not a single, safe URL path segment."""


def path_segment(value: str, name: str) -> str:
    """Return ``value`` if it is safe to interpolate as one URL path segment.

    ``name`` is the tool argument the value came from and appears in the error
    message so the operator knows which field to fix. The value itself is not
    echoed back: it is attacker-controlled by definition here, and the audit
    log already records tool arguments.

    Raises:
        InvalidIdentifierError: on an empty value, a bare ``.`` or ``..``, any
            character outside ``[A-Za-z0-9_.:-]``, or a value longer than
            :data:`MAX_SEGMENT_LENGTH`.
    """
    if not isinstance(value, str) or not value:
        raise InvalidIdentifierError(f"{name} must be a non-empty identifier")
    if value in {".", ".."}:
        raise InvalidIdentifierError(f"{name} is not a valid identifier")
    if len(value) > MAX_SEGMENT_LENGTH:
        raise InvalidIdentifierError(
            f"{name} is too long ({len(value)} characters, limit {MAX_SEGMENT_LENGTH})"
        )
    if not _SEGMENT.match(value):
        raise InvalidIdentifierError(
            f"{name} may only contain letters, digits, '_', '.', ':' and '-'"
        )
    return value


__all__ = ["MAX_SEGMENT_LENGTH", "InvalidIdentifierError", "path_segment"]
