"""Exception types shared by every controller client.

They lived in :mod:`mcp_unifi.clients.unifi` until the identifier validator in
:mod:`mcp_unifi.clients.ids` needed to raise one; that module is imported by
``unifi.py``, so the base class had to move out to break the cycle. The names
are still re-exported from ``mcp_unifi.clients.unifi`` for existing imports.
"""

from __future__ import annotations


class UniFiError(RuntimeError):
    """Raised on any non-2xx response or transport failure."""


class UniFiUnsupportedError(UniFiError):
    """Raised when the controller firmware does not expose the requested route.

    Distinct from a generic :class:`UniFiError` so callers can tell "this
    controller version cannot answer that question" apart from "the call
    failed". Both surface to the operator as an error — which is the entire
    point. See :meth:`UniFiClient._get_or_unsupported` for why.
    """


__all__ = ["UniFiError", "UniFiUnsupportedError"]
