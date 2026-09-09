"""``confirm_destructive_action`` tool — the second half of preview-then-confirm.

v0.7.0 split every Network ``delete_*`` tool into two phases. The first call
returns a preview envelope with a token; this tool executes the queued action
when the caller passes the token back.

Side effects:

* On success: runs the pending action's executor, removes the token from the
  registry, returns whatever the original delete tool would have returned
  (a ``{"deleted": true, "<id>_id": "..."}`` envelope or an upstream error).
* On expired / unknown token: returns the standard error envelope.

The audit decorator captures both halves. The token itself is scrubbed from
both events (any key containing ``token`` is a secret to the audit log), so the
link between them is ``preview_id``: the preview envelope carries it, and this
tool annotates its own event with the same value plus the queued ``action`` and
the controller the pending action actually targets. Without that annotation
the confirm event said ``controller: default`` regardless, because this tool
takes no ``controller`` argument for the decorator to read.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from mcp_unifi.annotations import DESTRUCTIVE_ONCE
from mcp_unifi.clients.unifi import UniFiError
from mcp_unifi.modules._audit import annotate_audit, audited
from mcp_unifi.modules.network._common import make_err
from mcp_unifi.modules.network._pending import get_pending_actions, preview_id

if TYPE_CHECKING:
    from fastmcp import FastMCP

    from mcp_unifi.config import Settings
    from mcp_unifi.dispatcher import ControllerRegistry

logger = logging.getLogger("mcp_unifi.network.confirm")


def register(mcp: FastMCP, settings: Settings, _registry: ControllerRegistry) -> None:
    """Register :func:`confirm_destructive_action` on ``mcp``."""
    err = make_err(settings)

    @mcp.tool(annotations=DESTRUCTIVE_ONCE)
    # Classified mutating, and this is the classification the whole write gate
    # turns on. The tool's own name carries no write-shaped prefix, so any gate
    # that keyed on ``create_``/``update_``/``delete_``/``set_`` would leave it
    # callable — a "read-only" server that still executes a queued delete. It
    # runs the mutation; it is mutating.
    @audited("confirm_destructive_action", mutates=True)
    async def confirm_destructive_action(token: str) -> str:
        """Execute a queued destructive action by its preview token.

        Side effects:
        - Runs the mutation that was previewed (delete VLAN, WLAN, firewall
          rule, port profile, port forward, or static DHCP lease).
        - Removes the token from the in-process pending-actions registry.
          A second call with the same token returns an error.

        Example: confirm_destructive_action(token="3f1a...")

        Args:
            token: The ``token`` field from a previous destructive tool's
                preview envelope. Tokens expire 5 minutes after issuance.

        Returns:
            The standard delete-tool envelope on success:
            ``{"deleted": true, "<resource>_id": "..."}``. Returns the
            standard error envelope (``{"error": "...", "stub_mode": bool}``)
            for unknown, used, or expired tokens.
        """
        annotate_audit(preview_id=preview_id(token))
        pending = get_pending_actions().pop(token)
        if pending is None:
            return err(
                "unknown or expired token. Tokens are single-use and "
                "expire 5 minutes after issuance; re-invoke the original "
                "destructive tool to get a fresh token."
            )
        annotate_audit(controller=pending.controller, action=pending.action)
        try:
            return await pending.executor()
        except UniFiError as exc:
            logger.exception(
                "confirm_destructive_action failed",
                extra={"action": pending.action, "controller": pending.controller},
            )
            return err(str(exc))


__all__ = ["register"]
