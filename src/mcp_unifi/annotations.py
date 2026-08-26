"""MCP tool annotations, shared by all 134 tools across the three modules.

WHY THIS FILE EXISTS
--------------------
Nothing in an MCP manifest distinguishes ``delete_wlan`` from ``get_system_info``
unless the tool says so. Without these hints a client has no basis on which to
prompt before a call, which on this server means no basis on which to prompt
before deleting a VLAN, blocking a client, restarting a live gateway, or
restoring a whole configuration over the current one.

This server already has the best write gate in the fleet: destructive actions
preview, mint a token, and require ``confirm_destructive_action`` to execute.
These annotations are not a replacement for it. A gate protects the moment a
call is *made*; an annotation is what lets the layer above decide whether to
make it. Both, or neither is doing its job.

CHOOSING BETWEEN THEM
---------------------
``destructiveHint`` marks a call that removes, revokes, or interrupts, and the
classification here leans deliberately toward setting it. Where a change is
technically reversible but takes something away *now* -- blocking a client,
restarting a device, replacing a config -- it is marked destructive, because
the hint exists to trigger a confirmation and an unwanted prompt costs far less
than a silent outage.

``idempotentHint`` answers a narrower question: does calling this twice land in
the same place? A ``set_*`` or ``update_*`` does. A ``create_*`` does not -- it
makes a second one. Getting this wrong in the safe-sounding direction is the
more dangerous error, because an idempotent hint actively invites a retry.

``openWorldHint`` is True on every tool here: all of them talk to a UniFi
controller over the network, and none operates on a closed, enumerable set.
"""

from __future__ import annotations

#: Reads only. Safe to repeat, safe to call speculatively.
READ_ONLY = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": True,
}

#: Sets a value on something that already exists. Applying the same arguments
#: twice lands in the same place, which is what makes a retry safe here.
WRITE_IDEMPOTENT = {
    "readOnlyHint": False,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": True,
}

#: Creates a new resource. Calling twice creates two, which is exactly why
#: this is separate from WRITE_IDEMPOTENT rather than folded into it.
CREATE = {
    "readOnlyHint": False,
    "destructiveHint": False,
    "idempotentHint": False,
    "openWorldHint": True,
}

#: Performs a one-shot operation with a real effect that persists nothing.
#: ``trigger_speedtest`` is the case: it changes no controller state, but it
#: saturates the WAN for the better part of a minute, so calling it twice is
#: not a no-op and read-only would be a plain lie.
ACTION = {
    "readOnlyHint": False,
    "destructiveHint": False,
    "idempotentHint": False,
    "openWorldHint": True,
}

#: Removes, revokes, or interrupts. The calls a client should be able to
#: confirm -- and the class ``confirm_destructive_action`` itself belongs to,
#: since it is the tool that actually executes every gated deletion.
DESTRUCTIVE = {
    "readOnlyHint": False,
    "destructiveHint": True,
    "idempotentHint": True,
    "openWorldHint": True,
}

#: Same, but a repeat is an error rather than a no-op: a preview token is
#: single-use, so a second ``confirm_destructive_action`` with it fails.
DESTRUCTIVE_ONCE = {
    "readOnlyHint": False,
    "destructiveHint": True,
    "idempotentHint": False,
    "openWorldHint": True,
}
