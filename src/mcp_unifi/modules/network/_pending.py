"""In-process registry for preview-then-confirm (PtC) destructive actions.

v0.7.0 changed the contract for the six ``delete_*`` tools in the Network
module. Calling ``delete_firewall_rule(rule_id="abc")`` no longer mutates the
controller. Instead the tool:

1. Resolves the target resource via the existing backend lookup.
2. Generates a UUID4 token and stores a :class:`PendingAction` in the
   in-process registry with an expiration (now + ``TOKEN_TTL_SECONDS``).
3. Returns a preview envelope:

   .. code-block:: json

      {
        "preview": true,
        "action": "delete_firewall_rule",
        "controller": "default",
        "resource": {"_id": "abc", "name": "..."},
        "token": "<uuid4>",
        "expires_at": "<iso8601>",
        "confirm_with": "confirm_destructive_action"
      }

Callers commit the change by passing the token back to
:func:`confirm_destructive_action`. The registry resolves the token, runs the
queued executor, removes the token, and returns the original delete-tool
result.

Design notes
------------
* The registry is module-global on purpose: the FastMCP server is one process
  with one event loop and one set of registered tools, so a single shared
  store is enough. ``reset_pending_actions()`` exists for test isolation.
* Lazy cleanup: every ``put``, ``pop``, and ``get`` sweeps expired tokens
  first. No background task, no thread, no signal handler.
* The executor is captured as an ``async`` callable rather than serialised
  args. The delete tool body builds a tiny closure that does the actual
  backend call, then hands it to the registry. This keeps the registry
  ignorant of resource shape — it only knows "run this when the user
  confirms."
* ``time.monotonic`` would be slightly safer against wall-clock jumps, but
  tests need to express "the token is expired" by advancing the clock, and
  monkeypatching ``time.time`` is the established pattern in this repo.
  Using ``time.time`` here keeps that pattern intact.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

#: How long a preview token stays valid before it's swept. Tracks the spec.
TOKEN_TTL_SECONDS: float = 300.0  # 5 minutes


@dataclass
class PendingAction:
    """One queued destructive action awaiting confirmation.

    Attributes:
        token: UUID4 string returned to the caller.
        action: Name of the destructive tool (e.g. ``"delete_vlan"``).
        controller: Name of the UniFi controller the action targets.
        resource: Snapshot of the resource at preview time. Always carries
            ``_id`` plus whatever subset of fields the tool considered
            user-facing (name, ssid, mac, etc.).
        expires_at: Wall-clock epoch seconds at which the token is no longer
            valid. Lazy sweeps drop tokens with ``expires_at <= time.time()``.
        executor: Async callable that performs the actual mutation and
            returns the same JSON string the legacy delete tool returned.
    """

    token: str
    action: str
    controller: str
    resource: dict[str, Any]
    expires_at: float
    executor: Callable[[], Awaitable[str]] = field(repr=False)

    def expires_at_iso(self) -> str:
        """Return ``expires_at`` formatted as ISO 8601 UTC."""
        return datetime.fromtimestamp(self.expires_at, tz=UTC).isoformat()


class PendingActionsRegistry:
    """Simple in-process dict of ``token -> PendingAction``.

    Concurrency: FastMCP serialises tool calls on a single event loop, so we
    don't need a lock here. The registry is asyncio-friendly by virtue of
    being purely synchronous.
    """

    def __init__(self, ttl_seconds: float = TOKEN_TTL_SECONDS) -> None:
        self._actions: dict[str, PendingAction] = {}
        self._ttl_seconds = ttl_seconds

    @property
    def ttl_seconds(self) -> float:
        return self._ttl_seconds

    def _sweep(self) -> None:
        """Drop expired tokens. Called from every public access path."""
        now = time.time()
        expired = [tok for tok, act in self._actions.items() if act.expires_at <= now]
        for tok in expired:
            self._actions.pop(tok, None)

    def put(
        self,
        action: str,
        controller: str,
        resource: dict[str, Any],
        executor: Callable[[], Awaitable[str]],
    ) -> PendingAction:
        """Register a new pending action and return it.

        Args:
            action: Destructive tool name (used by audit + the preview shape).
            controller: Controller name the action will run against.
            resource: Snapshot of the target resource. Must include ``_id``.
            executor: Zero-arg async callable that performs the mutation and
                returns the tool's normal JSON string response.

        Returns:
            The newly-created :class:`PendingAction`, with its generated
            token and ISO expiration available on the instance.
        """
        self._sweep()
        token = str(uuid.uuid4())
        pending = PendingAction(
            token=token,
            action=action,
            controller=controller,
            resource=resource,
            expires_at=time.time() + self._ttl_seconds,
            executor=executor,
        )
        self._actions[token] = pending
        return pending

    def pop(self, token: str) -> PendingAction | None:
        """Resolve and remove a token. Returns ``None`` if unknown/expired."""
        self._sweep()
        return self._actions.pop(token, None)

    def get(self, token: str) -> PendingAction | None:
        """Resolve a token without removing it. Used by tests / introspection."""
        self._sweep()
        return self._actions.get(token)

    def __len__(self) -> int:
        self._sweep()
        return len(self._actions)

    def __contains__(self, token: object) -> bool:
        if not isinstance(token, str):
            return False
        self._sweep()
        return token in self._actions


#: Module-global registry. One per process; tests reset via
#: :func:`reset_pending_actions`.
_REGISTRY: PendingActionsRegistry = PendingActionsRegistry()


def get_pending_actions() -> PendingActionsRegistry:
    """Return the process-global :class:`PendingActionsRegistry`."""
    return _REGISTRY


def reset_pending_actions(ttl_seconds: float = TOKEN_TTL_SECONDS) -> PendingActionsRegistry:
    """Replace the global registry. Test-only entry point.

    Args:
        ttl_seconds: TTL for the fresh registry. Defaults to the production
            5-minute value but tests can shrink it to assert expiration paths
            without ``time.sleep``.
    """
    global _REGISTRY
    _REGISTRY = PendingActionsRegistry(ttl_seconds=ttl_seconds)
    return _REGISTRY


def build_preview_envelope(pending: PendingAction) -> dict[str, Any]:
    """Build the JSON-serialisable preview envelope returned by delete tools.

    Centralised so every delete tool returns the same shape and the
    confirm tool can document the contract in one place.
    """
    return {
        "preview": True,
        "action": pending.action,
        "controller": pending.controller,
        "resource": pending.resource,
        "token": pending.token,
        "expires_at": pending.expires_at_iso(),
        "confirm_with": "confirm_destructive_action",
    }


__all__ = [
    "TOKEN_TTL_SECONDS",
    "PendingAction",
    "PendingActionsRegistry",
    "build_preview_envelope",
    "get_pending_actions",
    "reset_pending_actions",
]
