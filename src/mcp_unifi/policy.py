"""Fail-closed authorization policy primitives for the MCP tool surface.

The v1 deployable posture is ``monitor``: explicitly classified reads are
available and every mutation is denied. ``control`` is represented so a future
approval/change-plan implementation has a stable contract, but is deliberately
not an executable mode in v1.

This module contains no controller or FastMCP calls. Keeping the decision
function pure makes the deny precedence and approval contract testable without
either a live gateway or a simulated mutation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Final


class OperationMode(StrEnum):
    """Server posture selected by the operator."""

    MONITOR = "monitor"
    CONTROL = "control"


class ToolClass(StrEnum):
    """Canonical classes used by policy; unknown is never treated as a read."""

    READ = "read"
    MUTATION = "mutation"
    UNKNOWN = "unknown"


READ: Final = ToolClass.READ
MUTATION: Final = ToolClass.MUTATION
UNKNOWN: Final = ToolClass.UNKNOWN


class PolicyDecision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class PolicyConfigurationError(ValueError):
    """Raised when an unsafe or unsupported policy is constructed."""


class ApprovalContractError(ValueError):
    """Raised when a future approval/change-plan contract is incomplete."""


@dataclass(frozen=True, slots=True)
class ApprovalBinding:
    """Non-executable future approval binding.

    The object records the fields an eventual control-plane approval must bind.
    It intentionally has no method that executes a tool or authorizes a call.
    """

    digest: str
    requester: str
    tool: str
    target: str
    expires_at: datetime
    one_use: bool = True

    def __post_init__(self) -> None:
        if not self.digest.strip():
            raise ApprovalContractError("approval digest is required")
        if not self.requester.strip():
            raise ApprovalContractError("approval requester is required")
        if not self.tool.strip():
            raise ApprovalContractError("approval tool is required")
        if not self.target.strip():
            raise ApprovalContractError("approval target is required")
        if self.expires_at.tzinfo is None:
            raise ApprovalContractError("approval expiry must include a timezone")
        if not self.one_use:
            raise ApprovalContractError("approvals must be single-use")


@dataclass(frozen=True, slots=True)
class ChangePlan:
    """Documentation-ready future change plan; never executable by itself."""

    digest: str
    requester: str
    tool: str
    target: str
    expires_at: datetime
    approval: ApprovalBinding | None = None


@dataclass(slots=True)
class _UseCounter:
    used_digests: set[str] = field(default_factory=set)

    def consume(self, approval: ApprovalBinding, *, now: datetime | None = None) -> bool:
        """Atomically validate expiry and consume an approval once in memory."""
        current = now or datetime.now(UTC)
        if current.tzinfo is None:
            raise ApprovalContractError("current time must include a timezone")
        if approval.expires_at <= current or approval.digest in self.used_digests:
            return False
        self.used_digests.add(approval.digest)
        return True


class V1Policy:
    """Pure v1 policy evaluator with deny precedence and default deny."""

    def __init__(self, mode: OperationMode | str = OperationMode.MONITOR) -> None:
        try:
            self.mode = OperationMode(mode)
        except ValueError as exc:
            raise PolicyConfigurationError(f"unsupported operation mode: {mode!r}") from exc
        if self.mode is OperationMode.CONTROL:
            raise PolicyConfigurationError(
                "control mode is reserved and not deployable in policy v1"
            )
        self._used = _UseCounter()

    def decide(
        self, tool_class: ToolClass | str, *, explicitly_allowed: bool = False
    ) -> PolicyDecision:
        """Return a decision; deny rules always run before allow rules."""
        try:
            classification = ToolClass(tool_class)
        except ValueError:
            classification = ToolClass.UNKNOWN
        if classification in {ToolClass.MUTATION, ToolClass.UNKNOWN}:
            return PolicyDecision.DENY
        # ``control`` is rejected by __init__, so the only executable v1 mode
        # is monitor. The explicit allow flag is retained for decision-table
        # callers, but can never override the deny cases above.
        return PolicyDecision.ALLOW if classification is ToolClass.READ else PolicyDecision.DENY

    def classify(self, *, mutates: bool | None) -> ToolClass:
        """Convert the registration declaration to the canonical class."""
        if mutates is None:
            return ToolClass.UNKNOWN
        return ToolClass.MUTATION if mutates else ToolClass.READ

    def consume_approval(self, approval: ApprovalBinding, *, now: datetime | None = None) -> bool:
        """Validate the future single-use contract without authorizing execution."""
        return self._used.consume(approval, now=now)


__all__ = [
    "MUTATION",
    "READ",
    "UNKNOWN",
    "ApprovalBinding",
    "ApprovalContractError",
    "ChangePlan",
    "OperationMode",
    "PolicyConfigurationError",
    "PolicyDecision",
    "ToolClass",
    "V1Policy",
]
