"""Decision-table tests for the v1 fail-closed policy contract."""

from datetime import UTC, datetime, timedelta

import pytest

from mcp_unifi.config import Settings
from mcp_unifi.policy import (
    ApprovalBinding,
    ApprovalContractError,
    OperationMode,
    PolicyConfigurationError,
    PolicyDecision,
    ToolClass,
    V1Policy,
)
from mcp_unifi.server import build_server


@pytest.mark.parametrize(
    ("tool_class", "explicitly_allowed", "expected"),
    [
        (ToolClass.READ, True, PolicyDecision.ALLOW),
        (ToolClass.READ, False, PolicyDecision.ALLOW),
        (ToolClass.MUTATION, True, PolicyDecision.DENY),
        (ToolClass.MUTATION, False, PolicyDecision.DENY),
        (ToolClass.UNKNOWN, True, PolicyDecision.DENY),
        ("not-a-class", True, PolicyDecision.DENY),
    ],
)
def test_monitor_policy_is_default_deny_and_deny_overrides_allow(
    tool_class: ToolClass | str, explicitly_allowed: bool, expected: PolicyDecision
) -> None:
    assert V1Policy().decide(tool_class, explicitly_allowed=explicitly_allowed) is expected


def test_control_is_reserved_and_not_deployable() -> None:
    with pytest.raises(PolicyConfigurationError, match="not deployable"):
        V1Policy(OperationMode.CONTROL)


def test_classification_never_defaults_unknown_to_read() -> None:
    policy = V1Policy()
    assert policy.classify(mutates=None) is ToolClass.UNKNOWN
    assert policy.decide(policy.classify(mutates=None)) is PolicyDecision.DENY


def _approval(*, digest: str = "sha256:abc", one_use: bool = True) -> ApprovalBinding:
    return ApprovalBinding(
        digest=digest,
        requester="operator@example.test",
        tool="create_vlan",
        target="controller/default/network/net-1",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
        one_use=one_use,
    )


def test_future_approval_is_bound_and_single_use() -> None:
    policy = V1Policy()
    approval = _approval()
    assert policy.consume_approval(approval) is True
    assert policy.consume_approval(approval) is False


def test_future_approval_rejects_missing_binding_fields() -> None:
    with pytest.raises(ApprovalContractError, match="digest"):
        _approval(digest=" ")
    with pytest.raises(ApprovalContractError, match="single-use"):
        _approval(one_use=False)


def test_future_approval_requires_timezone_aware_expiry() -> None:
    with pytest.raises(ApprovalContractError, match="timezone"):
        ApprovalBinding(
            digest="sha256:abc",
            requester="operator",
            tool="create_vlan",
            target="controller/default",
            expires_at=datetime.now(),
        )


@pytest.mark.asyncio
async def test_explicit_monitor_mode_hides_mutations() -> None:
    server = build_server(
        Settings(
            stub_mode=True,
            operation_mode="monitor",
            mcp_transport="stdio",
            auth_required=False,
        )
    )
    names = {tool.name for tool in await server.list_tools()}
    assert "list_networks" in names
    assert "create_vlan" not in names


def test_control_mode_cannot_build_a_server() -> None:
    with pytest.raises(ValueError, match="not deployable"):
        build_server(Settings(stub_mode=True, operation_mode="control"))
