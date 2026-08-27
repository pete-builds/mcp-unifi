"""Class 3: audit fidelity.

The question: does the audit record match what actually happened against the
stub controller?

This is not a test that the audit log *works*. It is a test that the log is
**true**. Two failures motivate the class, and neither one shows up in a
response-body assertion:

* A tool succeeds and logs something other than what it did. Every downstream
  use of the log (forensics, replay, "what did the agent change last Tuesday")
  is then confidently wrong.
* A tool refuses and logs nothing. The control worked and left no evidence,
  which is indistinguishable from the control never having been reached.

Each case pairs an action with ground truth read from the stub state, then
compares the record against that truth rather than against the response.

One documented asymmetry is pinned here rather than glossed over: a tool that
returns a controller-side error envelope (a missing id, a rejected payload)
is recorded with ``success: true``, because the dispatch itself succeeded and
``success`` reflects whether the tool body raised. The error text lives inside
the recorded ``result``. ``test_error_envelope_is_logged_as_a_dispatch`` asserts
that behaviour so nobody reads ``success: true`` as "the caller got what they
asked for".
"""

from __future__ import annotations

from typing import Any

from evals.harness import HarnessSession, eval_server, payload_of
from evals.scoring import CaseResult, ClassResult
from mcp_unifi.redaction import REDACTED
from mcp_unifi.scoping import DENIED_BY_READONLY

#: Not a credential. A literal used to prove the scrubber fires before the sink.
EVAL_PASSPHRASE = "eval-harness-passphrase-not-real"  # noqa: S105


async def run_audit_fidelity() -> ClassResult:
    """Run every audit-fidelity case and return the class result."""
    results: list[CaseResult] = []
    async with eval_server(readonly=False) as session:
        results.append(await _read_logs_one_true_record(session))
        results.append(await _write_record_matches_state(session))
        results.append(await _error_envelope_is_logged_as_a_dispatch(session))
        results.append(await _secret_never_reaches_the_sink(session))
        results.append(await _preview_is_not_logged_as_a_completed_delete(session))
        results.append(await _no_phantom_records(session))
    async with eval_server(readonly=True) as session:
        results.append(await _refusal_is_logged_exactly_once(session))
        results.append(await _permitted_read_carries_no_denial(session))
    return ClassResult(name="audit_fidelity", deterministic=True, cases=results)


def _only(session: HarnessSession, tool: str) -> dict[str, Any] | None:
    records = session.records_for(tool)
    return records[-1] if records else None


async def _read_logs_one_true_record(session: HarnessSession) -> CaseResult:
    """A plain read must produce one record whose envelope matches the call."""
    case = "read_logs_one_true_record"
    payload = payload_of(await session.client.call_tool("list_networks", {}))
    records = session.records_for("list_networks")
    if len(records) != 1:
        return CaseResult(case, False, "record_count", f"expected 1 record, got {len(records)}")
    record = records[0]
    if record.get("success") is not True or record.get("denied_by") is not None:
        return CaseResult(case, False, "wrong_envelope", f"success/denied_by: {record}")
    if record.get("controller") != "default":
        return CaseResult(case, False, "wrong_controller", str(record.get("controller")))
    if not isinstance(record.get("latency_ms"), int | float):
        return CaseResult(case, False, "no_latency", "latency_ms is not numeric")
    if not isinstance(payload, list) or len(record.get("result") or []) != len(payload):
        return CaseResult(case, False, "result_mismatch", "logged result differs from the response")
    return CaseResult(case, True, "match", "one record, envelope and result agree with the call")


async def _write_record_matches_state(session: HarnessSession) -> CaseResult:
    """A successful mutation must be logged, and the state must actually have moved."""
    case = "write_record_matches_state"
    before = session.network_names()
    await session.client.call_tool(
        "create_vlan", {"name": "EvalAudit", "vlan_id": 142, "subnet": "10.0.142.0/24"}
    )
    record = _only(session, "create_vlan")
    if record is None:
        return CaseResult(case, False, "no_record", "the mutation was not audited at all")
    changed = session.network_names() - before
    if changed != {"EvalAudit"}:
        return CaseResult(case, False, "state_mismatch", f"stub state changed by {sorted(changed)}")
    if record.get("success") is not True:
        return CaseResult(case, False, "wrong_envelope", "a successful write logged success=false")
    if record.get("args", {}).get("name") != "EvalAudit":
        return CaseResult(case, False, "args_mismatch", "logged args do not match what was sent")
    return CaseResult(case, True, "match", "record and controller state agree")


async def _error_envelope_is_logged_as_a_dispatch(session: HarnessSession) -> CaseResult:
    """A controller-side error is a completed dispatch carrying an error result.

    Pinned deliberately. ``success`` answers "did the tool body raise", not
    "did the caller get what they wanted", and the difference matters to anyone
    counting failures out of this log.
    """
    case = "error_envelope_is_logged_as_a_dispatch"
    payload = payload_of(
        await session.client.call_tool("get_network_details", {"network_id": "no-such-id"})
    )
    record = _only(session, "get_network_details")
    if record is None:
        return CaseResult(case, False, "no_record", "an errored call was not audited")
    if not isinstance(payload, dict) or "error" not in payload:
        return CaseResult(case, False, "unexpected_response", "expected an error envelope")
    logged = record.get("result")
    if not isinstance(logged, dict) or logged.get("error") != payload["error"]:
        return CaseResult(case, False, "result_mismatch", "the error text was not recorded")
    if record.get("success") is not True or record.get("denied_by") is not None:
        return CaseResult(case, False, "wrong_envelope", "dispatch classification changed")
    return CaseResult(case, True, "match", "error text recorded, dispatch classified unchanged")


async def _secret_never_reaches_the_sink(session: HarnessSession) -> CaseResult:
    """The passphrase must be redacted in the record and absent from the file."""
    case = "secret_never_reaches_the_sink"
    await session.client.call_tool(
        "create_wlan",
        {
            "name": "EvalAuditWlan",
            "passphrase": EVAL_PASSPHRASE,
            "network_id": "5f54c89b4b794a09a3509a33",
        },
    )
    record = _only(session, "create_wlan")
    if record is None:
        return CaseResult(case, False, "no_record", "the call was not audited")
    if record.get("args", {}).get("passphrase") != REDACTED:
        return CaseResult(case, False, "not_redacted", "the passphrase survived into the record")
    if EVAL_PASSPHRASE in session.audit_path.read_text(encoding="utf-8"):
        return CaseResult(case, False, "leaked_to_disk", "the passphrase is in the sink file")
    return CaseResult(case, True, "match", "redacted in the record and absent from the file")


async def _preview_is_not_logged_as_a_completed_delete(session: HarnessSession) -> CaseResult:
    """The first half of a two-step delete must not read as a deletion.

    ``delete_vlan`` queues rather than deletes. If the record made that look
    like a completed removal, an operator reading the log would believe a VLAN
    is gone while it is still serving traffic.
    """
    case = "preview_is_not_logged_as_a_completed_delete"
    created = payload_of(
        await session.client.call_tool(
            "create_vlan", {"name": "EvalPreview", "vlan_id": 143, "subnet": "10.0.143.0/24"}
        )
    )
    if not isinstance(created, dict) or "_id" not in created:
        return CaseResult(case, False, "setup_failed", "could not create a VLAN to preview")
    before = session.network_names()
    payload = payload_of(
        await session.client.call_tool("delete_vlan", {"network_id": created["_id"]})
    )
    record = _only(session, "delete_vlan")
    if record is None:
        return CaseResult(case, False, "no_record", "the preview was not audited")
    if session.network_names() != before:
        return CaseResult(case, False, "state_changed", "the preview deleted something")
    logged = record.get("result")
    if not isinstance(payload, dict) or payload.get("preview") is not True:
        return CaseResult(case, False, "unexpected_response", "expected a preview envelope")
    if not isinstance(logged, dict) or logged.get("preview") is not True:
        return CaseResult(
            case, False, "result_mismatch", "the record does not say it was a preview"
        )
    return CaseResult(case, True, "match", "recorded as a preview, nothing deleted")


async def _no_phantom_records(session: HarnessSession) -> CaseResult:
    """One call in, one record out. No duplicates, no invented entries."""
    case = "no_phantom_records"
    before = len(session.audit_records())
    await session.client.call_tool("list_clients", {})
    await session.client.call_tool("list_devices", {})
    after = len(session.audit_records())
    if after - before != 2:
        return CaseResult(case, False, "record_count", f"2 calls produced {after - before} records")
    return CaseResult(case, True, "match", "two calls, two records")


async def _refusal_is_logged_exactly_once(session: HarnessSession) -> CaseResult:
    """A refused mutation must leave one record naming the control that refused it."""
    case = "refusal_is_logged_exactly_once"
    await session.client.call_tool("delete_firewall_rule", {"rule_id": "d3c8614ed2334da2adc09bc5"})
    records = session.records_for("delete_firewall_rule")
    if len(records) != 1:
        return CaseResult(case, False, "record_count", f"expected 1 record, got {len(records)}")
    record = records[0]
    if record.get("denied_by") != DENIED_BY_READONLY:
        return CaseResult(case, False, "wrong_denied_by", str(record.get("denied_by")))
    if record.get("success") is not False or record.get("result") is not None:
        return CaseResult(case, False, "wrong_envelope", "a refusal recorded a result")
    if not record.get("error"):
        return CaseResult(case, False, "no_reason", "the refusal recorded no reason")
    return CaseResult(case, True, "match", "one record, denied_by names the write gate")


async def _permitted_read_carries_no_denial(session: HarnessSession) -> CaseResult:
    """``denied_by`` must isolate blocked attempts, so a permitted call must not set it."""
    case = "permitted_read_carries_no_denial"
    await session.client.call_tool("list_wlans", {})
    record = _only(session, "list_wlans")
    if record is None:
        return CaseResult(case, False, "no_record", "the read was not audited")
    if record.get("denied_by") is not None:
        return CaseResult(case, False, "false_denial", "a permitted read was marked as denied")
    if record.get("success") is not True:
        return CaseResult(case, False, "wrong_envelope", "a permitted read logged success=false")
    return CaseResult(case, True, "match", "denied_by is null on a dispatched call")


__all__ = ["EVAL_PASSPHRASE", "run_audit_fidelity"]
