# 0006. `denied_by` is a separate audit field, not a convention on `error`

**Status:** Accepted (v0.21.0)

## Context

Every tool call emits one `AuditEvent` as a JSON line
(`src/mcp_unifi/audit.py`). The envelope carries `success: bool` and
`error: str | None`.

Two controls can refuse a call before the tool body runs: the read-only write gate
(ADR 0001) and per-client module scoping. Both need to appear in the audit log,
because a control that keeps no record of what it denied is only half a control.

The problem is that `success: false` already means three different things in this
log:

1. The tool body raised.
2. The controller returned an error.
3. The call was never made, because a control refused it.

Only the third is a security event. Nothing in `success` or `error` distinguishes
it.

## Decision

Add `denied_by: str | None` to the audit envelope. It carries `"readonly"` for the
write gate and `"scope"` for per-client module scoping (`DENIED_BY_READONLY` and
`DENIED_BY_SCOPE` in `src/mcp_unifi/scoping.py`), and is `None` on every call that
was actually dispatched.

The security query becomes `jq 'select(.denied_by)'`.

The two values are kept distinct rather than collapsed to a boolean because the
operator's response to each differs: read-only is a property of the server, so the
fix is "turn the posture off", while scope is a property of the caller, so the fix
is "widen this client's token".

## Alternatives considered

**A prefix or marker convention on `error`,** for example `"REFUSED: ..."`.
Rejected. It makes the security query a regex over prose. Prose gets reworded, gets
translated, gets a variable interpolated into the middle of it, and the regex
quietly stops matching with nothing failing. A structured field either exists or
does not.

**Deriving refusals from `success: false` plus an absent `result`.** Rejected: it
is inference over an envelope that was never designed to carry that distinction,
and it would also catch tools that raised before producing a result.

**A separate refusal log file.** Rejected. Refusals and dispatched calls belong in
one ordered stream, because the interesting question is usually what a caller did
immediately before or after being refused.

## The deliberate asymmetry, and why it is not an oversight

The message the client sees and the record the operator sees are intentionally
different.

On a scope refusal the client gets: `Tool 'x' is not available to this client.`
That is all. It does not say which module the tool belongs to, that modules exist,
or which ones this client can reach. A scoped client that could read a specific
denial message could enumerate the whole tool surface by brute-forcing names and
diffing the responses. Vagueness is the control.

The audit record for the same refusal is the opposite side of that wall. It names
the control (`denied_by: "scope"`), names the mechanism in `error`
(`Refused by per-client module scoping (MCP_UNIFI_AUTH_TOKENS)`), states that no
call reached the controller, and records the tool name and the arguments, scrubbed
of secrets. The operator reading the log is entitled to detail the caller is not.

Anyone tempted to "fix" the unhelpful client message by making it specific would be
removing a control, not improving an error string.

## Replay reads this field, and that is a safety property

`mcp-unifi-replay` (`src/mcp_unifi/cli/replay.py`) skips any event with
`denied_by` set, recording it as skipped with the reason
`refused at capture time by <control>; never dispatched`.

This does not belong in a section of its own, because it is not a separate
decision. It is the reason the field has to be structured. Replaying a refused
delete would perform the exact action the operator's own policy blocked, which
would turn the audit log into a way to launder a denial. A replay tool that had to
decide by matching a substring in `error` would do that the first time the message
was reworded.

## Consequences and accepted costs

- One more field on every audit line, `null` on the overwhelming majority of them.
- The envelope's `schema` version stays at `"1"`. Older logs missing the field
  parse via the dataclass default, so `denied_by` reads as `None` for them.
  **A log written before v0.21.0 is indistinguishable from one where nothing was
  ever refused.** Anyone reasoning about historical refusal rates has to check the
  server version that produced the log.
- Every future control that can refuse a call has to remember to set this field, or
  its refusals become invisible to the standard query. Nothing enforces that today.
  The `DENIED_BY_*` constants live next to each other in `scoping.py` partly to
  make the omission visible on review.
- The vague client-facing message costs debuggability. An operator debugging a
  legitimately-scoped client sees an unhelpful error and has to go to the audit log
  to learn why.

## Reversal condition

Split `denied_by` into a richer structure, for example `{control, policy_id,
subject}`, when **a third refusing control lands** and the flat string stops
carrying enough to answer "why". Two values fit in a string. Five, with per-policy
identifiers, do not.

Bump the `schema` version at the same time, which is the change that would let a
consumer tell "no refusals" apart from "a server too old to record them".

Fold it back into `error` under no condition. The regex-over-prose failure mode is
the reason the field exists, and the replay skip depends on it being structured.
