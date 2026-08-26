# 0001. Classify tools as mutating by explicit declaration, not by name prefix

**Status:** Accepted (v0.21.0)

## Context

`MCP_UNIFI_READONLY=true` is meant to make the server structurally unable to
change anything: mutating tools are hidden from `tools/list` and refused on
`tools/call`. That control needs to answer one question for every tool: does
calling this change state outside this process?

The server registers 134 tools across the `network`, `protect`, and `access`
modules. 62 of them mutate. The question has to be answered for all 134, and it
has to keep being answered correctly for every tool added later, by whoever adds
it.

The original scope proposed answering it from the tool name, gating anything
starting with `create_`, `update_`, `delete_`, `set_`, `provision_`, `apply_`, or
`reboot`.

## Decision

`mutates: bool` is a **required keyword-only argument** on the `@audited()`
decorator that every tool already carries, declared at the registration site next
to the tool body. Three layers enforce it:

1. **Import time.** Omitting `mutates=` raises `TypeError` from Python itself.
   There is no default, so a new tool cannot quietly inherit "read-only".
2. **Registration time.** `register_modules()` in `src/mcp_unifi/dispatcher.py`
   raises `UnclassifiedToolError` if a registered tool has no declaration, or if
   the tool list cannot be enumerated at all (which would make tagging a silent
   no-op). The server refuses to boot in either case.
3. **CI.** `tests/test_write_gate.py::test_every_registered_tool_is_classified`
   enumerates the live registration rather than any hand-maintained list, and
   fails if anything is unclassified.

A fourth guard, `ToolClassificationConflictError`, refuses registration when one
tool name is declared with two different `mutates` values.

## Alternatives considered

**Name-prefix classification.** Rejected on measurement, not on taste. Enumerating
the live registration shows **twelve mutating tools carry none of those prefixes**:
`block_client`, `confirm_destructive_action`, `locate_device`, `quarantine_client`,
`reconnect_client`, `rename_device`, `restart_device`, `restore_config`,
`toggle_traffic_route`, `toggle_traffic_rule`, `trigger_speedtest`, and
`unblock_client`.

`confirm_destructive_action` is the one that kills the idea outright. It executes a
delete that was queued by an earlier preview call. A prefix gate would have shipped
a "read-only" mode that still commits previewed deletions, which is worse than no
read-only mode at all because it reads as a guarantee. That specific case is pinned
by its own test, `test_confirm_destructive_action_is_mutating`.

The full pin list in the test carries thirteen names. The thirteenth,
`backup_config`, is a pure read that a prefix gate would also have miscategorised,
in the harmless direction. Both directions are asserted so the test stays honest
about which is which.

**An attribute on the wrapped function.** Rejected on mechanism: FastMCP re-wraps
tool callables during registration, so an attribute set by the decorator is not
guaranteed to survive onto `Tool.fn`. Classification is instead held in a
process-level registry keyed by tool name, which is what the dispatcher reads when
it tags tools and what the completeness test enumerates.

**A separate allowlist or denylist file.** Rejected because it splits the
classification from the code it describes. A reviewer would have to remember to
open a second file, and nothing would fail if they did not.

## Consequences and accepted costs

- Every new tool costs one extra argument and one extra decision at write time.
  That is the point, but it is still friction on every contribution.
- Classification is a human judgement call, and the guards catch *missing*
  declarations, not *wrong* ones. A tool declared `mutates=False` that actually
  writes would pass all three layers. Nothing in the repo detects that today.
- The registry is keyed by tool name and is process-global, so tool names must stay
  globally unique across modules. `ToolClassificationConflictError` enforces this,
  but it constrains module authors.
- `_iter_registered_tools()` reads FastMCP's `_local_provider._components`, a
  private attribute. A FastMCP upgrade that changes that shape degrades tagging to
  a no-op, which is exactly why the empty-enumeration case raises rather than
  returning quietly.

## Reversal condition

Revisit if **MCP or FastMCP grows a first-class read/write annotation on tool
definitions** that clients and servers both understand. At that point the local
registry becomes a private reimplementation of a protocol feature, and the
declaration should move onto the standard annotation with the dispatcher reading
that instead.

A weaker trigger: if `_local_provider._components` breaks across a FastMCP major
version and no supported enumeration API replaces it, layer 2 has to be rebuilt on
whatever the SDK does expose, and this record should be rewritten rather than
patched.

Prefix classification does not come back under any condition. The twelve tools
above are the proof, and they are pinned in CI so nobody rederives the shortcut and
finds the tests still green.
