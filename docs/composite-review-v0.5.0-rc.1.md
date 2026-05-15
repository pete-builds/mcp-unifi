# Composite Review — v0.5.0-rc.1

**Phase 2, Part D**: closing the audit loop on every composite tool. Read-through
verification that what Part A eyeballed and Part C documented is actually true
in the source. No behavior changes made; one cross-cutting consistency
observation flagged for Pete (does not block release).

**Reviewer**: Forge
**Date**: 2026-05-14
**Scope**: 6 composites — 5 destructive, 1 read-only.
**Source files**:
- `src/mcp_unifi/modules/network/composites.py` (5 composites)
- `src/mcp_unifi/modules/network/backup.py` (`restore_config`)

## 7-checklist

For each composite the verdict columns are:

1. `controller` param wired through `registry.get(controller)`
2. `dry_run` param present (destructive composites only)
3. Dry-run early-returns with `would_create` / `would_apply` and **no** mutation
4. Rollback runs in reverse order; sub-step errors are caught and surfaced
5. Error messages name the failed step + resource type
6. No silent fallbacks (controller errors error; unknown targets error)
7. Audit emit on rollback is coherent (decorator + composite contract together)

---

## 1. `create_iot_network`

`composites.py:63-249`

| # | Check | Verdict | Detail |
|---|-------|---------|--------|
| 1 | controller param | ✓ | Line 73 declares; line 178 calls `registry.get(controller)` |
| 2 | dry_run param | ✓ | Line 74; checked at line 154 |
| 3 | Dry-run no mutation | ✓ | Lines 154-176 build `would_create` from local payloads only, return before any backend call |
| 4 | Rollback reverse order | ✓ | `_rollback` (lines 185-200): firewall_rule → wlan → network. `_delete_resource` catches `UniFiError` and logs to `logger.error` (lines 52-57) — surfaced, not silent |
| 5 | Error names step | ✓ | `f"create_iot_network failed at {step}: {exc}"` (line 206). `step` ∈ `{"vlan", "wlan", "firewall_rule"}` |
| 6 | No silent fallbacks | ⚠️ | Sub-step `UniFiError` → caught + rollback. **Unknown controller** (`UnknownControllerError`, a `KeyError` subclass) is NOT caught at line 178; raw exception propagates through `@audited` → FastMCP. Errors clearly, but with a different envelope shape than `restore_config`. See cross-cutting note. |
| 7 | Audit on rollback | ✓ | Composite catches `UniFiError`, returns `format_json({"error": ..., "rolled_back": [...]})`. `@audited` sees `success=True` with an error-shaped string result — same convention as `make_err`-wrapped tools throughout the codebase. The `logger.warning("create_iot_network rolled back", ...)` line (196) gives operators a separate structured trail of the undo events. |

Sample error message (verbatim from source line 206):
```python
f"create_iot_network failed at {step}: {exc}"
```
Realised at runtime as e.g. `"create_iot_network failed at wlan: 400 Bad Request: SSID already exists"`.

**Verdict: SAFE.**

---

## 2. `create_guest_network`

`composites.py:485-669`

| # | Check | Verdict | Detail |
|---|-------|---------|--------|
| 1 | controller param | ✓ | Line 496; line 602 |
| 2 | dry_run param | ✓ | Line 497; line 580 |
| 3 | Dry-run no mutation | ✓ | Lines 580-600 return before any backend call. Note: guest variant always builds `fw_payload` (isolation rule mandatory), unlike IoT |
| 4 | Rollback reverse order | ✓ | `_rollback` (lines 609-624): firewall_rule → wlan → network. Same `_delete_resource` helper |
| 5 | Error names step | ✓ | `f"create_guest_network failed at {step}: {exc}"` (line 630). Step ∈ `{"vlan", "wlan", "firewall_rule"}` |
| 6 | No silent fallbacks | ⚠️ | Same cross-cutting note as `create_iot_network`: unknown-controller raises raw |
| 7 | Audit on rollback | ✓ | Same pattern as `create_iot_network`. `logger.warning("create_guest_network rolled back", ...)` at line 620 |

Sample error message (verbatim from source line 630):
```python
f"create_guest_network failed at {step}: {exc}"
```

**Verdict: SAFE.**

---

## 3. `provision_homelab_service`

`composites.py:251-423`

| # | Check | Verdict | Detail |
|---|-------|---------|--------|
| 1 | controller param | ✓ | Line 260; line 357 |
| 2 | dry_run param | ✓ | Line 261; line 335 |
| 3 | Dry-run no mutation | ✓ | Lines 335-355 build local payloads only. Returns before backend call. |
| 4 | Rollback reverse order | ✓ | `_rollback` (lines 364-381): port_forwards (reversed) → firewall_rule → lease. The `for pf in reversed(created["port_forwards"])` (line 366) is the right call — multi-port wan-expose creates multiple port forwards, undo them newest-first |
| 5 | Error names step | ✓ | `f"provision_homelab_service failed at {step}: {exc}"` (line 387). Step ∈ `{"lease", "firewall_rule", "port_forward"}` |
| 6 | No silent fallbacks | ⚠️ | Same cross-cutting note |
| 7 | Audit on rollback | ✓ | Same pattern. `logger.warning("provision_homelab_service rolled back", ...)` line 377 |

Sample error message (verbatim from source line 387):
```python
f"provision_homelab_service failed at {step}: {exc}"
```

**Verdict: SAFE.**

---

## 4. `quarantine_client`

`composites.py:425-483`

| # | Check | Verdict | Detail |
|---|-------|---------|--------|
| 1 | controller param | ✓ | Line 430; line 472 |
| 2 | dry_run param | ✓ | Line 431; line 458 |
| 3 | Dry-run no mutation | ✓ | Lines 458-470 return before backend call |
| 4 | Rollback reverse order | ✓ (degenerate) | Single mutating step (`block_client`); the WARNING log entry afterwards is best-effort and not unwound. Description (lines 442-446) explicitly calls out "the log entry is best-effort and not unwound; only step 1 mutates the controller." Rollback contract is documented honestly |
| 5 | Error names step | ✓ | Two failure modes: unknown MAC → `err(f"client {mac} not found")` (line 475); UniFiError → `err(str(exc))` (line 483). Both name the operation context (the tool name lives in the audit envelope and the structured log line at 482) |
| 6 | No silent fallbacks | ✓ | Unknown MAC → explicit `"client {mac} not found"` error, NOT a silent no-op. UniFiError on `block_client` → caught and surfaced. Cross-cutting unknown-controller note still applies (`registry.get(controller)` is inside the `try`, but raises a `KeyError` subclass that `except UniFiError` doesn't catch — propagates to `@audited`) |
| 7 | Audit on rollback | ✓ | No multi-step rollback to coordinate. `@audited` sees the `err(...)` envelope as `success=True` with error-shaped result on the "not found" path; sees the raised+caught UniFiError as `success=False` only when the exception escapes (it doesn't here — line 483 catches and returns). Consistent with codebase convention |

Sample error messages (verbatim):
```python
err(f"client {mac} not found")            # line 475
err(str(exc))                              # line 483 — UniFiError text
```

**Verdict: SAFE.**

---

## 5. `audit_open_ports` (read-only)

`composites.py:671-726`

| # | Check | Verdict | Detail |
|---|-------|---------|--------|
| 1 | controller param | ✓ | Line 673; line 694 |
| 2 | dry_run param | N/A | Read-only |
| 3 | Dry-run no mutation | N/A | Read-only |
| 4 | Rollback reverse order | N/A | Read-only |
| 5 | Error names step | ✓ | Single try block; UniFiError → `err(str(exc))` (line 726) after `logger.exception("audit_open_ports failed")` (line 725). Tool name lives in the structured log line + audit envelope |
| 6 | No silent fallbacks | ✓ | Confirms brief: on controller-unreachable, returns `err(...)` envelope, NOT empty `port_forwards` / `wan_accept_rules` lists. The boilerplate-rule filter (lines 706-709) excludes only the established/related accept — that's a deliberate filter, not a silent skip |
| 7 | Audit on rollback | N/A | No mutation, no rollback |

Sample error message (verbatim from source line 726):
```python
err(str(exc))
```
Realised at runtime as e.g. `"unifi error: 401 Unauthorized"` (envelope shape from `make_err`).

**Verdict: SAFE.**

---

## 6. `restore_config` (Phase 2 Part B addition)

`backup.py:425-719`

| # | Check | Verdict | Detail |
|---|-------|---------|--------|
| 1 | controller param | ✓ | Line 429; line 522 (with explicit `except KeyError` envelope at 523-524) |
| 2 | dry_run param | ✓ | Line 430; line 549 |
| 3 | Dry-run no mutation | ✓ | Lines 549-563 build the action plan from the snapshot + envelope, return before any create/delete dispatch. Plan generation (`_plan`, lines 223-291) is pure — no backend writes. Verified with regression test `test_dry_run_never_mutates` (line 297 in test file) |
| 4 | Rollback reverse order | ✓ | `_rollback` (lines 580-613): iterates `reversed(created_for_rollback)`. Per-record delete in a try/except UniFiError block (594-607) — failure is logged + recorded as `{"deleted": False}`, never silently dropped. Final `logger.warning("restore_config rolled back", ...)` line 609 |
| 5 | Error names step | ✓ | `f"restore_config failed: {exc}"` (line 697). Action context (which create/delete failed) lives in the `partial` list (each entry carries `action`, `type`, `name`, plus the result so far) and the `rolled_back` list. Operator can reconstruct the failed step from `partial[-1]` |
| 6 | No silent fallbacks | ✓ | Schema mismatch → explicit error (line 481). Malformed JSON → explicit error (line 472). Missing/non-list resources section → explicit error (line 488/495/500). Unknown controller → explicit error envelope (line 524). Live snapshot failure → explicit error envelope (line 538). The "deletes already executed are not undone" gap is **declared in the description** (lines 451-454) and surfaced in the response (`partial` list shows what got deleted). Documented honesty, not silent fallthrough |
| 7 | Audit on rollback | ✓ | Same convention: composite catches UniFiError at apply time (line 692), runs `_rollback`, returns error envelope. `@audited` sees `success=True` with error-shaped result. Two structured log lines on the rollback path: `logger.exception("restore_config: apply failed")` (line 693) and `logger.warning("restore_config rolled back", ...)` (line 609) |

Sample error message (verbatim from source line 697):
```python
f"restore_config failed: {exc}"
```

**Verdict: SAFE.**

---

## Cross-cutting observation (does not block release)

**Inconsistent unknown-controller handling between `composites.py` and `backup.py`.**

`backup.py` wraps `registry.get(controller)` in `try/except KeyError` and returns
a clean `err(...)` envelope (e.g. `backup.py:387-389`, `522-524`). All four
destructive composites in `composites.py` (and `audit_open_ports`) do NOT — the
`UnknownControllerError` (a `KeyError` subclass per `dispatcher.py:39`) raises out
of the `try` block, propagates through `@audited` (which records `success=False`
and re-raises), and reaches FastMCP as a raw exception.

**Why it doesn't block release**: both paths fail loudly and surface the error
to the caller. The only difference is the envelope shape:
- `restore_config`: `{"error": "Unknown controller 'foo'. Available: default."}`
- `create_iot_network`: raw `UnknownControllerError` propagating up the FastMCP stack

**Why I flag it**: the intent of `make_err` + `err(...)` envelopes throughout
the codebase is "tools never raise; they return envelope." The composites
deviate from that intent for a single error mode. A one-liner `try/except`
around each `registry.get(controller)` call would normalise the contract.

**Recommendation**: not in this Phase 2 pass (behavior change). Track for v0.5.x.

---

## Summary

**All 6 composites verified safe.**

- 6 / 6 dry-run paths early-return without mutation (verified by source read; backup.py also covered by `test_dry_run_never_mutates`).
- 5 / 5 destructive composites have a coherent rollback in reverse-creation order with caught + logged sub-step failures.
- 6 / 6 error messages name the tool + step/context.
- 0 silent fallbacks. The one declared "no undo" path (`restore_config` deletes-already-executed) is documented in the tool description and surfaced in the response payload.
- 6 / 6 audit emit + rollback contracts are coherent under the existing `@audited` + `make_err` convention.

**No edits made. No regression tests added. No deploy.**

**Cross-cutting note for v0.5.x backlog**: normalise unknown-controller handling
in `composites.py` to match the `try/except KeyError → err(...)` pattern in
`backup.py`. Description-only — does not block Phase 3.

**Phase 2 complete. Ready for Phase 3.**
