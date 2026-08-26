# Architecture Decision Records

Records of decisions already made in this codebase, written so a reader can see
the alternatives that were considered, why the losers lost, and what would change
the answer.

Every record carries a **reversal condition**: the concrete, checkable thing that
would make this decision wrong. A record without one is a rationalisation, so if a
future ADR here lacks one, it is not finished.

Where a decision has a real downside, the record names it under **Consequences and
accepted costs**. A decision with no downside listed has not been examined.

| # | Decision | Status |
|---|---|---|
| [0001](0001-explicit-write-classification.md) | Classify tools as mutating by explicit declaration, not by name prefix | Accepted |
| [0002](0002-shared-substrate-stays-off-pypi.md) | Keep the shared MCP substrate off PyPI | Accepted (fleet-level; this repo is not a consumer) |
| [0003](0003-verify-ssl-defaults-off.md) | `verify_ssl` defaults to `false` | Accepted |
| [0004](0004-confirm-token-is-ceremony-not-consent.md) | The confirm-token handshake is ceremony, not consent | Interim control, known inadequate |
| [0005](0005-writes-stay-on-the-private-network-api.md) | Writes stay on the private UniFi Network API | Accepted, with an outstanding documentation task |
| [0006](0006-denied-by-is-a-separate-audit-field.md) | `denied_by` is a separate audit field, not a convention on `error` | Accepted |

## Template

New records use the same six sections:

```markdown
# NNNN. Title in the imperative or as a statement of the decision

**Status:** Proposed | Accepted | Superseded by NNNN | Interim, with a stated inadequacy

## Context
What forced a decision. Facts, measurements, constraints.

## Decision
What was chosen, and where it lives in the code.

## Alternatives considered
Each one that was genuinely on the table, and the specific reason it lost.
"It was worse" is not a reason.

## Consequences and accepted costs
What this decision costs. Name the downside plainly.

## Reversal condition
The concrete thing that would make this decision wrong, stated so someone could
check it later without asking the author.
```

## Conventions

- Numbers are sequential and never reused. A superseded record stays in place with
  its status updated, pointing at the record that replaced it.
- Records describe decisions **already made in the code**. They are not proposals.
- Claims are verified against the code at the time of writing. Where something
  could not be verified, the record says so rather than implying a verification
  that did not happen.
