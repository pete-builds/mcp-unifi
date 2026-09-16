# Upstream provenance

This repository starts from the upstream `pete-builds/mcp-unifi` project. The
baseline is intentionally pinned to an immutable commit; it must not be
updated by following `main`, `latest`, or an unpinned package/image reference.

## Pinned source

- Repository: https://github.com/pete-builds/mcp-unifi
- Commit: `97f057c42d02b127739e33689c1700dcf853e810`
- Baseline release metadata: `0.24.0`, commit subject `release: 0.24.0 (#150)`
- Local authoritative checkout: `TaltosLabs/taltos-unifi-mcp`, detached at the
  commit above when this record was created
- Upstream license: MIT; the complete upstream `LICENSE` file is retained

The commit is recorded by full object ID rather than by a mutable branch or
release alias. A later import must record a new full object ID and review the
diff before it is accepted.

## Imported material and divergence

The baseline retains the upstream source, tests, dependency manifests, build
metadata, documentation, examples, and license notices. The repository already
contains the `src/` package layout and `tests/` layout supplied by the pinned
baseline. This task adds repository-level provenance and safety documentation;
it does not add functional MCP tools, controller writes, deployment files, or
credentials.

At this baseline there is no separately approved `sirkirby` code import. No
ContextForge integration or other second upstream has been added.

The Taltos fork's deliberate divergence is therefore limited to attributable
repository scaffolding and future private development policy. Functional
changes must be recorded in subsequent task-specific diffs rather than being
silently mixed into this baseline record.

## Review rules for future imports

1. Reconfirm the full commit ID and license before copying material.
2. Preserve the applicable copyright and license notices in `LICENSE` and
   `NOTICE`.
3. Inspect dependencies and generated material for additional obligations.
4. Compare the imported tree with the previous baseline and record every
   material Taltos change.
5. Do not import code from another repository or track a mutable upstream
   reference without a separate approved task.
