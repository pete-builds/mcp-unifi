#!/usr/bin/env bash
# Regenerate every uv lockfile in this repo from the command recorded in its own header.
#
# Layer 3: deterministic, no reasoning, testable in isolation. The workflow that calls this
# only supplies the environment and turns the result into a pull request.
#
# WHY THE COMMAND IS READ OUT OF THE LOCK
#   The fleet does not share one compile command. Two variants are live today
#   (`--universal` vs `--python-platform linux`). A hardcoded command would silently produce
#   a lock this repo's own CI rejects. uv writes the exact command it used into the lock
#   header, so the header is the authoritative per-repo answer. A lock with no uv header is
#   SKIPPED and named, never guessed at.
#
# WHY IT COMPILES TO A TEMP PATH AND MOVES
#   `uv pip compile -o <existing lock>` reads that lock as PREFERENCES and keeps old pins,
#   so it can report success having changed nothing. The drift check compiles to a fresh
#   path, so the two resolutions differ. Compiling fresh and moving is what the check does,
#   which makes agreement structural instead of dependent on remembering `--upgrade`.
#
# Outputs (to stdout, as key=value lines for the caller):
#   changed=<space-separated lock paths>
#   skipped=<space-separated lock paths with no uv header>
#
# Exit: 0 nothing to do or locks updated, 1 a real error (never a silent pass).

set -euo pipefail

changed=""
skipped=""
deltas=""

for lock in $(git ls-files '*.lock' | sort); do
  cmd="$(sed -n 's/^#[[:space:]]*\(uv pip compile .*\)$/\1/p' "$lock" | head -1)"
  if [ -z "$cmd" ]; then
    # NEVER GUESS. A lock with no uv header may not be a uv lock at all.
    skipped="$skipped $lock"
    continue
  fi

  fresh="$(mktemp)"; rm -f "$fresh"
  regen="$(printf '%s' "$cmd" | sed -E "s#-o[[:space:]]+[^[:space:]]+#-o $fresh#")"
  if [ "$regen" = "$cmd" ]; then
    echo "error: could not find the -o target in: $cmd" >&2
    exit 1
  fi

  eval "$regen --quiet"
  # An empty or missing output must never be compared against, or the diff below would
  # "pass" while comparing nothing.
  test -s "$fresh"

  if diff -q <(grep -v '^#' "$lock") <(grep -v '^#' "$fresh") >/dev/null; then
    continue
  fi

  # PROOF, NOT ASSUMPTION. Compile a second time from scratch and require the two fresh
  # resolutions to agree before committing either. If they disagree, the resolution is not
  # deterministic right now and a PR would only move a red check to another branch.
  #
  # Compared with comments STRIPPED, exactly as the drift check compares. uv records its own
  # command line (including the -o path) in the header, so two runs to two temp paths always
  # differ on that line while resolving identically. Comparing whole files made this guard
  # fire on every healthy repo, turning the loop into a no-op that read as a strict check.
  second="$(mktemp)"; rm -f "$second"
  eval "$(printf '%s' "$cmd" | sed -E "s#-o[[:space:]]+[^[:space:]]+#-o $second#") --quiet"
  test -s "$second"
  if ! diff -q <(grep -v '^#' "$fresh") <(grep -v '^#' "$second") >/dev/null; then
    echo "error: $lock: two consecutive fresh compiles disagree; refusing to commit" >&2
    exit 1
  fi

  before="$(mktemp)"; cp "$lock" "$before"
  cp "$fresh" "$lock"

  # RESTORE THE HEADER. The fresh compile recorded `-o <tempfile>` in the lock's own header.
  # Committing that leaves a permanent reference to a path that never existed in the repo,
  # and because the drift check strips comments, CI stays green while it happens. It is also
  # self-propagating: the next run reads the -o target back out of this header.
  python3 - "$lock" "$cmd" <<'PY'
import re, sys
path, cmd = sys.argv[1], sys.argv[2]
text = open(path).read()
new, n = re.subn(r'(?m)^(#\s*)uv pip compile .*$', lambda m: m.group(1) + cmd, text, count=1)
if n != 1:
    sys.exit(f"could not restore the uv header in {path}")
open(path, 'w').write(new)
PY
  # Prove the restore landed rather than assuming it.
  grep -qF -- "$cmd" "$lock" || { echo "error: $lock: header restore failed" >&2; exit 1; }

  # SAY WHAT THIS ACTUALLY CHANGED, at package level.
  #
  # Not cosmetic. The fleet's CI checks come in two shapes: some recompile and diff the whole
  # lock, and some only verify that the `==` pins in requirements.in appear at the same
  # version in the lock. In the second kind, TRANSITIVE dependencies can drift arbitrarily
  # far and the check stays green, so a first run here can rewrite a thousand lines and bump
  # dozens of packages while CI reports success. That is a dependency upgrade, not a lock
  # sync, and the difference has to be visible in the PR rather than buried in a diff nobody
  # reads.
  delta="$(python3 - "$before" "$lock" <<'PY'
import re, sys
def pins(path):
    out = {}
    for line in open(path):
        m = re.match(r'^([A-Za-z0-9._-]+)==([^\s\\;]+)', line)
        if m:
            out[m.group(1).lower()] = m.group(2)
    return out
old, new = pins(sys.argv[1]), pins(sys.argv[2])
bumped = sorted(k for k in old.keys() & new.keys() if old[k] != new[k])
added = sorted(new.keys() - old.keys())
removed = sorted(old.keys() - new.keys())
sample = ", ".join(f"{k} {old[k]}->{new[k]}" for k in bumped[:5])
print(f"{len(bumped)} bumped, {len(added)} added, {len(removed)} removed"
      + (f" ({sample}{', ...' if len(bumped) > 5 else ''})" if sample else ""))
PY
)"
  echo "delta ${lock}: ${delta}" >&2
  deltas="${deltas}${deltas:+%0A}${lock}: ${delta}"

  changed="$changed $lock"
done

echo "changed=${changed# }"
echo "skipped=${skipped# }"
echo "deltas=${deltas}"
