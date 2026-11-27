#!/bin/sh
# Export a clean tree for the public repository: the files scripts/public-export.list selects,
# taken from one git ref with `git archive` (no history, no untracked files), then leak-scanned.
#
#   scripts/public-export.sh [--no-scan] <out-dir> [<ref>]
#
# <out-dir>  must not exist or be empty. <ref> defaults to HEAD. The list is read from the ref
#            itself, so what is exported is exactly what was reviewed at that ref.
# Then public/overlay/<path> (public-only files) is copied over <path>.
# Exit 0 only when the export is written and scripts/public-leak-scan.sh finds nothing.
set -eu
SCAN=1; [ "${1:-}" = --no-scan ] && { SCAN=0; shift; }
[ $# -ge 1 ] || { sed -n '2,10p' "$0" >&2; exit 2; }
OUT=$1 REF=${2:-HEAD}
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fail() { echo "public-export: $*" >&2; exit 1; }
cd "$ROOT"

git rev-parse -q --verify "$REF^{commit}" >/dev/null || fail "unknown ref $REF"
if [ -e "$OUT" ]; then
  [ -d "$OUT" ] && [ -z "$(ls -A "$OUT")" ] || fail "$OUT exists and is not an empty folder"
fi
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

LIST="$(mktemp)"; PATHS="$(mktemp)"
trap 'rm -f "$LIST" "$PATHS"' EXIT
git show "$REF:scripts/public-export.list" >"$LIST" 2>/dev/null \
  || fail "$REF has no scripts/public-export.list"

git ls-tree -r --name-only -z "$REF" | python3 -I "$ROOT/scripts/public-export-select.py" "$LIST" >"$PATHS"
COUNT=$(tr -cd '\0' <"$PATHS" | wc -c | tr -d ' ')
[ "$COUNT" -gt 0 ] || fail "the list selects no files"

# git archive takes the paths from a NUL-separated list via xargs, in batches; tar appends.
export COPYFILE_DISABLE=1
xargs -0 git archive --format=tar "$REF" -- <"$PATHS" | tar -x -C "$OUT"
GOT=$(cd "$OUT" && find . -type f -o -type l | wc -l | tr -d ' ')
[ "$GOT" -eq "$COUNT" ] || fail "selected $COUNT files but wrote $GOT (xargs split?)"

# Public-only files replace or add their path (README of docs/, the public TESTING guide...).
if git rev-parse -q --verify "$REF:public/overlay" >/dev/null; then
  OVL="$(mktemp -d)"
  git archive --format=tar "$REF" public/overlay | tar -x -C "$OVL"
  NOVL=$(cd "$OVL/public/overlay" && find . -type f | wc -l | tr -d ' ')
  cp -R "$OVL/public/overlay/." "$OUT/"
  rm -rf "$OVL"
  echo "public-export: $NOVL public-only file(s) from public/overlay"
fi
echo "public-export: $COUNT files from $(git rev-parse --short "$REF") into $OUT"

[ "$SCAN" -eq 1 ] || exit 0
sh "$ROOT/scripts/public-leak-scan.sh" "$OUT"
