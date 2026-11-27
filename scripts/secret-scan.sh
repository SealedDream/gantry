#!/bin/sh
# Secret scan for checkpoints and releases (docs/workflow/WORKFLOW.md, "Speed and security checks").
#   sh scripts/secret-scan.sh <commit>   lines added after <commit>, up to HEAD
#   sh scripts/secret-scan.sh --tree     every tracked file as it is now
# Prints file:line and the kind of secret, never the secret itself, so the output is safe to paste
# into an evidence file. Exits 1 when something is found, 2 on a usage error.
# The built-in patterns (scripts/secret-scan-patterns.txt) only match unambiguous formats: key
# blocks and provider tokens. When gitleaks is installed (brew install gitleaks), a commit range is
# also checked with its full rule set, which covers passwords and generic secrets.
# Skipped: files listed in scripts/secret-scan-allow.txt, and lines marked `gitleaks:allow`.
set -u
cd "$(dirname "$0")/.."
PATTERNS=scripts/secret-scan-patterns.txt
ALLOW=scripts/secret-scan-allow.txt
TAB=$(printf '\t')

mode=${1:-}
case "$mode" in
  '') echo "usage: sh scripts/secret-scan.sh <commit> | --tree" >&2; exit 2 ;;
  --tree) ;;
  *) git rev-parse --verify --quiet "$mode^{commit}" >/dev/null || { echo "secret-scan: not a commit: $mode" >&2; exit 2; } ;;
esac

tmp=$(mktemp -d) || exit 2
trap 'rm -rf "$tmp"' EXIT
grep -v '^#' "$ALLOW" | grep -v '^[[:space:]]*$' > "$tmp/allow"
: > "$tmp/loc"; : > "$tmp/text"

if [ "$mode" != --tree ]; then
  # Added lines: their text in one file, path:line at the same line number in another.
  git diff -U0 --no-color --no-ext-diff "$mode" HEAD | awk -v loc="$tmp/loc" -v txt="$tmp/text" '
    /^\+\+\+ / { f = substr($0, 7); next }
    /^@@ /     { split($3, a, ","); n = substr(a[1], 2) + 0; next }
    /^\+/      { print f ":" n > loc; print substr($0, 2) > txt; n++ }
  '
fi

grep -v '^#' "$PATTERNS" | grep -v '^[[:space:]]*$' | while IFS="$TAB" read -r name re; do
  if [ "$mode" = --tree ]; then
    git grep -n -I -E -e "$re" -- . 2>/dev/null | grep -v 'gitleaks:allow' | cut -d: -f1,2
  else
    grep -n -E -e "$re" "$tmp/text" | grep -v 'gitleaks:allow' | cut -d: -f1 |
      awk 'NR == FNR { want[$1] = 1; next } (FNR in want)' - "$tmp/loc"
  fi | while IFS= read -r where; do
    if [ -s "$tmp/allow" ] && printf '%s\n' "${where%%:*}" | grep -q -E -f "$tmp/allow"; then
      continue
    fi
    printf '%s: %s\n' "$where" "$name"
  done
done | sort -u > "$tmp/hits"

status=0
if [ -s "$tmp/hits" ]; then
  cat "$tmp/hits"
  echo "secret-scan: $(wc -l < "$tmp/hits" | tr -d ' ') finding(s). Remove a real secret and rotate it; list a fake test file in $ALLOW with the reason." >&2
  status=1
fi
if [ "$mode" != --tree ]; then
  if command -v gitleaks >/dev/null 2>&1; then
    gitleaks detect --source . --log-opts="$mode..HEAD" --redact --no-banner || status=1
  else
    echo "secret-scan: gitleaks is not installed, so passwords and generic secrets were not checked (brew install gitleaks)" >&2
  fi
fi
[ "$status" = 0 ] && echo "secret-scan: nothing found ($mode)"
exit "$status"
