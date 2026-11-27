#!/bin/sh
# Leak scan for a public export tree (scripts/public-export.sh runs it).
#   sh scripts/public-leak-scan.sh <tree>
# Private terms (lab host names, VM and user names) are read from the file named by
# PUBLIC_LEAK_TERMS, one per line. That file lives OUTSIDE the repository, so the names it hides are
# never published by the scan itself. Without it the scan still runs but says it is incomplete.
# Prints file:line:category; secrets and private terms are never echoed. Exit 1 on any hit.
set -eu
[ $# -eq 1 ] && [ -d "$1" ] || { echo "usage: sh scripts/public-leak-scan.sh <tree>" >&2; exit 2; }
HERE="$(cd "$(dirname "$0")" && pwd)"
TERMS=${PUBLIC_LEAK_TERMS:-}
if [ -z "$TERMS" ]; then
  echo "public-leak-scan: PUBLIC_LEAK_TERMS not set: lab host and user names NOT checked" >&2
elif [ ! -r "$TERMS" ]; then
  echo "public-leak-scan: cannot read PUBLIC_LEAK_TERMS file $TERMS" >&2; exit 2
fi
exec python3 -I "$HERE/public-leak-scan.py" "$1" "$HERE" "$TERMS"
