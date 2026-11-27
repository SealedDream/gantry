#!/bin/sh
# Stand-in for the 1Password CLI in UI tests: `op read op://<ref>` prints a test value, or the
# CLI's not-found message for any reference containing "missing". Never a real secret.
case "$*" in
  *missing*) echo "[ERROR] \"$4\" isn't an item in any vault" >&2; exit 1 ;;
  *) printf 'ui-test-%s' "$4" ;;
esac
