#!/bin/sh
# Tests for the PLUG-15 maintainer scripts. Offline: the advisory watch reads saved answers
# from scripts/tests/fixtures/wasmtime-advisories-*.json; the drill uses throwaway keys.
#   sh scripts/tests/plugin-ops-test.sh
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FIX="$ROOT/scripts/tests/fixtures"
pass=0 fail=0
check() { # <name> <expected-exit> <command...>
  name=$1 want=$2; shift 2
  out=$("$@" 2>&1); got=$?
  if [ "$got" = "$want" ]; then pass=$((pass + 1)); echo "ok   $name"; else fail=$((fail + 1)); echo "FAIL $name (exit $got, want $want)"; printf '%s\n' "$out" | sed 's/^/     /'; fi
}
W="$ROOT/scripts/wasmtime-advisory-watch.sh"
check "advisory watch: nothing affects the pin" 0 sh "$W" --from-file "$FIX/wasmtime-advisories-clean.json"
check "advisory watch: a critical advisory in range" 3 sh "$W" --from-file "$FIX/wasmtime-advisories-critical.json"
check "advisory watch: an advisory for older versions only" 0 sh "$W" --from-file "$FIX/wasmtime-advisories-older.json"
check "advisory watch: an unreadable range counts as affected" 3 sh "$W" --from-file "$FIX/wasmtime-advisories-oddrange.json"
check "advisory watch: a broken answer is an error, not clean" 1 sh "$W" --from-file "$FIX/wasmtime-advisories-broken.json"
check "revocation drill (throwaway keys)" 0 sh "$ROOT/scripts/plugin-revocation-drill.sh"
echo "passed $pass, failed $fail"
[ "$fail" -eq 0 ]
