#!/bin/sh
# Tests for scripts/public-export-select.py and scripts/public-leak-scan.py: sh scripts/tests/public-export-test.sh
# Fakes only: a rule file and a scratch tree. No git, no network. Exit 1 on the first failure.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail() { echo "FAIL: $*"; exit 1; }

cat >"$T/list" <<'R'
+ core/**
- core/**/secret*
+ core/**/secret-ok.txt
+ docs/*.md
- **/*tauri*
R
printf '%s\0' core/a.rs core/x/secret.rs core/x/secret-ok.txt docs/A.md docs/sub/B.md core/tauri.rs other.txt \
  | python3 -I "$ROOT/scripts/public-export-select.py" "$T/list" | tr '\0' '\n' >"$T/out"
[ "$(cat "$T/out")" = "core/a.rs
core/x/secret-ok.txt
docs/A.md" ] || fail "selection: $(tr '\n' ' ' <"$T/out")"
echo "PASS last matching rule wins; * stays in one folder; no match = out"

printf 'x core/a\n' >"$T/bad"
printf 'core/a\0' | python3 -I "$ROOT/scripts/public-export-select.py" "$T/bad" >/dev/null 2>&1 && fail "bad rule accepted"
echo "PASS malformed rule refused"

mkdir -p "$T/tree/src" "$T/scripts"
cp "$ROOT/scripts/secret-scan-patterns.txt" "$T/scripts/"
printf '# none\n' >"$T/scripts/public-leak-allow.txt"
printf 'let host = "lab-box-7";\n' >"$T/tree/src/a.rs"
printf 'lab-box-7\n' >"$T/terms"
out=$(python3 -I "$ROOT/scripts/public-leak-scan.py" "$T/tree" "$T/scripts" "$T/terms" 2>/dev/null) && fail "private term not found"
case "$out" in *lab-box*) fail "private term echoed: $out" ;; *private-term-1*) ;; *) fail "no private-term hit: $out" ;; esac
echo "PASS private term found and never printed"

printf 'private-term-1\tsrc/\n' >"$T/scripts/public-leak-allow.txt"
python3 -I "$ROOT/scripts/public-leak-scan.py" "$T/tree" "$T/scripts" "$T/terms" >/dev/null 2>&1 && fail "private term allowed"
echo "PASS private terms cannot be allowlisted"

printf 'a = "192.168.7.9"\nb = "ops@example.com"\nc = "x@realcorp.io"\n' >"$T/tree/src/a.rs"
printf '# none\n' >"$T/scripts/public-leak-allow.txt"
out=$(python3 -I "$ROOT/scripts/public-leak-scan.py" "$T/tree" "$T/scripts" "" 2>/dev/null)
echo "$out" | grep -q 'a.rs:1:private-ip' || fail "192.168 not blocking: $out"
echo "$out" | grep -q 'example.com' && fail "example.com flagged: $out"
echo "$out" | grep -q 'a.rs:3:email' || fail "real email not flagged: $out"
echo "PASS home-range IP and real e-mail block; example domains pass"
rm -f "$T/tree/src/a.rs"; : >"$T/tree/src/._a.rs"; : >"$T/tree/.DS_Store"
printf '& (Join-Path $PSScriptRoot "..\\ui-tauri\\scripts\\x.ps1")\n# ui-tauri/ in a comment\n' >"$T/tree/src/b.ps1"
out=$(python3 -I "$ROOT/scripts/public-leak-scan.py" "$T/tree" "$T/scripts" "" 2>/dev/null)
echo "$out" | grep -q '_a.rs:0:junk-file' || fail "AppleDouble file not flagged: $out"
echo "$out" | grep -q 'DS_Store:0:junk-file' || fail ".DS_Store not flagged: $out"
[ "$(echo "$out" | grep -c 'excluded-path')" = 1 ] || fail "ui-tauri path in a build script: $out"
echo "PASS macOS metadata files and build paths into ui-tauri block; comments do not"
echo "public-export-test: all passed"
