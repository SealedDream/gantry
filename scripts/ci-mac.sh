#!/bin/sh
# Native Mac CI pipeline, run locally (the repo has no GitHub Actions by owner rule).
# Steps: core + core-ffi tests, FFI build + Swift bindings, RDP library, Swift release build, doc tables.
# Works from a clean tree (no Generated/ yet, no .git), such as the public export.
# BASTION_CI_UI=1 also runs the driver suites (apps/macos/uitests/run-all.sh; needs the Mac screen).
# Exits non-zero on the first failing step and prints which one.
set -eu
cd "$(dirname "$0")/.."
step() { printf '\n== ci-mac: %s\n' "$1"; }
fail() { printf '\nci-mac: FAIL at "%s"\n' "$CURRENT" >&2; }
trap 'fail' EXIT
CURRENT="core tests";      step "$CURRENT"; (cd core && cargo test --quiet)
CURRENT="core-ffi tests";  step "$CURRENT"; (cd core-ffi && cargo test --quiet)
CURRENT="ffi + bindings";  step "$CURRENT"; sh apps/macos/build-core.sh
CURRENT="rdp library";     step "$CURRENT"; sh apps/macos/build-rdp.sh
CURRENT="swift build";     step "$CURRENT"; (cd apps/macos && swift build -c release)
CURRENT="markdown tables"; step "$CURRENT"; python3 scripts/check-md-tables.py
if [ "${BASTION_CI_UI:-}" = 1 ]; then
  CURRENT="driver suites"; step "$CURRENT"; sh apps/macos/uitests/run-all.sh
fi
trap - EXIT
printf '\nci-mac: PASS\n'
