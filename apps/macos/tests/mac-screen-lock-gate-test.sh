#!/bin/sh
# MAC-TEST-VAULT-SCREEN-LOCK (Native Mac): the release build keeps locking on the real screen lock;
# only a test-hooks build in a UI-driver run skips it. No app build needed.
#   sh apps/macos/tests/mac-screen-lock-gate-test.sh
set -eu
cd "$(dirname "$0")/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
swiftc -O -o "$T/gate" Sources/Bastion/ScreenLockGate.swift tests/mac-screen-lock-gate/main.swift
"$T/gate"
