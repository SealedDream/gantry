#!/bin/sh
# Native Mac: before-connect gate verdicts and the Connect All multi-host batch (HookGate.swift, B5).
# No app build, no network.
#   sh apps/macos/tests/hook-gate-test.sh
set -eu
cd "$(dirname "$0")/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
swiftc -O -o "$T/hook-gate" Sources/Bastion/HookGate.swift tests/hook-gate/main.swift
"$T/hook-gate"
