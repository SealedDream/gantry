#!/bin/sh
# UI-04 (Native Mac): login line and session status line text. No app build needed.
#   sh apps/macos/tests/connection-summary-test.sh
set -eu
cd "$(dirname "$0")/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
swiftc -O -o "$T/summary" Sources/Bastion/ConnectionSummary.swift tests/connection-summary/main.swift
"$T/summary"
