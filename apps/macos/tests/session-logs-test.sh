#!/bin/sh
# Native Mac: session log listing, filter and export (SessionLogFiles.swift, LOG-CORE-02).
# No app build, no network.
#   sh apps/macos/tests/session-logs-test.sh
set -eu
cd "$(dirname "$0")/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
swiftc -O -o "$T/session-logs" Sources/Bastion/SessionLogFiles.swift tests/session-logs/main.swift
"$T/session-logs"
