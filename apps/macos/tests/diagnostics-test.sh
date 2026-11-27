#!/bin/sh
# Native Mac: diagnostics zip contents and redaction, app log (Diagnostics.swift), LOG-NATIVE-01. No app build.
#   sh apps/macos/tests/diagnostics-test.sh
set -eu
cd "$(dirname "$0")/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
swiftc -O -o "$T/diagnostics" Sources/Bastion/Diagnostics.swift tests/diagnostics/main.swift
"$T/diagnostics"
