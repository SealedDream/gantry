#!/bin/sh
# A1-NM-01 (Native Mac): the jump hosts Test Connection sends, built from the saved chain the core
# resolves (gateway, then ProxyJump). Compiles Sources/Bastion/TestConnectionRoute.swift with the
# tests; no app build, no network.
#   sh apps/macos/tests/test-connection-route-test.sh
set -eu
cd "$(dirname "$0")/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
swiftc -O -o "$T/route" Sources/Bastion/TestConnectionRoute.swift tests/test-connection-route/main.swift
"$T/route"
