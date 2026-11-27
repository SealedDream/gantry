#!/bin/sh
# Native Mac: audit log records and status text (AuditRecords.swift, LOG-NATIVE-01). No app build.
#   sh apps/macos/tests/audit-log-test.sh
set -eu
cd "$(dirname "$0")/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
swiftc -O -o "$T/audit-log" Sources/Bastion/AuditRecords.swift tests/audit-log/main.swift
"$T/audit-log"
