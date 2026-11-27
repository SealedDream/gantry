#!/bin/sh
# Native Mac: activity log rows, filter JSON and export (ActivityRecords.swift, LOG-NATIVE-01).
# No app build, no network.
#   sh apps/macos/tests/activity-test.sh
set -eu
cd "$(dirname "$0")/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
swiftc -O -o "$T/activity" Sources/Bastion/ActivityRecords.swift tests/activity/main.swift
"$T/activity"
