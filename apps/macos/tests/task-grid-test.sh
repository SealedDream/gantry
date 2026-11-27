#!/bin/sh
# Native Mac: Tasks results grid model (TaskGridModel.swift): status, summary line, grouping,
# diff, labelled copy. No app build, no network.
#   sh apps/macos/tests/task-grid-test.sh
set -eu
cd "$(dirname "$0")/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
swiftc -O -o "$T/task-grid" Sources/Bastion/TaskGridModel.swift tests/task-grid/main.swift
"$T/task-grid"
