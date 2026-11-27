#!/bin/sh
# Native Mac: terminal program titles become safe unsaved-tab names (TabTitle.swift).
#   sh apps/macos/tests/tab-title-test.sh
set -eu
cd "$(dirname "$0")/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
swiftc -O -o "$T/tab-title" Sources/Bastion/TabTitle.swift tests/tab-title/main.swift
"$T/tab-title"
