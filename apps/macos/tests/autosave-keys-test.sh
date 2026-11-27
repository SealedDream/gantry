#!/bin/sh
# Native Mac: stale SwiftUI window and split-view keys (AutosaveKeys.swift). No app build, no network.
#   sh apps/macos/tests/autosave-keys-test.sh
set -eu
cd "$(dirname "$0")/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
swiftc -O -o "$T/autosave-keys" Sources/Bastion/AutosaveKeys.swift tests/autosave-keys/main.swift
"$T/autosave-keys"
