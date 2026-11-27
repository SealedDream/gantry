#!/bin/sh
# Native Mac: tab preview and overview rules (PreviewCache.swift, B11). No app build, no network.
#   sh apps/macos/tests/tab-preview-test.sh
set -eu
cd "$(dirname "$0")/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
swiftc -O -o "$T/tab-preview" Sources/Bastion/PreviewCache.swift tests/tab-preview/main.swift
"$T/tab-preview"
