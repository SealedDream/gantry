#!/bin/sh
# Native Mac: the UI driver's accessibility walk reads non-string roles and titles without an
# Objective-C exception (AXTree.swift; the exception left the auto-lock timer to crash).
#   sh apps/macos/tests/ax-tree-test.sh
set -eu
cd "$(dirname "$0")/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
swiftc -O -o "$T/ax-tree" Sources/Bastion/AXTree.swift tests/ax-tree/main.swift
"$T/ax-tree"
