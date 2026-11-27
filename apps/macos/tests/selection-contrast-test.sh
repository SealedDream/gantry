#!/bin/sh
# Native Mac: selected tree-row fill keeps white text at WCAG AA for every accent (SelectionContrast.swift).
#   sh apps/macos/tests/selection-contrast-test.sh
set -eu
cd "$(dirname "$0")/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
swiftc -O -o "$T/selection-contrast" Sources/Bastion/SelectionContrast.swift tests/selection-contrast/main.swift
"$T/selection-contrast"
