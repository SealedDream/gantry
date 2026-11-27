#!/bin/sh
# Native Mac: the terminal colour choice (TerminalThemeChoice.swift). No app build, no network.
#   sh apps/macos/tests/terminal-theme-choice-test.sh
set -eu
cd "$(dirname "$0")/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
swiftc -O -o "$T/terminal-theme-choice" Sources/Bastion/TerminalThemeChoice.swift tests/terminal-theme-choice/main.swift
"$T/terminal-theme-choice"
