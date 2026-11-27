#!/bin/sh
# Native Mac: Window at launch size rules (WindowLaunch.swift). No app build, no network.
#   sh apps/macos/tests/window-launch-test.sh
set -eu
cd "$(dirname "$0")/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
swiftc -O -o "$T/window-launch" Sources/Bastion/WindowLaunch.swift tests/window-launch/main.swift
"$T/window-launch"
