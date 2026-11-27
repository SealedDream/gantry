#!/bin/sh
# Native Mac: the Activity log start and end JSON for RDP, VNC and web tabs (SessionActivityStart.swift,
# LOG-RDP-01). No app build, no network.
#   sh apps/macos/tests/session-activity-test.sh
set -eu
cd "$(dirname "$0")/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
swiftc -O -o "$T/session-activity" Sources/Bastion/SessionActivityStart.swift tests/session-activity/main.swift
"$T/session-activity"
