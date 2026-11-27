#!/bin/sh
# Native Mac: Plugins page wording (PluginsText.swift, PLUG-06a part 1). No app build.
#   sh apps/macos/tests/plugins-text-test.sh
set -eu
cd "$(dirname "$0")/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
swiftc -O -o "$T/plugins-text" Sources/Bastion/PluginsText.swift tests/plugins-text/main.swift
"$T/plugins-text"
