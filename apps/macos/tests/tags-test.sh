#!/bin/sh
# Native Mac: tag normalisation and the tag:name filter (TagQuery.swift). No app build, no network.
#   sh apps/macos/tests/tags-test.sh
set -eu
cd "$(dirname "$0")/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
swiftc -O -o "$T/tags" Sources/Bastion/TagQuery.swift tests/tags/main.swift
"$T/tags"
