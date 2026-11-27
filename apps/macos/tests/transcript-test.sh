#!/bin/sh
# Native Mac: transcript viewer paging, lines, time column and find (TranscriptText.swift), LOG-NATIVE-01. No app build.
#   sh apps/macos/tests/transcript-test.sh
set -eu
cd "$(dirname "$0")/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
swiftc -O -o "$T/transcript" Sources/Bastion/TranscriptText.swift tests/transcript/main.swift
"$T/transcript"
