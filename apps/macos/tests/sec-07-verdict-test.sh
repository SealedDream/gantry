#!/bin/sh
# SEC-07 (Native Mac): the Test Connection decisions that need no screen: what a report means
# (a report waiting for the host key is never a pass) and the question put to the user.
# Compiles Sources/Bastion/TestConnectionVerdict.swift with the tests; no app build, no network.
#   sh apps/macos/tests/sec-07-verdict-test.sh
set -eu
cd "$(dirname "$0")/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
swiftc -O -o "$T/sec-07-verdict" Sources/Bastion/TestConnectionVerdict.swift tests/sec-07-verdict/main.swift
"$T/sec-07-verdict"
