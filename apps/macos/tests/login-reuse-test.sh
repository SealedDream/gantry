#!/bin/sh
# SEC-03 (Native Mac): the remembered-login store's reuse rule wiring. No app build needed.
#   sh apps/macos/tests/login-reuse-test.sh
set -eu
cd "$(dirname "$0")/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
swiftc -O -o "$T/reuse" Sources/Bastion/LoginReuse.swift tests/login-reuse/main.swift
"$T/reuse"
