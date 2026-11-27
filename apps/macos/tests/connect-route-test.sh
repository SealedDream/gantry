#!/bin/sh
# Native Mac: the mode and route each connection type opens in (ConnectRoute.swift): normal
# connect, Connect All and its Open One by One. No app build, no network.
#   sh apps/macos/tests/connect-route-test.sh
set -eu
cd "$(dirname "$0")/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
swiftc -O -o "$T/connect-route" Sources/Bastion/ConnectRoute.swift tests/connect-route/main.swift
"$T/connect-route"
