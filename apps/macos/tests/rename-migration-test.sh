#!/bin/sh
# Native Mac: Bastion -> Gantry data folder migration (AppRename.swift), owner 2026-11-23. No app build.
#   sh apps/macos/tests/rename-migration-test.sh
set -eu
cd "$(dirname "$0")/.."
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
swiftc -O -o "$T/rename-migration" Sources/Bastion/AppRename.swift tests/rename-migration/main.swift
"$T/rename-migration"
