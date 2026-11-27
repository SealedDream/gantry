#!/bin/sh
# Native Mac: the SQL code editor's logic (SqlEditorLogic.swift, PLUG-06c). No app build.
#   sh apps/macos/tests/sql-editor-logic-test.sh
set -eu
cd "$(dirname "$0")/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
swiftc -O -o "$T/sql-editor-logic" Sources/Bastion/SqlEditorLogic.swift tests/sql-editor-logic/main.swift
"$T/sql-editor-logic"
