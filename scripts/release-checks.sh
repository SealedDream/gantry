#!/bin/sh
# Every dependency check a release needs, in one run (there is no CI; Codex D04/L04).
# scripts/release.sh runs this first; run it by hand after dependency changes. docs/DEPENDENCIES.md.
set -eu
cd "$(dirname "$0")/.."
sh scripts/audit-deps.sh
sh scripts/deny.sh
sh scripts/audit-npm.sh
python3 scripts/notices.py --check
sh scripts/sbom.sh
