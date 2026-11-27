#!/bin/sh
# Dependency vulnerability scan: RustSec advisories against every shipped crate's committed
# Cargo.lock (core, core-ffi, core-cabi, rdp-ffi, cli, plugin-host, and the Tauri app with its RDP helper). Requires `cargo install cargo-audit --locked`.
# Exits non-zero when any crate has a vulnerability advisory; warnings (unmaintained, yanked) are
# printed but do not fail. Accepted advisories go in scripts/audit-ignore.txt, each with a reason.
set -u
cd "$(dirname "$0")/.."
status=0
IGNORE=$(grep -v '^#' scripts/audit-ignore.txt | awk 'NF{printf " --ignore %s", $1}')
for crate in core core-ffi core-cabi rdp-ffi cli plugin-host ui-tauri/src-tauri ui-tauri/rdp-helper; do
  [ -f "$crate/Cargo.lock" ] || continue
  echo "== $crate"
  if ! cargo audit --file "$crate/Cargo.lock" $IGNORE; then
    status=1
  fi
done
exit $status
