#!/bin/sh
# Fails when any independently built crate's Cargo.lock no longer matches its manifest (H01).
# Run before opening a PR that touches a Cargo.toml. Offline: resolution only, no compile.
set -u
cd "$(dirname "$0")/.."
status=0
for m in core cli core-ffi core-cabi rdp-ffi ui-tauri/src-tauri; do
  [ -f "$m/Cargo.toml" ] || continue   # the public tree has no ui-tauri
  if cargo tree --manifest-path "$m/Cargo.toml" --locked --offline --depth 0 -q >/dev/null 2>&1; then
    echo "ok     $m"
  else
    echo "STALE  $m/Cargo.lock (run: cargo tree --manifest-path $m/Cargo.toml --offline)"; status=1
  fi
done
exit $status
