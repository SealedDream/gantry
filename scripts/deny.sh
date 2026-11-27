#!/bin/sh
# Licence, source and advisory policy (deny.toml, Codex D04) over every shipped crate's committed
# Cargo.lock. Requires `cargo install cargo-deny --locked`. Exits non-zero on any violation.
set -u
cd "$(dirname "$0")/.."
status=0
for crate in core core-ffi core-cabi rdp-ffi cli plugin-host ui-tauri/src-tauri ui-tauri/rdp-helper; do
  [ -f "$crate/Cargo.lock" ] || continue
  echo "== $crate"
  cargo deny --locked --manifest-path "$crate/Cargo.toml" --config deny.toml check || status=1
done
exit $status
