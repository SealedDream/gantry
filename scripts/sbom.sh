#!/bin/sh
# CycloneDX SBOMs (JSON) for every Rust crate that ships inside an app: core (via core-ffi and
# core-cabi), core-ffi (macOS static library), core-cabi (Windows DLL), rdp-ffi (macOS dylib) and
# the Tauri app (`ui-tauri/src-tauri` → bastion-tauri, `ui-tauri/rdp-helper` → bastion-rdp-helper).
# Requires `cargo install cargo-cyclonedx --locked`. Output: build/sbom/<crate>.cdx.json.
# Generated from the committed Cargo.lock files, so the SBOM matches what a locked build links.
set -eu
cd "$(dirname "$0")/.."
OUT=build/sbom
mkdir -p "$OUT"
for entry in core core-ffi core-cabi rdp-ffi ui-tauri/src-tauri:bastion-tauri ui-tauri/rdp-helper:bastion-rdp-helper; do
  dir=${entry%%:*}
  name=${entry##*:}
  name=${name##*/}
  [ -d "$dir" ] || continue   # the public tree has no ui-tauri
  ( cd "$dir" && cargo cyclonedx --format json --spec-version 1.5 --override-filename "$name.cdx" )
  mv "$dir/$name.cdx.json" "$OUT/"
  count=$(grep -c '"bom-ref"' "$OUT/$name.cdx.json" || true)
  echo "$OUT/$name.cdx.json: $count components"
done
