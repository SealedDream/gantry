#!/bin/sh
# Build bastion-rdp (IronRDP adapter) as a universal dylib and generate its Swift bindings.
# It is a separate dynamic library because IronRDP cannot share a Cargo graph with russh (see ARCHITECTURE.md).
set -eu
export MACOSX_DEPLOYMENT_TARGET=14.0
cd "$(dirname "$0")/../../rdp-ffi"
# sccache when installed (never required); see scripts/lib/build-env.sh.
. ../scripts/lib/build-env.sh
OUT=../apps/macos/Generated/rdp
# BUILD-SPEED-02: reuse the outputs of an identical rdp-ffi (same git tree hash) from ~/Bastion-prebuilt.
. ../scripts/lib/prebuilt.sh
KEY=$(bastion_prebuilt_key .. plain rdp-ffi apps/macos/build-rdp.sh scripts/lib/prebuilt.sh)
if bastion_prebuilt_restore "$KEY" rdp "$OUT" module swift lib; then echo "built $OUT/lib/libbastion_rdp.dylib (prebuilt)"; exit 0; fi
rustup target add aarch64-apple-darwin x86_64-apple-darwin >/dev/null
cargo build --release --lib --target aarch64-apple-darwin
cargo build --release --lib --target x86_64-apple-darwin
rm -rf "$OUT" && mkdir -p "$OUT/module" "$OUT/swift" "$OUT/lib"
lipo -create target/aarch64-apple-darwin/release/libbastion_rdp.dylib target/x86_64-apple-darwin/release/libbastion_rdp.dylib -output "$OUT/lib/libbastion_rdp.dylib"
# Loaded through the app's rpath: next to the binary, in Contents/Frameworks, or in this folder during development.
install_name_tool -id @rpath/libbastion_rdp.dylib "$OUT/lib/libbastion_rdp.dylib"
codesign --force --sign - "$OUT/lib/libbastion_rdp.dylib"
cargo run --quiet --bin uniffi-bindgen -- generate --library target/aarch64-apple-darwin/release/libbastion_rdp.dylib --language swift --out-dir "$OUT/gen"
mv "$OUT/gen/"*.h "$OUT/module/"
cat "$OUT/gen/"*.modulemap > "$OUT/module/module.modulemap"
mv "$OUT/gen/"*.swift "$OUT/swift/"
rm -rf "$OUT/gen"
bastion_prebuilt_save "$KEY" rdp "$OUT" module swift lib
echo "built $OUT/lib/libbastion_rdp.dylib"
