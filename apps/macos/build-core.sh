#!/bin/sh
# Build bastion-ffi for macOS (arm64 + x86_64), generate Swift bindings and an XCFramework.
set -eu
export MACOSX_DEPLOYMENT_TARGET=14.0
cd "$(dirname "$0")/../../core-ffi"
# sccache when installed (never required); see scripts/lib/build-env.sh.
. ../scripts/lib/build-env.sh
OUT=../apps/macos/Generated
# BUILD-SPEED-02: reuse the outputs of an identical core (same git tree hashes) from ~/Bastion-prebuilt.
. ../scripts/lib/prebuilt.sh
VARIANT=plain; [ "${BASTION_TEST_HOOKS:-}" = 1 ] && VARIANT=test-hooks
# The version and release repo are compiled in (option_env!), so they are part of the cache key.
VARIANT="$VARIANT-${BASTION_VERSION:-crate}-$(printf %s "${BASTION_RELEASE_REPO:-default}" | tr / _)"
ENTRIES="headers swift lib BastionFFI.xcframework"
KEY=$(bastion_prebuilt_key .. "$VARIANT" core core-ffi apps/macos/build-core.sh scripts/lib/prebuilt.sh)
# shellcheck disable=SC2086
if bastion_prebuilt_restore "$KEY" "core-$VARIANT" "$OUT" $ENTRIES; then echo "built $OUT/BastionFFI.xcframework (prebuilt)"; exit 0; fi
rustup target add aarch64-apple-darwin x86_64-apple-darwin >/dev/null
# BASTION_TEST_HOOKS=1 (driver suites only) adds the core fault hooks; release bundles never set it.
FEATURES=""; [ "${BASTION_TEST_HOOKS:-}" = 1 ] && FEATURES="--features test-hooks"
cargo build --release --target aarch64-apple-darwin $FEATURES
cargo build --release --target x86_64-apple-darwin $FEATURES
# Only this script's outputs: Generated/rdp belongs to build-rdp.sh.
rm -rf "$OUT/headers" "$OUT/swift" "$OUT/lib" "$OUT/gen" "$OUT/BastionFFI.xcframework" && mkdir -p "$OUT/headers" "$OUT/swift" "$OUT/lib"
lipo -create target/aarch64-apple-darwin/release/libbastion_ffi.a target/x86_64-apple-darwin/release/libbastion_ffi.a -output "$OUT/lib/libbastion_ffi.a"
cargo run --quiet --features bindgen --bin uniffi-bindgen -- generate --library target/aarch64-apple-darwin/release/libbastion_ffi.a --language swift --out-dir "$OUT/gen"
mv "$OUT/gen/"*.h "$OUT/headers/"
cat "$OUT/gen/"*.modulemap | sed 's/^module /module /' > "$OUT/headers/module.modulemap"
mv "$OUT/gen/"*.swift "$OUT/swift/"
rm -rf "$OUT/gen"
xcodebuild -create-xcframework -library "$OUT/lib/libbastion_ffi.a" -headers "$OUT/headers" -output "$OUT/BastionFFI.xcframework" >/dev/null
# shellcheck disable=SC2086
bastion_prebuilt_save "$KEY" "core-$VARIANT" "$OUT" $ENTRIES
echo "built $OUT/BastionFFI.xcframework"
