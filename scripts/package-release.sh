#!/bin/sh
# Assemble the downloadable Native Mac and Native Windows archives for one tagged release.
# It builds and checks; it never uploads. Publishing is scripts/release.sh, run by the owner.
#
#   scripts/package-release.sh [--check] <tag> <plugin-dir> [<windows-zip> [<windows-setup-exe>]]
#
# <tag>          vX.Y.Z; HEAD must be exactly that tag, the tree clean, and X.Y.Z must equal the
#                core-ffi and core-cabi crate versions (what the apps report as installed).
# <plugin-dir>   the signed Official plugin packs from scripts/plugin-release.sh: one
#                <id>-<version>.bastionplugin and its .sig for each of postgres, proxmox and vmware.
#                Every record is verified against the keys pinned in core before it is bundled.
# <windows-zip>  Gantry-windows-x64.zip from apps\windows\package-windows.ps1, built on Windows
#                from the same tag. The plugin packs are added to a copy under plugins\.
# <windows-setup-exe> Gantry-X.Y.Z-windows-x64-setup.exe (Inno Setup, package-windows.ps1) from the
#                same tag; copied as is. scripts/install.ps1, when present, is published as install.ps1:
#                it installs the setup exe and fails closed unless SHA256SUMS lists it.
#
# Output in dist/<tag>/: Gantry-macos-<arch>.zip and .dmg (Gantry.app + plugins/, the dmg with an
# Applications link), Gantry-windows-x64.zip
# (when given), SHA256SUMS, and update-manifest.json: the signed list of the update files (both zips
# and the setup exe) that Check for Updates reads from the latest release. It is signed with the
# Keychain key "Bastion update signing key" (scripts/sign-update-manifest.sh keychain), which must
# match UPDATE_KEYS in core-ffi/src/update.rs. BASTION_RELEASE_REPO (owner/name, default
# SealedDream/gantry) is both compiled into the apps and used for the manifest URLs. --check runs every check and stops before building.
set -eu
CHECK=0; [ "${1:-}" = --check ] && { CHECK=1; shift; }
[ $# -ge 2 ] || { sed -n '2,17p' "$0" >&2; exit 2; }
TAG=$1 PLUGINS=$2 WINZIP=${3:-} WINSETUP=${4:-}
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
fail() { echo "package-release: $*" >&2; exit 1; }
cd "$ROOT"

case "$TAG" in v[0-9]*.[0-9]*.[0-9]*) ;; *) fail "tag must look like v1.0.0: $TAG" ;; esac
VERSION=${TAG#v}
[ "$(git rev-parse HEAD)" = "$(git rev-parse -q --verify "refs/tags/$TAG^{commit}" || echo none)" ] \
  || fail "HEAD is not tag $TAG (git checkout $TAG first)"
[ -z "$(git status --porcelain --untracked-files=no)" ] || fail "tracked files have changes"
for crate in core-ffi core-cabi; do
  v=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$crate/Cargo.toml" | head -1)
  [ "$v" = "$VERSION" ] || fail "$crate/Cargo.toml says $v, the tag says $VERSION"
done

# Signed plugin packs: exactly one of each Official plugin, each with a verified release record.
[ -d "$PLUGINS" ] || fail "no plugin folder $PLUGINS"
INDEX_KEYS=$(sed -n '/^const INDEX_KEYS/,/^];/s/.*hex32("\([0-9a-f]*\)").*/\1/p' core/src/plugin/catalogue.rs | paste -sd, -)
OFFICIAL_KEYS=$(sed -n 's/^const OFFICIAL_KEYS.*hex32("\([0-9a-f]*\)").*/\1/p' core/src/plugin/catalogue.rs)
[ -n "$INDEX_KEYS" ] && [ -n "$OFFICIAL_KEYS" ] || fail "cannot read the pinned keys from core/src/plugin/catalogue.rs"
PACKS=""
for id in postgres proxmox vmware; do
  set -- "$PLUGINS"/dev.bastion.$id-*.bastionplugin
  [ $# -eq 1 ] && [ -f "$1" ] || fail "need exactly one dev.bastion.$id-*.bastionplugin in $PLUGINS"
  sig="${1%.bastionplugin}.sig"
  [ -f "$sig" ] || fail "no signature $sig"
  sh scripts/plugin-sign.sh verify-record "$sig" "$INDEX_KEYS" "$OFFICIAL_KEYS" >/dev/null || fail "signature check failed: $sig"
  PACKS="$PACKS $1 $sig"
done
if [ -n "$WINZIP" ]; then
  [ -f "$WINZIP" ] || fail "no Windows zip at $WINZIP"
  unzip -l "$WINZIP" | grep -q 'Gantry\.exe$' || fail "$WINZIP has no Gantry.exe"
  ! unzip -l "$WINZIP" | grep -q 'TEST-HOOKS-BUILD.txt' || fail "$WINZIP is a test-hooks build"
fi
if [ -n "$WINSETUP" ]; then
  [ -f "$WINSETUP" ] || fail "no Windows setup at $WINSETUP"
  [ "$(basename "$WINSETUP")" = "Gantry-$VERSION-windows-x64-setup.exe" ] || fail "setup must be named Gantry-$VERSION-windows-x64-setup.exe"
fi
[ "${BASTION_VERSION:-$VERSION}" = "$VERSION" ] || fail "BASTION_VERSION is $BASTION_VERSION, the tag says $VERSION"
PINNED=$(sed -n 's/^const UPDATE_KEYS.*hex32("\([0-9a-f]*\)").*/\1/p' core-ffi/src/update.rs)
SIGNER=$(security find-generic-password -s "Bastion update signing key" -a bastion-update -w 2>/dev/null \
  | (cd core && cargo run --quiet --example update_manifest -- pubkey /dev/stdin) | sed -n 's/^public key *//p')
[ -n "$SIGNER" ] || fail "no Keychain item \"Bastion update signing key\" (account bastion-update)"
[ "$SIGNER" = "$PINNED" ] || fail "the Keychain update key is not the one pinned in core-ffi/src/update.rs"
echo "checks passed for $TAG"
[ "$CHECK" = 0 ] || exit 0

# Mac: release core (no test hooks), RDP library, app bundle. bundle.sh refuses a test-hooks core.
OUT="$ROOT/dist/$TAG"; rm -rf "$OUT"; mkdir -p "$OUT"
export BASTION_VERSION="$VERSION"
( cd apps/macos && unset BASTION_TEST_HOOKS && sh build-core.sh && sh build-rdp.sh && swift build -c release && sh bundle.sh )
STAGE=$(mktemp -d); trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/mac/plugins"
ditto apps/macos/build/Gantry.app "$STAGE/mac/Gantry.app"
for f in $PACKS; do cp "$f" "$STAGE/mac/plugins/"; done
codesign --verify --deep --strict "$STAGE/mac/Gantry.app" || fail "Gantry.app signature does not verify"
( cd "$STAGE/mac" && ditto -c -k --sequesterRsrc . "$OUT/Gantry-macos-$(uname -m).zip" )
# The same contents as a disk image with an Applications link (hdiutil, no extra tools).
ln -s /Applications "$STAGE/mac/Applications"
hdiutil create -quiet -volname "Gantry $VERSION" -srcfolder "$STAGE/mac" -fs HFS+ -format UDZO -ov "$OUT/Gantry-macos-$(uname -m).dmg"
hdiutil verify -quiet "$OUT/Gantry-macos-$(uname -m).dmg" || fail "dmg does not verify"
rm "$STAGE/mac/Applications"

if [ -n "$WINZIP" ]; then
  mkdir -p "$STAGE/win" && ( cd "$STAGE/win" && unzip -q "$WINZIP" )
  # package-windows.ps1 -PluginPacks already puts them in Plugins\ (PR #1423); add them only if
  # it did not (Windows file names ignore case, so never a second plugins folder).
  if ! ls "$STAGE/win" | grep -qix plugins; then
    mkdir -p "$STAGE/win/Plugins"; for f in $PACKS; do cp "$f" "$STAGE/win/Plugins/"; done
  fi
  ( cd "$STAGE/win" && zip -qr "$OUT/Gantry-windows-x64.zip" . )
fi
if [ -n "$WINSETUP" ]; then cp "$WINSETUP" "$OUT/"; fi
if [ -f scripts/install.ps1 ]; then cp scripts/install.ps1 "$OUT/install.ps1"; fi
# "<hash>  <name>" lines (sha256sum format), which install.ps1 checks against.
( cd "$OUT" && shasum -a 256 $(ls *.zip *.dmg *.exe install.ps1 2>/dev/null) > SHA256SUMS )
UPDATES=$(cd "$OUT" && ls Gantry-macos-*.zip Gantry-windows-x64.zip Gantry-Native-*-setup.exe 2>/dev/null | sed "s|^|$OUT/|")
# shellcheck disable=SC2086  # names are checked URL-safe by the signer
sh scripts/sign-update-manifest.sh keychain "$VERSION" --release "$TAG" $UPDATES > "$OUT/update-manifest.json"
echo "built in $OUT (not uploaded):"; cat "$OUT/SHA256SUMS"; echo "update-manifest.json signs: $(echo $UPDATES | xargs -n1 basename | paste -sd' ' -)"
