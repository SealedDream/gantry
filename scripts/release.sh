#!/bin/sh
# Publish a Gantry release on GitHub, run by hand (GitHub Actions is off):
#   scripts/release.sh [--dry-run] <version> <secret-key-file> <artifact>...
# An artifact that is a .app folder is zipped first as Gantry-macos-<arch>.zip (ditto keeps the
# ad hoc signature). Windows builds go in as Gantry-windows-<x64|arm64>.zip (the WinUI publish
# folder), the name the Windows app downloads. Every artifact is listed, with SHA-256 and size, in update-manifest.json, which
# scripts/sign-update-manifest.sh signs; then `gh release create v<version>` uploads all of them.
# NOTES (release notes), DAYS (manifest validity, default 30) and CHANNEL (default stable) come
# from the environment. --dry-run stops before uploading and prints where the files are.
#
# The signing key must live outside this repository (mode 0600) and its public key must be the
# one compiled into core-ffi/src/update.rs (UPDATE_KEYS); <version> must equal core-ffi's crate
# version, which is what the apps report as installed.
set -eu
DRY=0
[ "${1:-}" = --dry-run ] && { DRY=1; shift; }
[ $# -ge 3 ] || { sed -n '2,13p' "$0" >&2; exit 2; }
VERSION=$1 KEY=$2
shift 2
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REPO=SealedDream/gantry
TAG="v$VERSION"

fail() { echo "release: $*" >&2; exit 1; }
[ -f "$KEY" ] || fail "no key file at $KEY"
KEY="$(cd "$(dirname "$KEY")" && pwd)/$(basename "$KEY")"
case "$KEY" in "$ROOT"/*) fail "the signing key is inside the repository; move it out (and never commit it)" ;; esac
[ "$(stat -f %Lp "$KEY" 2>/dev/null || stat -c %a "$KEY")" = 600 ] || fail "chmod 600 $KEY first"

CRATE_VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/core-ffi/Cargo.toml" | head -1)"
[ "$VERSION" = "$CRATE_VERSION" ] || fail "core-ffi/Cargo.toml says $CRATE_VERSION; bump it to $VERSION so the release reports that version"

PUBKEY="$(cd "$ROOT/core" && cargo run --quiet --example update_manifest -- pubkey "$KEY" | sed -n 's/^public key //p')"
grep -q "\"$PUBKEY\"" "$ROOT/core-ffi/src/update.rs" || fail "public key $PUBKEY is not in UPDATE_KEYS (core-ffi/src/update.rs); apps would refuse this release"

# Advisories, licence/source policy, npm audit, notices and SBOM (docs/DEPENDENCIES.md).
[ -n "${DRY:-}" ] || sh "$ROOT/scripts/release-checks.sh" || fail "dependency checks failed (scripts/release-checks.sh)"

OUT="$(mktemp -d)"
# Rebuild the positional list in place so paths with spaces or metacharacters stay one argument
# each, and the same exact list goes to signing and upload.
for a in "$@"; do
  shift
  case "$a" in
    *.app|*.app/)
      zip="$OUT/Gantry-macos-$(uname -m).zip"
      ditto -c -k --keepParent "${a%/}" "$zip"
      set -- "$@" "$zip" ;;
    *) [ -f "$a" ] || fail "no artifact at $a"; set -- "$@" "$a" ;;
  esac
done
DAYS="${DAYS:-30}" CHANNEL="${CHANNEL:-stable}" NOTES="${NOTES:-}" \
  sh "$ROOT/scripts/sign-update-manifest.sh" "$KEY" "$VERSION" --release "$TAG" "$@" > "$OUT/update-manifest.json"

if [ "$DRY" = 1 ]; then
  echo "dry run: signed manifest and artifacts in $OUT (not uploaded)"
  exit 0
fi
gh release create "$TAG" --repo "$REPO" --title "Gantry Terminal $VERSION" --notes "${NOTES:-Gantry Terminal $VERSION}" "$@" "$OUT/update-manifest.json"
rm -rf "$OUT"
echo "released $TAG: https://github.com/$REPO/releases/tag/$TAG"
