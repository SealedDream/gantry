#!/bin/sh
# Build and sign an update manifest for one release artifact, or for every asset of a GitHub release.
#   scripts/sign-update-manifest.sh <secret-key-file> <version> <artifact> <https-url> [days-valid=30] [channel=stable] [notes]
#   scripts/sign-update-manifest.sh <secret-key-file> <version> --release <tag> <artifact>...   (DAYS, CHANNEL, NOTES from env)
# Writes the signed envelope to stdout. --release lists each artifact at
# https://github.com/$BASTION_RELEASE_REPO/releases/download/<tag>/<basename> (default repo
# SealedDream/gantry; build the apps with the same BASTION_RELEASE_REPO). <secret-key-file> may be
# "keychain": the login Keychain item "Bastion update signing key" (account bastion-update), read
# straight into the signer and never written to disk or printed. Its public key must be in
# core-ffi/src/update.rs (UPDATE_KEYS) for the app to trust it.
set -eu
[ $# -ge 4 ] || { sed -n '2,10p' "$0" >&2; exit 2; }
REPO=${BASTION_RELEASE_REPO:-SealedDream/gantry}
case "$REPO" in */*) ;; *) echo "BASTION_RELEASE_REPO must be owner/name" >&2; exit 2 ;; esac
KEY=$1 VERSION=$2
shift 2
if [ "$1" = --release ]; then
  TAG=$2
  shift 2
  DAYS=${DAYS:-30} CHANNEL=${CHANNEL:-stable} NOTES=${NOTES:-}
  # Pairs of (path, URL) built without word splitting. The asset name must be URL-safe, because
  # GitHub renames assets with other characters and the listed URL would then not exist.
  for a in "$@"; do
    shift
    name=$(basename "$a")
    case "$name" in *[!A-Za-z0-9._-]*) echo "asset name '$name' must use only A-Z a-z 0-9 . _ -" >&2; exit 2 ;; esac
    set -- "$@" "$a" "https://github.com/$REPO/releases/download/$TAG/$name"
  done
else
  ARTIFACT=$1 URL=$2 DAYS=${3:-30} CHANNEL=${4:-stable} NOTES=${5:-}
  case "$URL" in https://*) ;; *) echo "artifact URL must be https" >&2; exit 2 ;; esac
  set -- "$ARTIFACT" "$URL"
fi
case "$KEY" in keychain|/*) ;; *) KEY="$(pwd)/$KEY" ;; esac
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PAYLOAD="$(mktemp)"
trap 'rm -f "$PAYLOAD"' EXIT
python3 -I - "$VERSION" "$DAYS" "$CHANNEL" "$NOTES" "$@" > "$PAYLOAD" <<'PY'
import hashlib, json, os, sys, time
version, days, channel, notes = sys.argv[1:5]
pairs = sys.argv[5:]
def entry(artifact, url):
    data = open(artifact, "rb").read()
    return {"name": os.path.basename(artifact), "url": url,
            "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
print(json.dumps({
    "schema": 1, "channel": channel, "version": version,
    "expires": int(time.time()) + int(days) * 86400, "notes": notes,
    "files": [entry(pairs[i], pairs[i + 1]) for i in range(0, len(pairs), 2)],
}))
PY
cd "$ROOT/core"
if [ "$KEY" = keychain ]; then
  security find-generic-password -s "Bastion update signing key" -a bastion-update -w \
    | cargo run --quiet --example update_manifest -- sign /dev/stdin "$PAYLOAD"
else
  cargo run --quiet --example update_manifest -- sign "$KEY" "$PAYLOAD"
fi
