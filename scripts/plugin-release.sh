#!/bin/sh
# Build, pack and sign the Official plugins (PLUG-12). Runbook: docs/plugins/OPERATIONS.md.
#
#   scripts/plugin-release.sh <out-dir> [plugin ...]        (default: postgres proxmox vmware kubernetes docker)
#
# For each plugin under plugins/official/<name>: cargo build --locked --release for
# wasm32-wasip2 (offline), pack <id>-<version>.gantryplugin, sign <id>-<version>.sig as an
# Official release record (index key + official key), and verify it against the keys pinned
# in core. The source commit is HEAD, which must be clean and on origin.
#
# Keys: INDEX_KEY and OFFICIAL_KEY name the encrypted key files (default ~/Bastion-keys/
# index-a.key and official.key). Passphrases are asked by scripts/plugin-sign.sh; on the
# signing Mac, KEYCHAIN=1 reads them from the login Keychain (service "Bastion plugin signing
# key", accounts bastion-plugin-index-a and bastion-plugin-official) instead.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[ $# -ge 1 ] || { sed -n '2,15p' "$0" >&2; exit 2; }
OUT=$1; shift
[ $# -ge 1 ] || set -- postgres proxmox vmware kubernetes docker
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
export INDEX_KEY="${INDEX_KEY:-$HOME/Bastion-keys/index-a.key}"
export OFFICIAL_KEY="${OFFICIAL_KEY:-$HOME/Bastion-keys/official.key}"

cd "$ROOT"
[ -z "$(git status --porcelain -- plugins core/src/plugin)" ] || { echo "plugins/ or core/src/plugin has uncommitted changes" >&2; exit 1; }
COMMIT=$(git rev-parse HEAD)
API_MAX=$(sed -n 's/.*APP_API: ApiVersion = ApiVersion { major: \([0-9]*\), minor: \([0-9]*\) }.*/\1.\2/p' core/src/plugin/catalogue.rs)
[ -n "$API_MAX" ] || { echo "cannot read APP_API" >&2; exit 1; }
# The pinned keys, read from core so the check below is against what the apps trust.
INDEX_KEYS=$(sed -n '/^const INDEX_KEYS/,/^];/s/.*hex32("\([0-9a-f]*\)").*/\1/p' core/src/plugin/catalogue.rs | paste -sd, -)
OFFICIAL_KEYS=$(sed -n 's/^const OFFICIAL_KEYS.*hex32("\([0-9a-f]*\)").*/\1/p' core/src/plugin/catalogue.rs)
[ -n "$INDEX_KEYS" ] && [ -n "$OFFICIAL_KEYS" ] || { echo "cannot read the pinned keys from core/src/plugin/catalogue.rs" >&2; exit 1; }

passphrases() {
  security find-generic-password -s "Bastion plugin signing key" -a bastion-plugin-index-a -w
  security find-generic-password -s "Bastion plugin signing key" -a bastion-plugin-official -w
}

for name in "$@"; do
  dir="plugins/official/$name"
  [ -f "$dir/plugin.toml" ] || { echo "no plugin $dir" >&2; exit 1; }
  # field <toml file> <key> [<key> ...]: one string value, by its key path.
  field() { python3 -I -c 'import sys, tomllib; t = tomllib.load(open(sys.argv[1], "rb"))
for k in sys.argv[2:]: t = t[k]
print(t)' "$@"; }
  id=$(field "$dir/plugin.toml" id)
  version=$(field "$dir/plugin.toml" version)
  api=$(field "$dir/plugin.toml" api)
  crate=$(field "$dir/Cargo.toml" package name | tr - _)
  echo "== $id $version" >&2
  # A plugin whose exports sit behind a `plugin` feature (so its logic also builds as a plain
  # library for tests) is built with it; without it the component exports nothing.
  features=""
  grep -q '^plugin = ' "$dir/Cargo.toml" && features="--features plugin"
  (cd "$dir" && cargo build --quiet --locked --offline --release --target wasm32-wasip2 $features)
  wasm=$(ls "$dir/target/wasm32-wasip2/release/$crate.wasm" "plugins/target/wasm32-wasip2/release/$crate.wasm" 2>/dev/null | head -1)
  [ -n "$wasm" ] || { echo "no wasm for $crate" >&2; exit 1; }
  base="$OUT/$id-$version"
  python3 -I scripts/plugin-pack.py "$dir" "$wasm" "$base.gantryplugin" "$OUT/.perms-$name.json"
  if [ "${KEYCHAIN:-0}" = 1 ]; then
    passphrases | sh scripts/plugin-sign.sh record "$id" "$version" official "$base.gantryplugin" "$OUT/.perms-$name.json" "$api" "$API_MAX" https://github.com/SealedDream/gantry "$COMMIT" > "$base.sig"
  else
    sh scripts/plugin-sign.sh record "$id" "$version" official "$base.gantryplugin" "$OUT/.perms-$name.json" "$api" "$API_MAX" https://github.com/SealedDream/gantry "$COMMIT" > "$base.sig"
  fi
  rm -f "$OUT/.perms-$name.json"
  sh scripts/plugin-sign.sh verify-record "$base.sig" "$INDEX_KEYS" "$OFFICIAL_KEYS"
  shasum -a 256 "$base.gantryplugin" >&2
done
