#!/bin/sh
# Codex L01: release.sh/sign-update-manifest.sh keep artifact paths with spaces, Unicode and shell
# metacharacters as single arguments. Stubs cargo (pubkey/sign) and gh (fails if called); --dry-run.
set -eu
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/key dir" "$T/dir with spaces/ünï \$(x) ;&"
PUB=$(sed -n 's/.*UPDATE_KEYS.*hex32("\([0-9a-f]*\)").*/\1/p' "$ROOT/core-ffi/src/update.rs")
cat > "$T/bin/cargo" <<STUB
#!/bin/sh
case "\$*" in *pubkey*) echo "public key $PUB" ;; *sign*) eval "cat \"\\\${\$#}\"" ;; esac
STUB
printf '#!/bin/sh\necho "gh must not run" >&2; exit 99\n' > "$T/bin/gh"
chmod +x "$T/bin/cargo" "$T/bin/gh"
KEY="$T/key dir/secret.key"; echo k > "$KEY"; chmod 600 "$KEY"
A="$T/dir with spaces/ünï \$(x) ;&/Bastion-windows-x64.zip"; echo one > "$A"
B="$T/plain.zip"; echo two > "$B"
VERSION=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$ROOT/core-ffi/Cargo.toml" | head -1)
out=$(PATH="$T/bin:$PATH" sh "$ROOT/scripts/release.sh" --dry-run "$VERSION" "$KEY" "$A" "$B")
dir=$(printf '%s\n' "$out" | sed -n 's/^dry run: signed manifest and artifacts in \(.*\) (not uploaded)$/\1/p')
python3 -I - "$dir/update-manifest.json" <<'PY'
import json, sys
files = json.load(open(sys.argv[1]))["files"]
assert [f["name"] for f in files] == ["Bastion-windows-x64.zip", "plain.zip"], files
assert files[0]["size"] == 4 and files[0]["url"].endswith("/Bastion-windows-x64.zip"), files
PY
rm -rf "$dir"
# An asset name GitHub would rename is refused rather than listed under a wrong URL.
C="$T/bad name.zip"; echo x > "$C"
if PATH="$T/bin:$PATH" sh "$ROOT/scripts/release.sh" --dry-run "$VERSION" "$KEY" "$C" 2>/dev/null; then
  echo "FAIL: unsafe asset name accepted"; exit 1
fi
echo "release-args-test: ok"
