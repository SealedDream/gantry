#!/bin/sh
# PLUG-14 (Native Mac): sign-bundle.sh signs inside-out (dylib, helper, app), gives the helper its
# one entitlement and the app none of it, verifies --deep --strict, and refuses stray helper files.
# Runs anywhere (Linux included): codesign is a stub that logs its arguments and answers -d from
# what was signed. The real proof on a Mac is in docs/evidence/PLUG-14.md.
#   sh apps/macos/tests/sign-bundle-test.sh
set -eu
cd "$(dirname "$0")/.."
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
cat > "$T/codesign" <<'STUB'
#!/bin/sh
echo "$*" >> "$LOG"
if [ "$1" = -d ]; then   # codesign -d --entitlements - --xml <path>: print what was signed onto <path>
  for a; do p="$a"; done
  grep -F " $p" "$LOG" | grep -- "--sign" | tail -1 | sed -n 's/.*--entitlements \([^ ]*\) .*/\1/p' | while read -r e; do cat "$e"; done
fi
exit 0
STUB
chmod +x "$T/codesign"
fail=0; pass=0
ok() { pass=$((pass+1)); echo "PASS  $1"; }
no() { fail=$((fail+1)); echo "FAIL  $1"; }
mkapp() { rm -rf "$T/B.app"; mkdir -p "$T/B.app/Contents/Frameworks" "$T/B.app/Contents/MacOS"; : > "$T/B.app/Contents/Frameworks/libbastion_rdp.dylib"; }
run() { LOG="$T/log"; : > "$LOG"; export LOG; CODESIGN="$T/codesign" sh sign-bundle.sh "$T/B.app" "$1" > "$T/out" 2>&1; }

# 1. With the helper, ad hoc.
mkapp; mkdir -p "$T/B.app/Contents/Helpers"; : > "$T/B.app/Contents/Helpers/bastion-plugin-host"
if run -; then ok "ad hoc bundle with helper signs"; else no "ad hoc bundle with helper signs: $(cat "$T/out")"; fi
signs="$(grep -- '--sign' "$T/log" | sed 's#.*/B.app#B.app#')"
expect="B.app/Contents/Frameworks/libbastion_rdp.dylib
B.app/Contents/Helpers/bastion-plugin-host
B.app"
[ "$signs" = "$expect" ] && ok "inside-out order: dylib, helper, app" || no "order was: $signs"
grep -- '--sign' "$T/log" | grep -q -- "--entitlements BastionPluginHelper.entitlements .*bastion-plugin-host$" && ok "helper signed with its own entitlements" || no "helper entitlements"
grep -- '--sign' "$T/log" | grep -q -- "--entitlements Bastion.adhoc.entitlements .*B.app$" && ok "app keeps Bastion.adhoc.entitlements" || no "app entitlements"
[ "$(grep -c -- '--options runtime' "$T/log")" = 3 ] && ok "hardened runtime on all three" || no "hardened runtime"
grep -q -- '--deep' "$T/log" && ! grep -- '--deep' "$T/log" | grep -q -- '--sign' && ok "--deep used to verify only" || no "--deep use"
grep -q -- '--verify --deep --strict' "$T/log" && ok "verify --deep --strict" || no "verify --deep --strict"
! grep -q -- '--timestamp' "$T/log" && ok "ad hoc: no timestamp" || no "ad hoc timestamp"

# 2. Without the helper: same as before PLUG-14.
mkapp; if run -; then ok "bundle without helper signs"; else no "bundle without helper: $(cat "$T/out")"; fi
[ "$(grep -c -- '--sign' "$T/log")" = 2 ] && ok "two signatures without helper" || no "signature count without helper"

# 3. Developer ID identity: timestamp and Bastion.entitlements.
mkapp; mkdir -p "$T/B.app/Contents/Helpers"; : > "$T/B.app/Contents/Helpers/bastion-plugin-host"
run "Developer ID Application: Test" || true
[ "$(grep -- '--sign' "$T/log" | grep -c -- '--timestamp')" = 3 ] && ok "identity: timestamp on all three" || no "identity timestamp"
grep -- '--sign' "$T/log" | grep -q -- "--entitlements Bastion.entitlements .*B.app$" && ok "identity: app uses Bastion.entitlements" || no "identity app entitlements"

# 4. Refusals.
mkapp; mkdir -p "$T/B.app/Contents/Helpers"; : > "$T/B.app/Contents/Helpers/bastion-plugin-host"; : > "$T/B.app/Contents/Helpers/extra"
if run -; then no "stray file in Helpers accepted"; else grep -q "unexpected file" "$T/out" && ok "stray file in Helpers refused" || no "stray refusal message"; fi
[ ! -s "$T/log" ] && ok "nothing signed after a refusal" || no "signed before refusing"
mkapp; mkdir -p "$T/B.app/Contents/Helpers"; ln -s /bin/sh "$T/B.app/Contents/Helpers/bastion-plugin-host"
if run -; then no "symlinked helper accepted"; else ok "symlinked helper refused"; fi
mkapp; rm "$T/B.app/Contents/Frameworks/libbastion_rdp.dylib"
if run -; then no "missing dylib accepted"; else ok "missing dylib refused"; fi

# 5. The entitlement files themselves.
grep -q allow-unsigned-executable-memory BastionPluginHelper.entitlements && ok "helper file has allow-unsigned-executable-memory" || no "helper file key"
[ "$(grep -c '<key>' BastionPluginHelper.entitlements)" = 1 ] && ok "helper file has one key only" || no "helper file key count"
for f in Bastion.adhoc.entitlements Bastion.entitlements; do
  ! grep -q allow-unsigned-executable-memory "$f" && ok "$f lacks the helper's key" || no "$f holds the helper's key"
done
command -v plutil >/dev/null && { plutil -lint BastionPluginHelper.entitlements >/dev/null && ok "plutil lint" || no "plutil lint"; }
python3 -c "import plistlib,sys; d=plistlib.load(open(sys.argv[1],'rb')); assert d=={'com.apple.security.cs.allow-unsigned-executable-memory': True}" BastionPluginHelper.entitlements && ok "helper plist parses to exactly the one key" || no "helper plist parse"

echo "$pass passed, $fail failed"
[ "$fail" = 0 ]
