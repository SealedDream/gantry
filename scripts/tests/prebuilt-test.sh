#!/bin/sh
# BUILD-SPEED-02: scripts/lib/prebuilt.sh and scripts/lib/link-cc.sh, on a throwaway git repo.
# No cargo build, nothing outside a temp folder. About 5 s.
#   sh scripts/tests/prebuilt-test.sh
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
pass=0; fail=0
ok() { if [ "$2" = "$3" ]; then pass=$((pass + 1)); else fail=$((fail + 1)); echo "FAIL $1: got '$2', want '$3'"; fi; }
has() { case "$2" in *"$3"*) pass=$((pass + 1)) ;; *) fail=$((fail + 1)); echo "FAIL $1: '$3' not in '$2'" ;; esac; }
BASTION_PREBUILT_DIR="$T/cache"; BASTION_PREBUILT_KEEP=2; unset BASTION_NO_PREBUILT
. "$ROOT/scripts/lib/prebuilt.sh"

R="$T/repo"; mkdir -p "$R/core" "$R/ui"; cd "$R" || exit 1
git init -q; git config user.email t@t; git config user.name t
echo a > core/lib.rs; echo s > ui/app.swift; git add .; git commit -qm one
k1=$(bastion_prebuilt_key "$R" plain core)
ok "key is 40 hex" "$(printf %s "$k1" | grep -c '^[0-9a-f]\{40\}$')" 1
ok "same tree, same key" "$(bastion_prebuilt_key "$R" plain core)" "$k1"
[ "$(bastion_prebuilt_key "$R" test-hooks core)" != "$k1" ]; ok "variant changes the key" $? 0
echo t > ui/app.swift; git commit -qam ui-only
ok "a change outside the folders keeps the key" "$(bastion_prebuilt_key "$R" plain core)" "$k1"
echo dirty > core/lib.rs
ok "uncommitted change: no key" "$(bastion_prebuilt_key "$R" plain core 2>/dev/null)" ""
git checkout -q core/lib.rs; echo new > core/new.rs
ok "untracked file in the folder: no key" "$(bastion_prebuilt_key "$R" plain core 2>/dev/null)" ""
rm core/new.rs
ok "BASTION_NO_PREBUILT=1: no key" "$(BASTION_NO_PREBUILT=1 bastion_prebuilt_key "$R" plain core)" ""
echo b > core/lib.rs; git commit -qam core
k2=$(bastion_prebuilt_key "$R" plain core)
[ "$k2" != "$k1" ]; ok "a committed change in the folder changes the key" $? 0
ok "a missing folder: no key" "$(bastion_prebuilt_key "$R" plain core nosuch)" ""

# save and restore
O="$T/out"; mkdir -p "$O/lib" "$O/swift" "$O/other"; echo bin1 > "$O/lib/x.a"; echo sw1 > "$O/swift/x.swift"; echo keep > "$O/other/y"
bastion_prebuilt_restore "$k1" core "$O" lib swift; ok "nothing cached: restore fails" $? 1
bastion_prebuilt_save "$k1" core "$O" lib swift 2>/dev/null
ok "saved with checksums" "$(wc -l < "$BASTION_PREBUILT_DIR/core-$k1/SHA256SUMS" | tr -d ' ')" 2
echo changed > "$O/lib/x.a"; rm -rf "$O/swift"
bastion_prebuilt_restore "$k1" core "$O" lib swift 2>/dev/null; ok "restore succeeds" $? 0
ok "restored content" "$(cat "$O/lib/x.a") $(cat "$O/swift/x.swift")" "bin1 sw1"
ok "other folders untouched" "$(cat "$O/other/y")" keep
bastion_prebuilt_save "$k1" core "$O" lib swift 2>/dev/null
ok "second save does not nest" "$(ls "$BASTION_PREBUILT_DIR/core-$k1" | tr '\n' ' ')" "INFO SHA256SUMS out "
echo tampered > "$BASTION_PREBUILT_DIR/core-$k1/out/lib/x.a"; echo mine > "$O/lib/x.a"
has "tampered entry is refused" "$(bastion_prebuilt_restore "$k1" core "$O" lib swift 2>&1; echo rc=$?)" "fails its checksum"
ok "tampered entry changes nothing" "$(cat "$O/lib/x.a")" mine
bastion_prebuilt_restore "$k1" core "$O" lib swift nosuch 2>/dev/null; ok "missing entry: restore fails" $? 1
bastion_prebuilt_save "" core "$O" lib 2>/dev/null; ok "empty key: nothing saved" "$(ls "$BASTION_PREBUILT_DIR" | grep -c .)" 1
for k in k3 k4 k5; do sleep 1; bastion_prebuilt_save "$k" core "$O" lib 2>/dev/null; done
ok "only the newest entries are kept" "$(ls "$BASTION_PREBUILT_DIR" | tr '\n' ' ')" "core-k4 core-k5 "
ok "no temp folders left" "$(ls -a "$BASTION_PREBUILT_DIR" | grep -c '^\.tmp')" 0

# link-cc.sh: adds @rpath/<file> to dylibs without an install name, passes everything else on
mkdir -p "$T/bin"; printf '#!/bin/sh\nfor a in "$@"; do printf "%%s|" "$a"; done\n' > "$T/bin/cc"; chmod +x "$T/bin/cc"
lk() { PATH="$T/bin:/usr/bin:/bin" sh "$ROOT/scripts/lib/link-cc.sh" "$@"; }
ok "proc-macro dylib gets @rpath name" "$(lk -arch arm64 -dynamiclib -o /a/b/libm-1.dylib x.o)" "-arch|arm64|-dynamiclib|-o|/a/b/libm-1.dylib|x.o|-Wl,-install_name,@rpath/libm-1.dylib|"
ok "named dylib unchanged" "$(lk -dynamiclib -Wl,-install_name,@rpath/q.dylib -o /a/q.dylib)" "-dynamiclib|-Wl,-install_name,@rpath/q.dylib|-o|/a/q.dylib|"
ok "executable unchanged" "$(lk -o /a/bin x.o)" "-o|/a/bin|x.o|"

echo "prebuilt-test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
