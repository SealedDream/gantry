#!/bin/sh
# Revocation drill (PLUG-15). Runbook: docs/plugins/OPERATIONS.md, "Revocation drill".
#
#   scripts/plugin-revocation-drill.sh [report-file]
#
# Runs the whole revocation path with THROWAWAY keys made in a temporary folder and deleted at
# the end. It never touches the real keys, the published catalogue or the network.
#   1. The signing tool: three new keys (active index, spare index, official), an Official
#      record, an index with it, an index that revokes the version, and a spare-key index that
#      revokes the active key. Each output is checked by the core verifier.
#   2. The app side: core/tests/plugin_revocation_drill.rs (install, revoke, load refused,
#      revocation kept; stolen key revoked by the spare, floor reset, stolen-key indexes refused).
# It prints the time each signing step took; the target is a signed revocation within one hour
# of a confirmed report. Exit 0 only when every step passed.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SIGN="$ROOT/scripts/plugin-sign.sh"
REPORT=${1:-}
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT INT TERM
log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$W/report.txt"; }
step() { # <name> <command...>: time a step; stop the drill on the first failure
  name=$1; shift
  t0=$(date +%s)
  if "$@" > "$W/out.txt" 2> "$W/err.txt"; then
    log "PASS $name ($(( $(date +%s) - t0 )) s)"
  else
    log "FAIL $name"; sed 's/^/    /' "$W/err.txt" | tee -a "$W/report.txt"; exit 1
  fi
}
expect_fail() { # <name> <command...>: the command must be refused
  name=$1; shift
  if "$@" > "$W/out.txt" 2> "$W/err.txt"; then log "FAIL $name (was accepted)"; exit 1; fi
  log "PASS $name (refused: $(tail -1 "$W/err.txt"))"
}

# Throwaway passphrase, made here and never printed or stored outside the temporary folder.
PASS=$(python3 -I -c 'import secrets; print(secrets.token_urlsafe(24))')
export PASS
TOOL="cargo run --quiet --offline --manifest-path $ROOT/core/Cargo.toml --example plugin_sign --"

log "DRILL start $(date -u +%Y-%m-%dT%H:%M:%SZ), throwaway keys in a temporary folder"
step "build the signing tool" sh -c "cd '$ROOT/core' && cargo build --quiet --offline --example plugin_sign"
for k in active:index spare:index official:official; do
  step "keygen ${k%%:*}" sh -c "printf '%s\n' \"\$PASS\" | '$SIGN' keygen ${k#*:} '$W/${k%%:*}.key'"
done
pub() { "$SIGN" pubkey "$W/$1.key" | awk '/^public key/ {print $3}'; }
A=$(pub active) B=$(pub spare) O=$(pub official)
echo '{}' > "$W/p.json"
$TOOL envelope "$W/p.json" > "$W/e.json"
expect_fail "an index key may not sign as official" sh -c "printf '%s\n' \"\$PASS\" | $TOOL sign official '$W/active.key' '$W/e.json'"
expect_fail "a wrong passphrase is refused" sh -c "printf 'wrong-passphrase-0123456789\n' | INDEX_KEY='$W/active.key' '$SIGN' index 1 7"
expect_fail "a key file is never overwritten" sh -c "printf '%s\n' \"\$PASS\" | '$SIGN' keygen index '$W/active.key'"

printf 'drill package bytes\n' > "$W/pkg.bastionplugin"
printf '{"network":"entry","credentials":"entry","storage":true,"clipboard":"write","files":["save"]}' > "$W/perms.json"
COMMIT=0123456789abcdef0123456789abcdef01234567
step "sign an Official record (two keys)" sh -c "pp() { printf '%s\n%s\n' \"\$PASS\" \"\$PASS\"; }; pp | INDEX_KEY='$W/active.key' OFFICIAL_KEY='$W/official.key' '$SIGN' record bastion.drill 1.0.0 official '$W/pkg.bastionplugin' '$W/perms.json' 1.0 1.0 https://github.com/example/drill $COMMIT > '$W/rec.sig'"
step "verify the record is Official" sh -c "'$SIGN' verify-record '$W/rec.sig' $A,$B $O | grep -q 'Official'"
expect_fail "the record without the official key is refused" "$SIGN" verify-record "$W/rec.sig" "$A,$B" -
step "sign index 10 with the record" sh -c "printf '%s\n' \"\$PASS\" | INDEX_KEY='$W/active.key' '$SIGN' index 10 21 '$W/rec.sig' > '$W/i10.json'"
step "verify index 10" "$SIGN" verify-index "$W/i10.json" "$A,$B" "$O"

printf '[{"id":"bastion.drill","from":"1.0.0","to":"1.0.0","reason":"Drill: revoked."}]' > "$W/revs.json"
t_report=$(date +%s)
step "sign index 11 revoking bastion.drill 1.0.0" sh -c "printf '%s\n' \"\$PASS\" | REVOCATIONS='$W/revs.json' INDEX_KEY='$W/active.key' '$SIGN' index 11 21 '$W/rec.sig' > '$W/i11.json'"
step "verify index 11 carries the revocation" sh -c "'$SIGN' verify-index '$W/i11.json' $A,$B $O | grep -q 'revocations 1'"
log "TIME report-to-signed-revocation $(( $(date +%s) - t_report )) s (target: under 3600 s)"

step "spare key signs index 12 revoking the active key" sh -c "printf '%s\n' \"\$PASS\" | REVOKED_KEYS=$A INDEX_KEY='$W/spare.key' '$SIGN' index 12 21 > '$W/i12.json'"
step "verify index 12 revokes one key" sh -c "'$SIGN' verify-index '$W/i12.json' $A,$B $O | grep -q 'revoked-keys 1'"
expect_fail "an index from the revoked key is refused" "$SIGN" verify-index "$W/i11.json" "$A,$B" "$O" "$A"
expect_fail "a record from the revoked key is refused" "$SIGN" verify-record "$W/rec.sig" "$A,$B" "$O" "$A"

step "app side: core/tests/plugin_revocation_drill.rs" sh -c "cd '$ROOT/core' && cargo test --quiet --offline --test plugin_revocation_drill"
PASS=
log "DRILL done: all steps passed"
[ -z "$REPORT" ] || cp "$W/report.txt" "$REPORT"
