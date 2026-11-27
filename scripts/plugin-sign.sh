#!/bin/sh
# Plugin catalogue signing (PLUG-15). Runbook: docs/plugins/OPERATIONS.md.
#
#   scripts/plugin-sign.sh keygen <index|official> <key-file>
#   scripts/plugin-sign.sh pubkey <key-file>
#   scripts/plugin-sign.sh record <id> <version> <external|official> <package> <permissions.json> \
#                                 <api-min> <api-max> <source-repo-url> <source-commit>   > <id>-<version>.sig
#   scripts/plugin-sign.sh index <sequence> <days-valid> [record.sig ...]                  > plugin-index.json
#   scripts/plugin-sign.sh verify-record <file> <index-keys> <official-keys> [revoked-index-keys]
#   scripts/plugin-sign.sh verify-index  <file> <index-keys> <official-keys> [revoked-index-keys]
#   scripts/plugin-sign.sh pinned <index-keys> <official-keys>
#
# Keys: INDEX_KEY and OFFICIAL_KEY name encrypted key files (made by keygen). Key lists are
# comma-separated hex public keys. For `index`: REVOCATIONS names a JSON file with a list of
# {"id","from","to","reason"} (default none) and REVOKED_KEYS is a comma-separated list of
# index public keys to revoke (default none).
#
# Passphrases are asked on the terminal without echo. When standard input is not a terminal
# (the revocation drill), one line is read from it per key. Never put a passphrase in an
# argument, an environment variable or a file in this repository.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
usage() { sed -n '2,20p' "$0" >&2; exit 2; }
[ $# -ge 1 ] || usage
CMD=$1
shift

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

abs() { case "$1" in /*) printf '%s' "$1" ;; *) printf '%s/%s' "$(pwd)" "$1" ;; esac; }

# The example binary, built once (offline: no new crates; core's own dependencies only).
tool() {
  (cd "$ROOT/core" && cargo run --quiet --offline --example plugin_sign -- "$@")
}

# One passphrase line for the tool on its standard input.
ask() {
  if [ -t 0 ]; then
    printf '%s' "$1" >&2
    stty -echo
    IFS= read -r pass || { stty echo; exit 1; }
    stty echo
    printf '\n' >&2
  else
    IFS= read -r pass || { echo "no passphrase on standard input" >&2; exit 1; }
  fi
  printf '%s\n' "$pass"
  pass=
}

sign_with() { # <purpose> <key-file> <envelope-file>
  ask "Passphrase for $(basename "$2"): " | tool sign "$1" "$(abs "$2")" "$3"
}

case "$CMD" in
  keygen)
    [ $# -eq 2 ] || usage
    out=$(abs "$2")
    if [ -t 0 ]; then
      a=$(ask "New passphrase (16+ characters): ")
      b=$(ask "Again: ")
      [ "$a" = "$b" ] || { a= b=; echo "the passphrases differ" >&2; exit 1; }
      printf '%s\n' "$a" | tool keygen "$1" "$out"
      a= b=
    else
      ask "" | tool keygen "$1" "$out"
    fi
    ;;
  pubkey)
    [ $# -eq 1 ] || usage
    tool pubkey "$(abs "$1")"
    ;;
  record)
    [ $# -eq 9 ] || usage
    ID=$1 VERSION=$2 TIER=$3 PACKAGE=$4 PERMS=$5 API_MIN=$6 API_MAX=$7 REPO=$8 COMMIT=$9
    case "$TIER" in external|official) ;; *) echo "tier must be external or official" >&2; exit 2 ;; esac
    case "$REPO" in https://*) ;; *) echo "source repository must be https" >&2; exit 2 ;; esac
    : "${INDEX_KEY:?set INDEX_KEY to the index key file}"
    [ "$TIER" = external ] || : "${OFFICIAL_KEY:?an Official record needs OFFICIAL_KEY}"
    python3 -I - "$ID" "$VERSION" "$TIER" "$PACKAGE" "$PERMS" "$API_MIN" "$API_MAX" "$REPO" "$COMMIT" > "$TMP/payload.json" <<'PY'
import hashlib, json, re, sys
id_, version, tier, package, perms, api_min, api_max, repo, commit = sys.argv[1:]
if not re.fullmatch(r"[0-9a-f]{40}", commit):
    sys.exit("source commit must be a full 40-character lower-case hex commit")
data = open(package, "rb").read()
print(json.dumps({
    "schema": 1, "id": id_, "version": version, "tier": tier,
    "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
    "api": {"min": api_min, "max": api_max},
    "permissions": json.load(open(perms)),
    "source": {"repository": repo, "commit": commit},
}, separators=(",", ":")))
PY
    tool envelope "$TMP/payload.json" > "$TMP/env0.json"
    sign_with release-record "$INDEX_KEY" "$TMP/env0.json" > "$TMP/env1.json"
    if [ "$TIER" = official ]; then
      sign_with official "$OFFICIAL_KEY" "$TMP/env1.json" > "$TMP/env2.json"
      cat "$TMP/env2.json"
    else
      cat "$TMP/env1.json"
    fi
    ;;
  index)
    [ $# -ge 2 ] || usage
    SEQ=$1 DAYS=$2
    shift 2
    : "${INDEX_KEY:?set INDEX_KEY to the index key file}"
    [ "$DAYS" -ge 1 ] && [ "$DAYS" -le 30 ] || { echo "days-valid must be 1 to 30 (the app refuses more than 31)" >&2; exit 2; }
    python3 -I - "$SEQ" "$DAYS" "${REVOCATIONS:-}" "${REVOKED_KEYS:-}" "$@" > "$TMP/payload.json" <<'PY'
import json, re, sys, time
seq, days, revocations, revoked_keys = sys.argv[1:5]
records = [json.load(open(p)) for p in sys.argv[5:]]
revs = json.load(open(revocations)) if revocations else []
for r in revs:
    if set(r) != {"id", "from", "to", "reason"}:
        sys.exit("each revocation has exactly id, from, to, reason")
keys = [k.strip() for k in revoked_keys.split(",") if k.strip()]
for k in keys:
    if not re.fullmatch(r"[0-9a-f]{64}", k):
        sys.exit("revoked keys are 64 lower-case hex characters")
now = int(time.time())
print(json.dumps({
    "schema": 1, "sequence": int(seq), "issued": now, "expires": now + int(days) * 86400,
    "records": records, "revocations": revs, "revoked_keys": keys,
}, separators=(",", ":")))
PY
    tool envelope "$TMP/payload.json" > "$TMP/env0.json"
    sign_with index "$INDEX_KEY" "$TMP/env0.json"
    ;;
  verify-record|verify-index)
    [ $# -ge 3 ] || usage
    f=$(abs "$1"); shift
    tool "$CMD" "$f" "$@"
    ;;
  pinned)
    [ $# -eq 2 ] || usage
    tool pinned "$1" "$2"
    ;;
  *) usage ;;
esac
