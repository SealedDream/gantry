#!/bin/sh
# Wasmtime advisory watch (PLUG-15). Runbook: docs/plugins/OPERATIONS.md, "Wasmtime advisory watch".
#
#   scripts/wasmtime-advisory-watch.sh                      ask GitHub's advisory database
#   scripts/wasmtime-advisory-watch.sh --from-file <json>   read a saved answer (tests, offline)
#
# Finds every Wasmtime pin (`wasmtime = { version = "=X.Y.Z" ... }`) in the repository's
# Cargo.toml files and lists the published advisories that affect each pinned version.
# Exit: 0 nothing affects a pin; 3 an advisory affects a pin (critical or high: ship a release
# within 7 days, see the runbook); 1 the check could not run (treat as unknown, not as clean).
#
# Maintainer tool only: it needs the network, and nothing in the app runs it. It sends no
# identifiers beyond the public package name and version; `gh` is used when present (it adds
# the maintainer's GitHub login), else anonymous `curl`.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

PINS=$(cd "$ROOT" && git ls-files '*Cargo.toml' | while read -r f; do
  sed -n 's/^wasmtime *= *{ *version *= *"=\([0-9][0-9.]*\)".*/\1/p' "$f" | sed "s|^|$f |"
done)
[ -n "$PINS" ] || { echo "no exact Wasmtime pin found (every pin must be =X.Y.Z)" >&2; exit 1; }
VERSIONS=$(printf '%s\n' "$PINS" | awk '{print $2}' | sort -u)

if [ "${1:-}" = --from-file ]; then
  [ $# -eq 2 ] || { sed -n '2,6p' "$0" >&2; exit 2; }
  for v in $VERSIONS; do cp "$2" "$TMP/adv-$v.json"; done
else
  for v in $VERSIONS; do
    path="advisories?ecosystem=rust&affects=wasmtime@$v&per_page=100"
    if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
      timeout 60 gh api -H 'Accept: application/vnd.github+json' "/$path" > "$TMP/adv-$v.json" || { echo "advisory query failed for $v" >&2; exit 1; }
    else
      timeout 60 curl -fsS --proto =https -H 'Accept: application/vnd.github+json' "https://api.github.com/$path" > "$TMP/adv-$v.json" || { echo "advisory query failed for $v" >&2; exit 1; }
    fi
  done
fi

printf '%s\n' "$PINS" > "$TMP/pins.txt"
python3 -I - "$TMP" <<'PY'
import json, os, re, sys
tmp = sys.argv[1]
pins = [l.split() for l in open(os.path.join(tmp, "pins.txt")) if l.strip()]

def parse(v):
    m = re.fullmatch(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", v.strip())
    return tuple(int(x or 0) for x in m.groups()) if m else None

def in_range(version, rng):
    """GitHub ranges: comma-separated clauses such as '>= 40.0.0, < 48.0.9' or '= 1.2.3'."""
    v = parse(version)
    for clause in (c.strip() for c in rng.split(",") if c.strip()):
        m = re.fullmatch(r"(>=|<=|>|<|=)?\s*([\d.]+)", clause)
        if not m or parse(m.group(2)) is None:
            return True  # an unreadable range counts as affected: never report clean by mistake
        op, b = m.group(1) or "=", parse(m.group(2))
        if not {"<": v < b, "<=": v <= b, ">": v > b, ">=": v >= b, "=": v == b}[op]:
            return False
    return True

found, severe = 0, 0
for version in sorted({p[1] for p in pins}):
    try:
        advisories = json.load(open(os.path.join(tmp, f"adv-{version}.json")))
    except ValueError:
        sys.exit("the advisory answer is not JSON")
    where = ", ".join(f for f, v in pins if v == version)
    for adv in advisories if isinstance(advisories, list) else []:
        for vuln in adv.get("vulnerabilities") or []:
            pkg = (vuln.get("package") or {})
            if pkg.get("name") != "wasmtime" or (pkg.get("ecosystem") or "").lower() not in ("rust", "crates.io"):
                continue
            if not in_range(version, vuln.get("vulnerable_version_range") or ""):
                continue
            sev = (adv.get("severity") or "unknown").lower()
            found += 1
            severe += sev in ("critical", "high")
            print(f"AFFECTED wasmtime {version} ({where}): {adv.get('ghsa_id')} {sev.upper()} "
                  f"fixed in {vuln.get('first_patched_version') or 'no fix yet'}: {adv.get('summary', '').strip()}")
            break
print(f"pins: {' '.join(sorted({p[1] for p in pins}))}; advisories affecting them: {found} ({severe} critical or high)")
sys.exit(3 if found else 0)
PY
