#!/bin/sh
# BUILD-STAMP: print the commit a build is made from: the full SHA, plus "-dirty" when tracked files differ
# from it. Outside a git checkout (the public export tarball): $BASTION_BUILD_COMMIT when set, else "unknown". Used by apps/macos/uitests/build-app.sh and bundle.sh.
#   scripts/build-stamp.sh            print the stamp of the current checkout
#   scripts/build-stamp.sh check <stamp file> <expected>
#                                     exit 2 with a BUILD-STAMP MISMATCH line when the build is from another
#                                     commit (expected: full SHA or a prefix of 7+, optionally ending in -dirty)
set -u
stamp() {
  sha=$(git rev-parse HEAD 2>/dev/null) || { echo "${BASTION_BUILD_COMMIT:-unknown}"; return; }
  if [ -n "$(git status --porcelain --untracked-files=no 2>/dev/null)" ]; then echo "$sha-dirty"; else echo "$sha"; fi
}
[ "${1:-}" = check ] || { stamp; exit 0; }
file=$2; want=$(printf '%s' "$3" | tr 'A-F' 'a-f')
got=$(head -1 "$file" 2>/dev/null | tr -d '[:space:]')
want_sha=${want%-dirty}; got_sha=${got%-dirty}
want_dirty=no; case "$want" in *-dirty) want_dirty=yes ;; esac
got_dirty=no; case "$got" in *-dirty) got_dirty=yes ;; esac
if [ -n "$got" ] && [ ${#want_sha} -ge 7 ] && [ "$want_dirty" = "$got_dirty" ]; then
  case "$got_sha" in "$want_sha"*) echo "BUILD-STAMP: $got matches $3"; exit 0 ;; esac
fi
echo "BUILD-STAMP MISMATCH: expected $3, the build is ${got:-missing ($file not found)}. Rebuild from the expected commit; the tests did not run."
exit 2
