#!/bin/sh
# Prebuilt core and RDP outputs on the Mac (BUILD-SPEED-02). Sourced by apps/macos/build-core.sh
# and build-rdp.sh.
#
# The first build of a new worktree used to compile the whole Rust core, its dependencies and the
# RDP library (25-35 min) even when the branch changes only Swift. Now each clean build stores its
# outputs (the XCFramework and Swift bindings, or the RDP dylib and bindings) in
# ~/Bastion-prebuilt/<name>-<key>/, and a later build with the same key copies them (APFS clone,
# seconds) instead of compiling.
#
# The key is a SHA-256 over the git tree hashes of the source folders (for the core: core/ and
# core-ffi/, which hold Cargo.lock), the build script and this file, the variant (test hooks or
# not), `rustc -vV` and MACOSX_DEPLOYMENT_TARGET. Git tree hashes cover every tracked file's
# content, so a branch that changed nothing there gets the same key as origin/main, and any change
# gives a new one: never a name or a commit alone. A source folder with uncommitted changes gets no
# key and builds as before. Each entry has a SHA256SUMS file that is checked before every copy; an
# entry that fails the check is ignored and the build runs.
#
# `scripts/warm-worktree.sh --refresh` runs both build scripts on origin/main, so every merge batch
# fills the cache. Any session's clean build fills it too.
# BASTION_NO_PREBUILT=1 turns it off. The newest BASTION_PREBUILT_KEEP entries of each name are kept.

BASTION_PREBUILT_DIR=${BASTION_PREBUILT_DIR:-$HOME/Bastion-prebuilt}
BASTION_PREBUILT_KEEP=${BASTION_PREBUILT_KEEP:-4}

# bastion_prebuilt_key <repo-root> <variant> <path...>
# Prints the key, or nothing when these outputs must be built (turned off, not a git checkout,
# uncommitted changes under a path, no rustc).
bastion_prebuilt_key() {
  _pk_root=$1; _pk_var=$2; shift 2
  [ "${BASTION_NO_PREBUILT:-}" = 1 ] && return 0
  git -C "$_pk_root" rev-parse -q --verify HEAD >/dev/null 2>&1 || return 0
  _pk_dirty=$(git -C "$_pk_root" status --porcelain -- "$@" 2>/dev/null) || return 0
  if [ -n "$_pk_dirty" ]; then echo "prebuilt: uncommitted changes under $*; building" >&2; return 0; fi
  _pk_rustc=$(rustc -vV 2>/dev/null) || return 0
  _pk_in="variant=$_pk_var
MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET:-}
$_pk_rustc"
  for _pk_p in "$@"; do
    _pk_h=$(git -C "$_pk_root" rev-parse -q --verify "HEAD:$_pk_p" 2>/dev/null) || return 0
    _pk_in="$_pk_in
$_pk_p $_pk_h"
  done
  printf '%s\n' "$_pk_in" | shasum -a 256 | cut -c1-40
}

# bastion_prebuilt_restore <key> <name> <dest-dir> <entry...>
# Replaces each <dest-dir>/<entry> with the cached copy. Returns 1, having changed nothing, when
# there is no entry for the key or it fails its checksum.
bastion_prebuilt_restore() {
  _pr_key=$1; _pr_name=$2; _pr_dest=$3; shift 3
  [ -n "$_pr_key" ] || return 1
  _pr_src="$BASTION_PREBUILT_DIR/$_pr_name-$_pr_key"
  [ -f "$_pr_src/SHA256SUMS" ] || return 1
  for _pr_e in "$@"; do [ -e "$_pr_src/out/$_pr_e" ] || return 1; done
  if ! (cd "$_pr_src/out" && shasum -a 256 -s -c ../SHA256SUMS); then
    echo "prebuilt: $_pr_name-$_pr_key fails its checksum; building" >&2; return 1
  fi
  mkdir -p "$_pr_dest" || return 1
  for _pr_e in "$@"; do
    rm -rf "${_pr_dest:?}/$_pr_e"
    # -c: APFS clone (no extra disk); -p: keep times. Falls back to a plain copy.
    cp -c -R -p "$_pr_src/out/$_pr_e" "$_pr_dest/$_pr_e" 2>/dev/null || cp -R -p "$_pr_src/out/$_pr_e" "$_pr_dest/$_pr_e" || return 1
  done
  touch "$_pr_src"   # the newest used entries are the ones kept
  echo "prebuilt: $_pr_name from $_pr_src ($(sed -n 's/^commit //p' "$_pr_src/INFO" 2>/dev/null))" >&2
}

# bastion_prebuilt_save <key> <name> <dest-dir> <entry...>
# Stores the entries just built. Never fails the build: a problem only skips the cache.
bastion_prebuilt_save() {
  _ps_key=$1; _ps_name=$2; _ps_dest=$3; shift 3
  [ -n "$_ps_key" ] || return 0
  _ps_final="$BASTION_PREBUILT_DIR/$_ps_name-$_ps_key"
  [ -d "$_ps_final" ] && return 0
  mkdir -p "$BASTION_PREBUILT_DIR" || return 0
  _ps_tmp="$BASTION_PREBUILT_DIR/.tmp-$_ps_name-$$"; rm -rf "$_ps_tmp"; mkdir -p "$_ps_tmp/out" || return 0
  for _ps_e in "$@"; do
    cp -c -R -p "$_ps_dest/$_ps_e" "$_ps_tmp/out/$_ps_e" 2>/dev/null || cp -R -p "$_ps_dest/$_ps_e" "$_ps_tmp/out/$_ps_e" || { rm -rf "$_ps_tmp"; return 0; }
  done
  (cd "$_ps_tmp/out" && find . -type f -print0 | sort -z | xargs -0 shasum -a 256) > "$_ps_tmp/SHA256SUMS" || { rm -rf "$_ps_tmp"; return 0; }
  { echo "commit $(git rev-parse --short HEAD 2>/dev/null)"; echo "built $(date '+%Y-%m-%d %H:%M')"; } > "$_ps_tmp/INFO"
  # A rename is atomic: a reader sees the whole entry or none. Another build may have won the race.
  # (When it did, mv puts the temp folder inside the existing entry: remove that copy.)
  if [ -d "$_ps_final" ]; then rm -rf "$_ps_tmp"; else mv "$_ps_tmp" "$_ps_final" 2>/dev/null || rm -rf "$_ps_tmp"; fi
  rm -rf "${_ps_final:?}/${_ps_tmp##*/}"
  echo "prebuilt: stored $_ps_final" >&2
  ls -dt "$BASTION_PREBUILT_DIR/$_ps_name"-* 2>/dev/null | tail -n +"$((BASTION_PREBUILT_KEEP + 1))" | while IFS= read -r _ps_old; do rm -rf "$_ps_old"; done
  return 0
}
