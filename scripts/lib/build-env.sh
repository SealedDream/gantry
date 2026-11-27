#!/bin/sh
# Build environment for the Mac (BUILD-SPEED-01). Source it:  . scripts/lib/build-env.sh
# Used by scripts/build-slot.sh, scripts/warm-worktree.sh, apps/macos/build-core.sh and build-rdp.sh.
#
# 1. Compiler cache: sets RUSTC_WRAPPER to sccache when sccache is installed and answers. Without
#    sccache nothing is set and the build runs as before. BASTION_NO_SCCACHE=1 turns it off.
#    The cache is outside the repository, in SCCACHE_DIR, and is limited to SCCACHE_CACHE_SIZE.
# 2. Build slots: the number of slots for this machine (BASTION_SLOTS, the one place it is set),
#    the job count per build, and the memory gate and queue that build-slot.sh waits in.
#
# The Windows machines do not use this file: their builds are PowerShell and have their own cache.

# --- limits (one place) -------------------------------------------------------------------------
BASTION_SLOTS=${BASTION_SLOTS:-2}                 # heavy builds at once on this Mac (8 cores, 16 GB)
BASTION_MIN_JOBS=2                                # never fewer compile jobs than this
BASTION_MIN_FREE_MB=${BASTION_MIN_FREE_MB:-2048}  # a second build waits under this much free memory
BASTION_MIN_SWAP_FREE_MB=${BASTION_MIN_SWAP_FREE_MB:-1024}  # ... or when swap is nearly full
# (swap in use stays near 10 GB on this Mac even when idle, so the gate looks at what is left).
BASTION_SLOT_STALE_MIN=${BASTION_SLOT_STALE_MIN:-90}
BASTION_SLOT_POLL_SECS=${BASTION_SLOT_POLL_SECS:-15}
BASTION_PRIORITY_AHEAD=1000000000                 # build-slot.sh --priority: seconds a priority job jumps

# --- compiler cache -----------------------------------------------------------------------------
if [ -z "${RUSTC_WRAPPER:-}" ] && [ "${BASTION_NO_SCCACHE:-}" != 1 ]; then
  _bastion_sc=$(command -v sccache 2>/dev/null || true)
  if [ -z "$_bastion_sc" ] && [ -x "$HOME/.cargo/bin/sccache" ]; then _bastion_sc="$HOME/.cargo/bin/sccache"; fi
  if [ -n "$_bastion_sc" ] && "$_bastion_sc" --version >/dev/null 2>&1; then
    export RUSTC_WRAPPER="$_bastion_sc"
    export SCCACHE_DIR="${SCCACHE_DIR:-$HOME/Library/Caches/Mozilla.sccache}"
    export SCCACHE_CACHE_SIZE="${SCCACHE_CACHE_SIZE:-10G}"
  fi
  unset _bastion_sc
fi

# --- stable linker for cache hits across worktrees (BUILD-SPEED-02) --------------------------------
# rustc links proc-macros as dylibs whose install name is their absolute output path, so they differ
# per worktree and every crate using them (tokio, thiserror, zeroize, russh ...) missed sccache in a
# new worktree. lib/link-cc.sh names them @rpath/<file>. It is installed at one fixed path, because
# the linker path is part of every rustc command line and so of every cache key.
# Measured: a second target folder went from 145 to 148 of 155 hits for the same crates, and the
# crates that use derive macros now hit. The crates that still miss read env!("OUT_DIR"), an
# absolute path that sccache hashes as it is.
if [ -n "${RUSTC_WRAPPER:-}" ] && [ "$(uname -s)" = Darwin ] && [ "${BASTION_NO_STABLE_LINKER:-}" != 1 ]; then
  _bastion_lk="$HOME/Library/Caches/bastion-build/link-cc"
  # Callers cd into one of the crates (build-core.sh, build-rdp.sh). The root comes from git, or,
  # in a tree without .git (the public export), from the nearest parent holding this file.
  _bastion_root=$(git rev-parse --show-toplevel 2>/dev/null) || _bastion_root=$(
    d=$PWD; while [ "$d" != / ] && [ ! -f "$d/scripts/lib/link-cc.sh" ]; do d=${d%/*}; d=${d:-/}; done; echo "$d")
  _bastion_lk_src="$_bastion_root/scripts/lib/link-cc.sh"
  if [ -f "$_bastion_lk_src" ] && ! cmp -s "$_bastion_lk_src" "$_bastion_lk"; then
    mkdir -p "${_bastion_lk%/*}" && cp "$_bastion_lk_src" "$_bastion_lk.$$" && chmod 755 "$_bastion_lk.$$" && mv "$_bastion_lk.$$" "$_bastion_lk"
  fi
  if [ -x "$_bastion_lk" ]; then
    : "${CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER:=$_bastion_lk}"; export CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER
    : "${CARGO_TARGET_X86_64_APPLE_DARWIN_LINKER:=$_bastion_lk}"; export CARGO_TARGET_X86_64_APPLE_DARWIN_LINKER
  fi
  unset _bastion_lk _bastion_lk_src _bastion_root
fi

# --- machine readings (the BASTION_FAKE_* values are for scripts/tests/build-env-test.sh) --------
bastion_ncpu() {
  if [ -n "${BASTION_FAKE_NCPU:-}" ]; then echo "$BASTION_FAKE_NCPU"; return; fi
  sysctl -n hw.ncpu 2>/dev/null || echo 4
}

# Memory a new build can take without swapping: free, inactive, speculative and purgeable pages.
bastion_mem_free_mb() {
  if [ -n "${BASTION_FAKE_FREE_MB:-}" ]; then echo "$BASTION_FAKE_FREE_MB"; return; fi
  vm_stat 2>/dev/null | awk '
    /page size of/ { for (i = 1; i <= NF; i++) if ($i == "of") ps = $(i + 1) }
    /^Pages (free|inactive|speculative|purgeable):/ { v = $NF; sub(/\.$/, "", v); s += v }
    END { if (ps == 0) print 999999; else printf "%d\n", s * ps / 1048576 }'
}

# Swap still free. macOS grows the swap file as it needs; "nearly full" means this is small.
bastion_swap_free_mb() {
  if [ -n "${BASTION_FAKE_SWAP_FREE_MB:-}" ]; then echo "$BASTION_FAKE_SWAP_FREE_MB"; return; fi
  sysctl -n vm.swapusage 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "free") { v = $(i + 2); sub(/M$/, "", v); printf "%d\n", v; f = 1 } } END { if (!f) print 999999 }'
}

# Prints why a new build should wait and returns 0; returns 1 when memory is fine.
bastion_mem_block() {
  _bm_free=$(bastion_mem_free_mb); _bm_swap=$(bastion_swap_free_mb)
  if [ "$_bm_free" -lt "$BASTION_MIN_FREE_MB" ]; then
    echo "free memory is ${_bm_free} MB (limit ${BASTION_MIN_FREE_MB} MB)"; return 0
  fi
  if [ "$_bm_swap" -lt "$BASTION_MIN_SWAP_FREE_MB" ]; then
    echo "swap is nearly full: ${_bm_swap} MB free (limit ${BASTION_MIN_SWAP_FREE_MB} MB)"; return 0
  fi
  return 1
}

# bastion_jobs <builds running, this one included>: cores divided by the builds, never under
# BASTION_MIN_JOBS. A CARGO_BUILD_JOBS set by the caller is kept when it is lower.
bastion_jobs() {
  _bj_n=${1:-1}; [ "$_bj_n" -ge 1 ] || _bj_n=1
  _bj=$(( $(bastion_ncpu) / _bj_n ))
  [ "$_bj" -ge "$BASTION_MIN_JOBS" ] || _bj=$BASTION_MIN_JOBS
  case "${CARGO_BUILD_JOBS:-}" in
    ''|*[!0-9]*) ;;
    *) if [ "$CARGO_BUILD_JOBS" -ge 1 ] && [ "$CARGO_BUILD_JOBS" -lt "$_bj" ]; then _bj=$CARGO_BUILD_JOBS; fi ;;
  esac
  echo "$_bj"
}

# --- build-slot queue ---------------------------------------------------------------------------
# Slots whose owner is gone: a slot with a pid file is removed when that pid is dead; a slot
# without one (older build-slot.sh) is removed after BASTION_SLOT_STALE_MIN minutes.
_bastion_slots_reap() {
  for _bs in "$1"/slot*; do
    [ -d "$_bs" ] || continue
    if [ -f "$_bs/pid" ]; then
      kill -0 "$(cat "$_bs/pid" 2>/dev/null)" 2>/dev/null || rm -rf "$_bs"
    else
      find "$_bs" -maxdepth 0 -mmin +"$BASTION_SLOT_STALE_MIN" -exec rm -rf {} + 2>/dev/null
    fi
  done
}

_bastion_slot_owners() {
  for _bo in "$1"/slot*/owner; do [ -f "$_bo" ] && cut -d' ' -f1,2 "$_bo"; done 2>/dev/null | tr '\n' ',' | sed 's/,$//; s/,/, /g'
}

# bastion_slot_wait <slot-dir> <session-name> <max-slots> [priority]
# Waits, first come first served (a priority job goes ahead of every normal one, see build-slot.sh), until a slot is free and memory allows one more build. While it
# waits it says on stderr what it waits for (queue position, slot owners, memory) and keeps the
# same line in <slot-dir>/queue/<time>-<pid>, so anyone can read the queue. A build that would be
# the only one running never waits for memory: waiting would not free any.
# On return CARGO_BUILD_JOBS and BASTION_JOBS are set for this build (pass BASTION_JOBS to
# `swift build -j`). The caller takes its slot right after.
bastion_slot_wait() {
  _sw_dir=$1; _sw_name=$2; _sw_max=$3; _sw_prio=${4:-}
  _sw_q="$_sw_dir/queue"; mkdir -p "$_sw_q"
  # The queue is sorted by the number before the dash. A priority job files itself
  # BASTION_PRIORITY_AHEAD seconds earlier, so it is ahead of every normal job and, among
  # priority jobs, still first come first served. Older build-slot.sh copies sort the same way.
  _sw_t=$(date +%s); [ -n "$_sw_prio" ] && _sw_t=$((_sw_t - BASTION_PRIORITY_AHEAD))
  _sw_me="$_sw_q/$_sw_t-$$"; echo "$_sw_name: queued${_sw_prio:+ (priority)}" > "$_sw_me"
  trap 'rm -f "$_sw_me"' EXIT
  trap 'rm -f "$_sw_me"; exit 130' INT TERM HUP
  _sw_said=""; _sw_tick=0
  while :; do
    _bastion_slots_reap "$_sw_dir"
    for _sw_f in "$_sw_q"/[0-9]*; do
      [ -e "$_sw_f" ] || continue
      kill -0 "${_sw_f##*-}" 2>/dev/null || rm -f "$_sw_f"
    done
    _sw_used=$(ls -d "$_sw_dir"/slot* 2>/dev/null | wc -l | tr -d ' ')
    _sw_total=$(ls "$_sw_q" | grep -c '^[0-9]')
    _sw_pos=$(ls "$_sw_q" | grep '^[0-9]' | sort -t- -k1,1n -k2,2n | grep -n -x "${_sw_me##*/}" | cut -d: -f1)
    _sw_why=""
    if [ "${_sw_pos:-1}" != 1 ]; then
      _sw_why="queue position $_sw_pos of $_sw_total; slots in use $_sw_used of $_sw_max ($(_bastion_slot_owners "$_sw_dir"))"
    elif [ "$_sw_used" -ge "$_sw_max" ]; then
      _sw_why="queue position 1 of $_sw_total; all $_sw_max slots in use ($(_bastion_slot_owners "$_sw_dir"))"
    elif [ "$_sw_used" -ge 1 ] && _sw_mem=$(bastion_mem_block); then
      _sw_why="queue position 1 of $_sw_total; a slot is free but $_sw_mem"
    fi
    [ -n "$_sw_why" ] || break
    # Say it when it changes, and again every 5 minutes so a waiting session is never silent.
    if [ "$_sw_why" != "$_sw_said" ] || [ "$_sw_tick" -ge 300 ]; then
      echo "build-slot: $_sw_name waits $(date '+%H:%M'): $_sw_why" >&2
      echo "$_sw_name: $_sw_why" > "$_sw_me"
      _sw_said=$_sw_why; _sw_tick=0
    fi
    sleep "$BASTION_SLOT_POLL_SECS"; _sw_tick=$((_sw_tick + BASTION_SLOT_POLL_SECS))
  done
  # Stay at the head of the queue for two more seconds, while the caller takes its slot, so the
  # next in line cannot pass on the same free slot.
  trap - EXIT INT TERM HUP
  ( sleep 2; rm -f "$_sw_me" ) >/dev/null 2>&1 &
  CARGO_BUILD_JOBS=$(bastion_jobs $((_sw_used + 1))); BASTION_JOBS=$CARGO_BUILD_JOBS
  export CARGO_BUILD_JOBS BASTION_JOBS
  echo "build-slot: $_sw_name${_sw_prio:+ (priority)} starts $(date '+%H:%M') with $BASTION_JOBS jobs ($((_sw_used + 1)) of $_sw_max slots in use)" >&2
}
