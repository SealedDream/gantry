#!/bin/sh
# Linker for Rust builds on the Mac (BUILD-SPEED-02), installed by lib/build-env.sh at a fixed path.
# A dylib that rustc links without an install name (proc-macros, cdylibs) gets its absolute output
# path as install name, so the same proc-macro differs byte for byte between worktrees. Every crate
# that uses it (tokio, thiserror, zeroize, russh ...) then misses sccache in each new worktree.
# This gives such dylibs "@rpath/<file name>" instead. Proc-macros are loaded by path, so nothing
# else changes; build-rdp.sh sets the same name on libbastion_rdp.dylib afterwards anyway.
dylib=0; named=0; out=""; prev=""
for a in "$@"; do
  case "$a" in
    -dynamiclib) dylib=1 ;;
    *install_name*) named=1 ;;
  esac
  [ "$prev" = "-o" ] && out=$a
  prev=$a
done
if [ "$dylib" = 1 ] && [ "$named" = 0 ] && [ -n "$out" ]; then
  exec cc "$@" "-Wl,-install_name,@rpath/${out##*/}"
fi
exec cc "$@"
