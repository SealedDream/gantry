#!/bin/sh
# Regenerate apps/windows/Assets/Bastion.ico (light taskbar) and Bastion-dark.ico (dark taskbar) from the masters here.
# 16 and 24 px (and 20, from the 24 grid) use the simplified pixel-aligned glyphs; 32 px and up use the full glyph.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out="$here/../../../apps/windows/Assets"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
for theme in "" "-dark"; do
  list=""
  for px in 16 20 24 32 40 48 64 256; do
    case $px in 16) src="bastion-win-16$theme.svg" ;; 20|24) src="bastion-win-24$theme.svg" ;; *) src="bastion-win$theme.svg" ;; esac
    swift "$here/render-png.swift" "$here/$src" "$px" "$tmp/$px$theme.png"
    list="$list $tmp/$px$theme.png"
  done
  # shellcheck disable=SC2086
  python3 "$here/pack-ico.py" "$out/Bastion$theme.ico" $list
done
echo "wrote $out/Bastion.ico and $out/Bastion-dark.ico"
