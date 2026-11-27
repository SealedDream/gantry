#!/bin/sh
# Product rename check (Bastion -> Gantry, owner 2026-11-23): no string literal a user can see in the
# Native Mac, Native Windows, core, RDP or official plugin sources still says "Bastion".
# Internal names stay (crates, modules, C ABI bastion_* symbols, BASTION_* variables, the Bastion.Shell
# namespace, Notification names, file format markers). Lines that keep the old name on purpose (migration,
# legacy fallbacks, format markers) are listed in scripts/product-name-allowlist.txt as `path: literal`.
# Test sources are not checked. Exit 1 and list each hit when something is left.
set -eu
cd "$(dirname "$0")/.."
allow=scripts/product-name-allowlist.txt
files=$(git ls-files 'apps/macos/Sources/*.swift' 'apps/windows/*.cs' 'apps/windows/Interop/*.cs' 'apps/windows/*.xaml' \
  'core/src/*.rs' 'core-ffi/src/*.rs' 'core-cabi/src/*.rs' 'rdp-ffi/src/*.rs' 'plugins/official/*/src/*.rs' 'plugins/official/*/plugin.toml' \
  | grep -vE '(_tests?\.rs|/tests?(/|\.rs)|UIDriver|TestHook|SeedTestHook)')
perl -ne '
  BEGIN { open my $a, "<", shift @ARGV or die; while (<$a>) { chomp; next if /^#/ || !length; $ok{$_} = 1 } }
  $intest = 1 if /^\s*#\[cfg\(test\)\]/; $intest = 0 if $ARGV ne ($last // ""); $last = $ARGV;
  next if $intest || m{^\s*(//|///|\*)};
  while (/("(?:[^"\\\n]|\\.)*")/g) {
    my $lit = $1;
    next unless $lit =~ /\bBastion\b(?!_)(?!\.Shell)/;
    next if $ok{"$ARGV: $lit"};
    print "$ARGV:$.: $lit\n"; $bad++;
  }
  close ARGV if eof;
  END { exit($bad ? 1 : 0) }
' "$allow" $files && echo "product name check: no user-visible Bastion strings"
