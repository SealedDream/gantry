#!/bin/sh
# Time limits for commands (macOS has no `timeout`). Source it, or run it:
#   . scripts/lib/with-timeout.sh
#   with_timeout <seconds> <command...>         limit one process
#   with_timeout_group <seconds> <command...>   run the command in its own process group and
#                                               kill the whole group at the limit
#   sh scripts/lib/with-timeout.sh [-g] <seconds> <command...>
# Exit status: the command's own, or 124 when the limit was hit (one line on stderr says so).
# A command can exit 124 by itself. To be sure the limit was hit, set BASTION_TIMEOUT_MARK to a
# file path: the file is created only when the limit is hit (the command does not inherit it).
# A TERM, INT or HUP sent to the watcher is passed on to the command, so nothing is left behind.

_with_timeout() {
  perl -e '
    my ($group, $secs, @cmd) = @ARGV;
    my $mark = delete $ENV{BASTION_TIMEOUT_MARK};
    my $pid = fork();
    die "with-timeout: fork failed: $!\n" unless defined $pid;
    if ($pid == 0) { setpgrp(0, 0) if $group; exec @cmd or do { print STDERR "with-timeout: cannot run $cmd[0]: $!\n"; exit 127 } }
    my $target = $group ? -$pid : $pid;
    my $stop = sub { my $code = shift; kill "TERM", $target; select(undef, undef, undef, 1.0); kill "KILL", $target; waitpid($pid, 0); exit $code };
    $SIG{ALRM} = sub { if ($mark) { open(my $f, ">", $mark) and close $f } print STDERR "TIMEOUT after ${secs}s: @cmd\n"; $stop->(124) };
    $SIG{$_} = sub { $stop->(143) } for qw(TERM INT HUP);
    alarm $secs;
    waitpid($pid, 0);
    exit(($? & 127) ? 128 + ($? & 127) : $? >> 8);
  ' "$@"
}
with_timeout() { _with_timeout 0 "$@"; }
with_timeout_group() { _with_timeout 1 "$@"; }

case "${0##*/}" in
  with-timeout.sh)
    if [ "${1:-}" = -g ]; then shift; with_timeout_group "$@"; else with_timeout "$@"; fi ;;
esac
