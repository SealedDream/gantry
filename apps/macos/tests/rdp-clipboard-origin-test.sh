#!/bin/sh
# Native Mac SEC-6: RDP server clipboard text never crosses to another session (RdpClipboardOrigin.swift),
# and RdpView.swift uses the tag.
#   sh apps/macos/tests/rdp-clipboard-origin-test.sh
set -eu
cd "$(dirname "$0")/.."
grep -q 'RdpClipboardOrigin.markRemoteWrite' Sources/Bastion/RdpView.swift && grep -q 'RdpClipboardOrigin.mayOffer' Sources/Bastion/RdpView.swift \
  || { echo "FAIL RdpView.swift does not use RdpClipboardOrigin"; exit 1; }
echo "PASS RdpView tags server writes and checks before offering"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
swiftc -O -o "$T/rdp-clipboard-origin" Sources/Bastion/RdpClipboardOrigin.swift tests/rdp-clipboard-origin/main.swift
"$T/rdp-clipboard-origin"
