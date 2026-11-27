#!/bin/sh
# Test run with the internet blocked (owner rule: Bastion must work fully offline).
# BASTION_OFFLINE=1 makes the core refuse every destination off this machine and the LAN before
# any packet is sent, so only the LAN test servers (docs/TESTING.md) can be reached. Optional
# online features (update check, OpenH264) must fail at once and quietly.
# Usage: scripts/offline-test.sh   (start the test containers first for the live SSH tests)
set -eu
cd "$(dirname "$0")/.."
export BASTION_OFFLINE=1 BASTION_SSH_TEST="${BASTION_SSH_TEST:-1}" BASTION_SSH_KEY="${BASTION_SSH_KEY:-/tmp/bastion-test-key}"
(cd core && cargo test)
(cd core-ffi && cargo test)
(cd core-cabi && cargo test)
(cd rdp-ffi && cargo test --lib)
echo "offline test run: all suites passed with BASTION_OFFLINE=1"
