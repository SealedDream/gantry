# Testing

How to build Gantry and run its tests on your own machine. Everything here works without any
private infrastructure; tests that need a live server start it in a local container first.

## Prerequisites

- Rust (stable) with the WebAssembly target the plugin tests build for:
  `rustup target add wasm32-wasip2`
- Mac: Xcode 16 or later (Swift 6), macOS 14 or later.
- Windows: Visual Studio 2022 Build Tools (C++ and .NET desktop workloads), .NET 10 SDK,
  Windows App SDK; Windows 10 22H2 or Windows 11.
- Docker or Podman, only for the live-service tests.

## Unit tests (no network, no services)

```bash
cd core && cargo test
cd core-ffi && cargo test
cd core-cabi && cargo test
cd rdp-ffi && cargo test
cd plugins && cargo test
```

Tests that need a live service (SSH, FTPS, PostgreSQL, VNC, Vault, Vaultwarden, Keychain, PAM,
host certificates) are `#[ignore]`d. A plain `cargo test` reports them as ignored, never as
passed. Each one needs its `BASTION_*_TEST` variable and `-- --include-ignored`; a live test run
without its variable fails rather than skipping.

## SSH integration tests (local OpenSSH container)

1. Make a throwaway key (never a real one):
   ```bash
   ssh-keygen -q -t ed25519 -N "" -f /tmp/gantry-test-key -C gantry-test
   ```
2. Start a test server bound to localhost:
   ```bash
   docker run -d --name gantry-sshd -p 127.0.0.1:2222:2222 -e USER_NAME=tester \
     -e USER_PASSWORD=test-pass-123 -e PASSWORD_ACCESS=true \
     -e PUBLIC_KEY="$(cat /tmp/gantry-test-key.pub)" lscr.io/linuxserver/openssh-server:latest
   ```
3. The suite fails logins on purpose, so relax two OpenSSH DoS limits **on this test server
   only**:
   ```bash
   docker exec gantry-sshd sh -c 'printf "PerSourcePenalties no\nMaxStartups 100:30:200\n" >> /config/sshd/sshd_config'
   docker restart gantry-sshd
   ```
4. Run:
   ```bash
   cd core && BASTION_SSH_TEST=1 BASTION_SSH_KEY=/tmp/gantry-test-key cargo test --test ssh_integration -- --include-ignored
   ```

`docs/testservers/` has Dockerfiles for the PAM keyboard-interactive and systemd SSH servers some
tests use. Remove the containers when you are done.

## Offline run

The app must work fully offline. `sh scripts/offline-test.sh` runs the core, UniFFI, C ABI and
RDP suites with `BASTION_OFFLINE=1`: the core then refuses every destination that is not
loopback, private, link-local or CGNAT before a packet is sent (`core/src/offline.rs`).

## Mac app

```bash
sh scripts/ci-mac.sh
```

runs the core and core-ffi tests, builds the FFI library and Swift bindings, makes a release
build of the app, and checks the Markdown tables. For a debug run:

```bash
sh apps/macos/build-core.sh && cd apps/macos && swift build && swift run
```

The small logic suites in `apps/macos/tests/` each have a `*-test.sh` runner, for example
`sh apps/macos/tests/tags-test.sh`.

## Windows app

```powershell
cd apps\windows
powershell -File build-core.ps1            # builds core-cabi, copies the DLL to native\
dotnet build -c Release -p:Platform=x64
```

The unit and console projects in `apps\windows\tests\` (`*-unit`, `*-console`) run with
`dotnet run --project apps\windows\tests\<name>`.

## Release checks

- `sh scripts/secret-scan.sh --tree`: provider tokens and private keys in tracked files.
- `sh scripts/deny.sh`: licences, advisories and sources of every Rust dependency (cargo-deny).
- `sh scripts/audit-deps.sh`: RustSec advisories.
- `sh scripts/release-checks.sh`: the checks above, for a release tag.
