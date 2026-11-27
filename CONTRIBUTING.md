# Contributing to Gantry

Thanks for helping. Gantry is a remote-administration workstation (SSH, SFTP, RDP, VNC, web,
credentials) with one Rust core and two native apps: macOS (SwiftUI) and Windows (WinUI 3).

## Reporting

- **Security problems:** never in a public issue. Use GitHub's private vulnerability reporting
  (Security tab, "Report a vulnerability"). See [SECURITY.md](SECURITY.md).
- **Bugs:** open an issue with the app (Mac or Windows), its version (About window), the OS
  version, what you did, what you expected and what happened. Remove host names, user names and
  addresses from logs before you attach them.
- **Ideas:** open an issue first, before writing code, so we can agree on the shape.

## Building and testing

[docs/TESTING.md](docs/TESTING.md) has the prerequisites and commands. Before you open a pull
request:

1. `cd core && cargo test` (and the crates you touched: `core-ffi`, `core-cabi`, `rdp-ffi`).
2. Build the app you changed (Mac: `sh scripts/ci-mac.sh`; Windows: see TESTING).
3. `sh scripts/secret-scan.sh --tree`.

## Changes

- One topic per pull request; keep it small. Branch from `main`.
- Commit messages: `<type>: <description>`, type one of feat, fix, refactor, docs, test, chore,
  perf.
- Tests change with the code: add or update tests for what you changed.
- A feature should reach both apps. If your change adds something users can see or do in one app
  only, say so in the pull request so the other app can follow.
- Nothing may weaken security or need the internet: the app must work fully offline. Network
  features stay opt-in.
- UI text is short and plain: one line, details in tooltips, warnings only when something is
  risky.
- New dependencies need a reason in the pull request and must pass `sh scripts/deny.sh`.

## Licence

Gantry is Apache-2.0 ([LICENSE](LICENSE)). By contributing you agree your contribution is
licensed under the same terms.
