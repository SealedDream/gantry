# Architecture — Gantry

## Decision summary
**One shared Rust core, four apps:** Native Mac, Native Windows, Tauri Mac and Tauri Windows. The goal is the same features in all four (owner, 2026-11-10; `docs/tasks/PARITY.md`). Work goes to the two native apps first and reaches Tauri after they are proven.

The two native apps:

| Layer | macOS | Windows |
|---|---|---|
| UI | SwiftUI + AppKit (NSOutlineView tree, NSWindow tabs) | WinUI 3 (Windows App SDK, C#) |
| Bridge | UniFFI-generated Swift bindings | `core-cabi` C ABI + P/Invoke (see "Native interop on Windows") |
| Core | `bastion-core` (Rust): model, persistence, vault, import/export, automation, sessions | same crate |
| Secret store adapter | Keychain + LocalAuthentication (Touch ID) | Credential Manager / DPAPI + Windows Hello |
| Web connections | WKWebView (non-persistent data store per connection) | WebView2 (per-connection user data folder) |

The Tauri app (`ui-tauri`) is one Svelte front end in a Tauri 2 webview (WKWebView on macOS, WebView2 on Windows). Its Rust side links `bastion-core` directly, with no UniFFI or C ABI in between, and RDP runs in the sidecar `bastion-rdp-helper`. It was adopted after the spike of 2026-11-02 (`docs/TAURI_SPIKE.md`: terminal, RDP frame path, memory and security gates all passed), and it has been kept beside the native apps since the audit of 2026-11-03. The first version of this document listed Tauri under the alternatives; the spike's measurements replaced that judgement.

### Why not alternatives
- **Electron**: a web UI that ships its own browser engine; heavier than the system webview that Tauri uses.
- **Qt**: one UI on both, but non-native feel on macOS, LGPL/commercial licensing friction, C++ protocol glue.
- **.NET everywhere (Avalonia/MAUI)**: MAUI on macOS is Catalyst-based and weak for pro tools; RDP options in .NET are thin.
- **Two fully separate apps**: doubles protocol work — protocol code is the hardest, most security-critical part and must be shared.

Rust gives memory-safe protocol code, mature permissively licensed libraries, and a C ABI that both Swift and C# consume cheaply.

## Protocol libraries (licenses checked against crates.io metadata — re-verify on each bump)
| Protocol | Library | License | Notes |
|---|---|---|---|
| SSH / SFTP / tunnels | `russh`, `russh-sftp` | Apache-2.0 | pure Rust, agent, keyboard-interactive, forwarding |
| RDP | `ironrdp` (Devolutions) | MIT/Apache-2.0 | NLA/CredSSP, TLS, clipboard, drive redirection; rendered into a native surface. RD Gateway is not planned (owner 2026-11-03) |
| VNC/RFB | `vnc-rs` | MIT/Apache-2.0 | ARD auth (type 30) is reverse-engineered; documented as best-effort |
| FTP/FTPS | `suppaftp` | Apache-2.0 | |
| Terminal emulation | `alacritty_terminal` (core) | Apache-2.0 | rendered by native views (Metal / Direct2D) |
| Crypto | RustCrypto `chacha20poly1305`, `argon2` | MIT/Apache-2.0 | audited AEAD; no custom crypto |

FreeRDP (Apache-2.0) was considered; IronRDP chosen because it is Rust-native (no C build chain on two OSes, memory safety) and actively maintained by a commercial vendor. FreeRDP remains the fallback if a needed channel (e.g. printer redirection) is missing.

## Core module boundaries (`core/src`)
- `model` — documents, folders, connections, inheritance resolution, tags, favorites
- `store` — atomic persistence, versioned snapshots, corruption detection, optimistic concurrency (revision counter)
- `vault` — encrypted portable credential store (Argon2id → XChaCha20-Poly1305), zeroized secrets
- `vars` — task variable substitution with secret-leak guard
- `import` — OpenSSH config, CSV, `.rdp` files, Royal JSON, PuTTY `.reg`, RDCMan `.rdg`
- `search` — unified search
- `session` — session lifecycle state machine (see "Concurrency & lifecycle")
- `ssh`, `sftp`, `scp`, `ftp`, `ftps`, `vnc`, `tunnel`, `gateway` — protocol adapters. RDP is not in the core; it is the separate `rdp-ffi` library (see below)
- `logins` — the ordered list of logins for a connection: several logins per connection, folder inheritance, and the offer of a login saved for the same host under another protocol
- `personal`, `docfile` — the Personal library and other libraries as encrypted `.bastion` documents
- (planned) `plugin` — `docs/specs/plugins.md`

This is not the full list; `core/src/lib.rs` is.

## Expanded scope (master update, 2026-11-01)
The shared-core + native-frontends decision holds for every new requirement. Gap analysis and ordering are in AUDIT.md. New core modules planned: `session`, `workspace`, `pty` (local shells, WSL via ConPTY), `terminal` (wrapping `alacritty_terminal`), `ipc` (companion CLI), `credentials` (provider trait: local vault, OS keychain, Bitwarden/Vaultwarden via official CLI), `hypervisor` (provider trait + `proxmox`, `vsphere`, later `hyperv`), `sshconfig` (full OpenSSH resolution).

Status on 2026-11-12: these exist on `main`, some under other names (the module list above and `core/src/lib.rs` are current). The exception is `hypervisor` with its `proxmox`, `vsphere` and `hyperv` adapters: no app used the trait and `core/src/hypervisor.rs` was removed (task `DEAD-01-HYPERVISOR`, owner decision D4 of 2026-11-12). Proxmox and VMware are plugins, not built-in code (owner, 2026-11-14: `PLUG-PVE-01`, `PLUG-VMW-01` in `docs/specs/plugins.md`).

**Terminal:** `alacritty_terminal` is used as a library (VT parsing, grid, scrollback, selection, regex search). It is never launched as a separate app. Rendering is ours (Metal on macOS, Direct2D/DirectWrite on Windows), so the terminal lives inside our tabs and splits.

**Terminal (implemented):** `core/src/terminal.rs` owns a `Term` + VTE `Processor` per session and a byte backend (local PTY via `portable-pty`, or an SSH channel driven by a Tokio task). The UI never sees escape sequences: it polls a generation counter and pulls a `Screen` snapshot with colours resolved to RGB. `core-ffi` exposes `Terminal` and `SessionManager` (connect through the orchestrator; unknown host keys come back as a typed `HostKeyUnknown` error). The macOS view is a plain `NSView` drawing with AppKit text; a Metal renderer is a later optimisation.

**Security boundaries kept separate:** app lock (Touch ID / Windows Hello) ≠ vault unlock ≠ remote-server auth ≠ enterprise IdP. The shell IPC can ask the app to open a saved connection by name; it can never read secrets or run commands.

## Shared SSH configs (optional, local only)
Team-shared configs are just local files the user pulls themselves. Gantry never talks to GitLab or Git. `sshconfig` reads them read-only (`Discovery { scan_config_d }` makes the `config.d` scan optional); `sshworkflow::WorkflowStore` (`ssh-workflow.json` next to the library) is the separate store (keyed by the stable identity) holds personal values and placeholder answers; a `sources` snapshot (per-file hash) lets the app detect changes after a manual pull and show added/changed/removed before refreshing. Each part (config.d discovery, placeholders, overrides, change detection) is independently switchable, and manual connections need none of it. Placeholders and overrides are applied in memory in `core-ffi` right before the orchestrator connects; a host with unanswered placeholders returns `NeedsConfiguration`.

## Tunnels and gateways (implemented)
`SshSession::connect_via(jumps, target)` dials the first hop over TCP. Each later hop runs over a `direct-tcpip` channel of the previous one (`connect_stream`), with independent host-key verification and authentication per hop. Jump sessions live as long as the final session does. `tunnel.rs` owns its listeners only; stopping a tunnel aborts its own task and never signals other processes. Remote forwards accept only ports this session requested.

## Concurrency & lifecycle
All network I/O runs on a Tokio runtime owned by the core; the UI receives events over a callback interface. Every session is an explicit state machine (`core/src/session.rs`): `Idle → Connecting → Authenticating → Connected → Disconnecting → Closed`, plus `Failed(reason)`, `Reconnecting{attempt}` and `Suspended` (sleep). `spawn_supervised` drives one session: it reconnects with `ReconnectPolicy` back-off, never auto-retries authentication failures, drops the link on `Sleep` and reconnects on `Wake`, and stops at once on `Cancel`, even mid-connect or mid-backoff. Protocol adapters implement `Link`.

## IPC and companion CLI
`core/src/ipc.rs`: the running app listens on `<data dir>/bastion.sock` (mode 0600, the peer uid must equal ours). Each connection carries one JSON request line and one JSON response line, capped at 64 KiB, with a `PROTOCOL_VERSION` that both sides check (3 on 2026-11-12; the constant is in `core/src/ipc.rs`). Requests include `ping` and `open {name, files}`. Secrets never cross IPC. On Windows the app listens on a named pipe instead, `\\.\pipe\bastion<flavour>-<user SID>-<hash of the data folder>`, open to the current user only; the client must present a per-launch token and its SID is checked. Native and Tauri use separate pipes and tokens, so both can run side by side (built and tested: AUDIT.md, "Companion CLI"). `cli/` builds `bastion`: `list` reads the library file directly, and `ping` and `open` use IPC.

## Workspaces and hypervisors
`core/src/workspace.rs`: per-user `workspaces.json` next to the library, never in a shared document. It holds connection ids and tab modes only. The old `core/src/hypervisor.rs` (a `HypervisorProvider` trait for Proxmox, ESXi and vCenter) is gone (`DEAD-01-HYPERVISOR`); Proxmox and VMware come as plugins.

## Storage
Documents are JSON (`*.bastion.json`), written atomically (temp file + fsync + rename), mode 0600 on Unix. The last N revisions are kept in `backups/`. Secrets never live in documents — only credential IDs.

That paragraph describes the first, plain-JSON library. Since #703 and #720 (2026-11-07/08) the Personal library is one encrypted `.bastion` document that also holds its credentials (`core/src/personal.rs`, `core/src/docfile.rs`); the old `library.json` and vault are migrated into it once. Exported libraries still leave secrets out by default.

## Native interop on Windows: `core-cabi` (decided 2026-11-02, extended 2026-11-03)
**Why not UniFFI C# bindings.** `core-ffi` uses uniffi 0.32. The released `uniffi-bindgen-cs` (v0.11.1) generates for uniffi 0.31; generated bindings must match the library's uniffi contract version, and 0.32 support exists only as unmerged upstream PRs (#176, #183). Downgrading `core-ffi` would break the macOS bindings. So the WinUI app talks to a small hand-written C ABI instead. Revisit when a released generator supports the uniffi version in use; do not rewrite merely because one appears.

**Shape.** `core-cabi` is a separate `cdylib` that depends on `bastion-ffi` and only forwards to it (`Library`, `Terminal`); it adds no behaviour of its own and `core-ffi`'s API is unchanged. It is platform-neutral Rust, so a macOS (or any other) host can load the same surface; macOS currently uses the UniFFI Swift bindings instead.

**Rules every function follows** (tested in `core-cabi/tests`):
- *Ownership:* objects are opaque handles (`Box::into_raw`) released by exactly one `*_free`; strings and snapshots returned to the host are owned by the host and released with `bastion_string_free` / `bastion_screen_free`. Hosts free each handle once (the C# wrappers zero the handle before freeing).
- *Strings:* UTF-8, NUL-terminated, both directions; interior NULs are dropped; invalid UTF-8 input is an error, not a panic.
- *Errors:* `char **err` out-parameter (NULL on success, an owned message otherwise); a NULL `err` is allowed. Return values signal failure (NULL handle or -1).
- *Panics:* every entry point runs inside `catch_unwind`; a panic becomes an error, never an unwind across the boundary.
- *NULL and ranges:* NULL handles and pointers are rejected with an error; terminal sizes are limited to 1–1000; out-of-range selection coordinates are clamped by the core.
- *Threads:* library calls are serialised by the core's mutex; terminal calls may come from any thread concurrently (tested with 4 threads). Freeing a handle while another thread still uses it is the host's responsibility to prevent.
- *Versioning:* `bastion_abi_version()` returns `ABI_VERSION`, which is 95 on 2026-11-12 and rises with every change to the surface. Do not rely on a number quoted here: read the constant and the version history above it in `core-cabi/src/lib.rs`, and `docs/tasks/ABI-LEDGER.md` for numbers taken and free. The C# host refuses to start against a different version. Struct layouts (`BastionCell` 16 bytes, `BastionScreen` 56 bytes on x64) are asserted by the host at startup.
- *Secrets:* the host hands secrets in (a typed password, a key passphrase) and they are not returned, with one exception. A saved password is released to the host for the in-process RDP client, which needs it for the connect call just as it needs a typed one: `release_login` and `rdp_login_for` in `core-ffi`, `bastion_credentials_release_login_json` and `bastion_credentials_rdp_login_json` in this ABI. The release is made only for a credential in that connection's own login list (`core/src/logins.rs`), and every release is written to the audit log as `credential.release.rdp`. No other call returns a stored secret.
- *Loading and packaging:* `bastion_cabi.dll` sits next to `Gantry.exe` (copied by the build from `apps/windows/native`, produced by `build-core.ps1`); the process loads it from the application directory. Code signing and an integrity check of the DLL are release-pipeline work (not done).

**Terminal snapshots** are flat: one allocation holding `cols*rows` fixed-size cells (colours, attribute flags, offset/length into one UTF-8 text buffer) plus cursor, modes, alive flag and generation. Hosts poll the cheap `generation` call and copy a snapshot only when it moves.

## WinUI rendering constraints (measured, Windows 10)
On the development machine any running composition animation keeps a core busy (see docs/TESTING.md, "WinUI CPU spin"). Until that is understood on more hardware, the Windows app avoids animated templates where it has a choice: Button styles without `BrushTransition` (`Themes/Buttons.xaml`), a button-strip instead of `TabView`, a plain toolbar instead of `CommandBar` (stock AppBarButton templates carry BrushTransition), an in-window modal instead of `ContentDialog`, no item/content transitions, hidden scrollbars, a non-blinking terminal cursor. New controls must pass the idle-CPU budget before they ship.

**UI structure (redesign, 2026-11-02).** Design tokens are XAML resource dictionaries (`Themes/Colors.xaml` with Light/Dark/HighContrast theme dictionaries, `Tokens.xaml`, `Icons.xaml`, `Buttons.xaml`) merged in `App.xaml`; `MainWindow.xaml` has no literals and code-built UI reads tokens through `Ui.cs`, which looks brushes up per element theme. Window chrome stays the system title bar (themed through `AppWindowTitleBar.PreferredTheme`), so nothing extra animates in the app's compositor. Details: docs/UI_REDESIGN.windows.md.

## Property schema and inheritance (core)
`core/src/properties.rs` is the single source for editable properties; frontends render whatever it returns, so settings the core ignores are never offered. Effective value order: connection → nearest folder … root → `Document.type_defaults[protocol]` → protocol built-in. `core/src/catalog.rs` describes connection types and their support level for Add menus on every platform.

## RDP: separate `rdp-ffi` dynamic library (decided 2026-11-02)
IronRDP cannot share a Cargo graph with russh 0.65: IronRDP's `picky` pins `curve25519-dalek =5.0.0-rc.1` while russh needs `^5` (5.0.0), and the IronRDP 0.14–0.17 meta crates clash the same way. So RDP lives in the standalone crate `rdp-ffi/` (`bastion_rdp`), built as a **cdylib** with its own UniFFI module and loaded next to `bastion-ffi`. A second Rust *static* lib in the same binary would duplicate std symbols. It depends on the individual IronRDP crates (connector 0.12, session 0.13, tokio 0.12, tls 0.3 with rustls), not on the `ironrdp` meta crate.
- It cannot link `bastion-core`, so it runs its own connect/run loop rather than `session::spawn_supervised`; the frontend owns reconnect.
- TLS trust is pinned per host like SSH host keys: the first connect fails with `CertificateUnknown { fingerprint }` (SHA-256 of the leaf), and the user verifies the fingerprint and retries with `trusted_fingerprint`.
- The password goes in for one `connect` call and is never stored or returned. Kerberos is not supported (NTLM via CredSSP only).
- macOS embedding: `apps/macos/build-rdp.sh` builds a universal `libbastion_rdp.dylib` (install name `@rpath/libbastion_rdp.dylib`) and its Swift bindings into `Generated/rdp/`. `Package.swift` links it through a `systemLibrary` (`BastionRdpFFI`) plus the `BastionRdp` bindings target, with rpaths for the binary's own folder, `Contents/Frameworks` (an app bundle must copy the dylib there) and `Generated/rdp/lib` for development builds. `RdpView` polls `frame` at 30 Hz, copies a frame only when the serial changed, and letterboxes it; input is mapped from macOS key codes to set-1 scancodes (position-based, the remote layout decides characters; ⌘ is the Windows key). Certificate pins live app-side in `<data dir>/rdp_certificates.json` until `core` gets an RDP-aware trust store.
