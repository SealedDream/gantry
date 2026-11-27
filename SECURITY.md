# Security

Last reviewed against `main`: 2026-11-22.

## Reporting a vulnerability
Report privately through GitHub: **Security › Report a vulnerability** on this repository (private vulnerability reporting). Do not open a public issue. Include the version, OS, steps to reproduce and the impact. You get an answer within 7 days; a fix ships as a new release and the advisory is published after it.

## Supported versions
| Version | Supported |
|---|---|
| Latest 1.x release | Yes |
| Older releases, pre-release builds | No: update first |

## Downloads are unsigned: check them
Builds are not signed with a paid Apple or Microsoft certificate (owner decision); the Mac app is signed ad hoc. Every release lists the SHA-256 of each file in `SHA256SUMS`. Check before you open a download:
```bash
shasum -a 256 -c SHA256SUMS --ignore-missing
```
On Windows: `Get-FileHash Gantry-windows-x64.zip -Algorithm SHA256`, and compare with the line in `SHA256SUMS`. In-app updates are separate: Check for Updates installs only a release whose Ed25519-signed manifest verifies against the key compiled into the app.

## Plugins
- **Signed packs and tiers.** A plugin is a WebAssembly component. Its release record is signed by an index key and, for **Official** plugins, co-signed by the official key; the public keys are pinned in `core/src/plugin/catalogue.rs`. **External** plugins are made by others and reviewed by us. A local file with no signed record is **Unverified**, off by default and installed only after an explicit question. A revoked version is switched off when the signed index is loaded. Every place the core names a plugin shows its tier.
- **Sandbox.** Each plugin runs in its own helper process inside the WebAssembly sandbox and an OS sandbox: a `sandbox_init` profile on macOS, an AppContainer with no capabilities in a job object on Windows. The helper has no network and no file access. The core verifies the sandbox from outside and kills a helper without one.
- **Grants.** A plugin reaches only the host of the library entry it was opened on, on the ports its signed manifest lists, through the entry's route (direct, gateway or tunnel). The core runs TLS; the plugin never holds keys, and `http` grants are limited to the manifest's paths and methods.
- **Logins (#1412).** The plugin never sees the password. For token or header logins the core inserts the credential into each request. For session logins (VMware ESXi) the core sends the login itself, keeps the session cookie, adds it to requests and strips `Set-Cookie`; login happens only on the pinned TLS connection to the entry host, no redirects are followed, re-logins back off after repeated failures, and the session is logged out when the plugin stops. Released secrets are checked against everything a plugin writes (logs, clipboard, storage).
- **Limits.** Memory, streams and connection rate are capped; a helper that hangs for 10 s is killed.

## PostgreSQL, Proxmox VE and VMware plugins
- TLS is an entry property owned by the core: verify-full (default), pinned (certificate fingerprint), or off. Off needs "Allow unencrypted" for a non-local destination, and managed policy can forbid it. A failed certificate check cannot be clicked through.
- **PostgreSQL:** no login or statement is sent before TLS is up unless the destination is loopback or the user allowed unencrypted. Cancel requests go in plaintext (as in PostgreSQL itself); they carry no data or credential.
- **Proxmox VE:** API token in the vault, sent by the core as the `Authorization` header; read-only `GET` on `/api2/json/`. Guest addresses come only from the QEMU guest agent, never from names or tags.
- **VMware ESXi / vCenter:** session login run by the core as above; self-signed hosts are pinned by fingerprint.

## Tunnels and Mosh
- Saved local, remote and SOCKS tunnels listen on `127.0.0.1` only and run over the SSH connection's strict host-key check.
- Mosh starts the local `mosh` client, which logs in with the system `ssh` (keys or agent; a password is typed in the terminal). Gantry's vault, jump hosts and gateways are not used for Mosh and such a connection is refused up front. After login, Mosh uses its own AES-OCB UDP channel.

## Status statement
This is pre-release software. **No certification, attestation or compliance claim is made.** The framework mapping in SECURITY_CONTROL_MATRIX.md records design intent and test evidence only. SOC 2, ISO 27001 and similar outcomes require organisational controls and independent assessment that do not exist yet.

The spec distinguishes five levels, and every control here is labelled with one:
1. Implemented in software → 2. verified by tests → 3. operated by an organisation → 4. assessed by an independent auditor → 5. certified. **Nothing here is above level 2.**

## Secure defaults (implemented today)
- Offline, no account, **no telemetry**, no network listeners except tunnels the user starts (loopback only).
- Strict SSH host-key checking; a changed key is always refused.
- Legacy plaintext protocols (Telnet, FTP) disabled unless explicitly risk-accepted. A managed policy can forbid them outright.
- No plaintext secrets in documents, backups or logs. Ordinary documents and plain exports hold credential IDs only; a **protected** document (and a protected export with `include_secrets`, `core/src/docfile.rs` `export`) holds credentials encrypted under its password, and its backups are equally encrypted. Owner-only file permissions: 0600/0700 on macOS/Unix, a single-user DACL on Windows (`core/src/winacl.rs`, see O1).
- Destructive actions always require confirmation (policy level; UI pending).
- Auto-reconnect off by default and never retries authentication failures.

## Untrusted SSH config input (`core/src/sshconfig.rs`)
- Never executes anything: `ProxyCommand` is stored verbatim and flagged; `Match` blocks (including `Match exec`) are recorded and never evaluated. A test asserts a `Match exec` side effect never happens.
- `Include` confined to the discovery root (plus explicitly allowed roots), checked lexically for `..` and again after symlink resolution; depth limit 16, cycle detection, 256-file limit.
- Files over 1 MiB, non-UTF-8 or containing NUL are refused with a warning, not parsed.
- Limitation: `Match` semantics are therefore not reproduced; affected hosts carry a `MatchBlocksIgnored` flag so the UI can say so.

## Credential broker (`core/src/broker.rs`)
- Cached secrets live only in memory, inside leases with two independent timers from unlock (inactivity 15 min, reset by use; absolute 60 min, never extended). Expired, locked or replaced secrets are zeroized on drop.
- Lease key = credential identity + customer scope; every lookup re-runs `check_credential_scope`.
- Expiry only forces a fresh unlock; live sessions keep their already-authenticated transport.
- Protected documents auto-lock on screen lock and sleep (`core/src/docunlock.rs`, `LockReason::ScreenLocked`). Not yet: verifying external `ssh-agent` key lifetimes. (Session reconnect after wake uses the broker's leases and never extends them.)

## Host-key trust in the connect path (`core/src/connect.rs`)
- Connections always run `HostKeyPolicy::Strict`. An unknown key returns its SHA-256 fingerprint; the key is recorded only by `connect_ssh_trusting` with that exact fingerprint (`HostKeyPolicy::TrustFingerprint`), and a mismatching fingerprint is refused. Tested against a real server: valid credentials alone never create a known_hosts entry.
- An authentication failure evicts the cached lease so a stale secret is not retried.

## Terminal and interactive connect (`core/src/terminal.rs`, `core-ffi/src/terminal.rs`)
- Secrets typed in the Connect sheet go to a one-shot provider with a fresh item id, then through the broker like any other secret; they are not written anywhere and the lease cannot be reused by another connection. The audit log records the connect and unlock, never the secret (asserted by the FFI test).
- Unknown host keys surface as a typed error; the UI shows the SHA-256 fingerprint with out-of-band verification guidance, and only "Trust and Connect" records it (`hostkey.trust` audit event). Changed keys stay refused.
- Test Connection follows the same rule (SEC-07). It never stores a key (a new key goes into a throwaway copy of known_hosts) and never sends a password to a host whose key is unknown: the report carries the fingerprint (`needs_host_key_confirmation`), and only a second test carrying that exact fingerprint, after the user's yes, tries the login. A changed key stops the test. A jump host with an unknown or changed key fails before its login. With no credential or no user name the key is checked by key exchange alone, so no login attempt reaches the server. Key and agent logins are still tried against a new key: they send a signature, not a secret. `HostKeyPolicy::AcceptNew` exists only under the `test-accept-new` cargo feature, which no app build enables.
- Bracketed paste strips embedded start/end markers so pasted text cannot break out of the bracket and execute (test `bracketed_paste_wraps_only_when_requested`).
- Local shells start with the user's login shell unchanged (only `TERM`/`COLORTERM` set); closing a tab signals only that tab's own child process.
- Not yet: terminal output is not logged (by design, no keystroke logging); OSC 52 clipboard writes are left at the library default and need a policy decision before clipboard support lands.

## RDP (`rdp-ffi/`, `apps/macos/Sources/Bastion/Rdp*.swift`)
- TLS server certificates are trusted on first use only after an explicit prompt with the SHA-256 fingerprint. The pin is stored per `host:port` in `<data dir>/rdp_certificates.json` only after a successful connect with that fingerprint. A different certificate is refused by `rdp-ffi`, and the prompt then says "Changed certificate" in red before the user can replace the pin. Verified against xrdp: the scripted connect without a pin is refused with the fingerprint, which matched `openssl x509 -outform DER | sha256sum` of the server's `cert.pem`.
- The password lives in the connect sheet's state, goes into one `connect` call and is cleared; it is not stored. `autologon` is on, so the credentials log on directly instead of being typed into the server's own login screen.
- Later work (2026-11-03 on) added text clipboard and one-folder drive redirection (threat model T15/T15b) and an NLA-only switch (`RdpTarget::nla_only`); server redirection is refused. Still not: printer redirection; pins in the audit log. The pin file is plain JSON (fingerprints are not secret). Per-platform test status is in `AUDIT.md`.

## VNC (`core/src/vnc.rs`, `apps/macos/Sources/Bastion/VncView.swift`)
- RFB has no transport encryption here: classic VNC authentication is a DES challenge-response and everything after it, keystrokes included, crosses the network in clear. The connect sheet says so and recommends an SSH tunnel outside trusted networks. VeNCrypt/TLS is not supported yet, so there is no server identity check (no pin, unlike RDP).
- The password lives in the connect sheet's state, goes into one connect call (only used if the server asks) and is cleared; it is not stored or logged. A wrong password is reported as "authentication failed".
- Server-sent rectangles are bounds-checked before they are copied into the framebuffer; rectangles outside the desktop or with short data are dropped (unit tests `blit_ignores_rectangles_outside_the_desktop`).
- Not yet: no clipboard (nothing offered, so nothing leaks either way); VNC connects are not in the audit log yet.

## Web tabs (`apps/macos/Sources/Bastion/WebTab.swift`)
- Only `http`/`https` targets open; `file:`, `javascript:` and other schemes are refused before loading and cancelled when a page navigates to them.
- Each tab uses a non-persistent `WKWebsiteDataStore`: cookies, cache and storage live only as long as the tab and are not shared between connections. No script message handlers or other native bridges are exposed to pages.
- TLS is WebKit's default validation (no override prompt). Plain `http://` is allowed when the user enters it explicitly.

## SFTP (`core/src/sftp.rs`)
- Server-supplied names are untrusted: entries that are not a single path component (`/`, NUL, `.`, `..`) are dropped from listings.
- No silent overwrite in either direction; uploads and downloads use a random temporary name and rename into place; downloaded files are created 0600 with `create_new`.
- Rename refuses to replace an existing target. Uses the same orchestrated, audited, strict-host-key connect as terminals.

## Shared SSH config workflow (`core/src/sshworkflow.rs`)
- Source config files are only read; a test compares bytes and mtimes of the whole fixture tree before and after the workflow. There is no Git/GitLab/network code.
- Personal values (placeholder answers, overrides) are validated: no whitespace or control characters, no leading `-`, no nested placeholders, ≤255 bytes. Credential references only, never secrets.
- A host with unanswered placeholders cannot connect (`NeedsConfiguration`); a literal `<user>` never reaches the server. Imported ProxyJump chains are honoured, never bypassed: each hop passes policy, uses its own brokered credential, needs its own strict or explicitly trusted host key (`JumpHostKeyUnknown` names the hop), and is audited (`via` detail). Chains that loop or exceed 8 hops are refused.
- `ssh-workflow.json` is written atomically, size-limited on read, and a newer format version is refused rather than silently reset.

## Security review 2026-11-01 (internal, not independent)
| ID | Finding | Severity | Status |
|---|---|---|---|
| F1 | `$ENV:X$` substitution could read any environment variable into a command | High | Fixed: allowlist; test `f1_*` |
| F2 | Predictable temp file name in atomic save; world-readable backups dir | Medium | Fixed: random name + `create_new`, dir 0700; test `f2_*` |
| F3 | Vault KDF parameters read from file unbounded (DoS) | Medium | Fixed: bounds; test `f3_*` |
| F4 | Local forward could bind `0.0.0.0` | High | Fixed: loopback-only by default; test `f4_f5_*` |
| F5 | Remote forward bind address unrestricted | Medium | Fixed: loopback only; test `f4_f5_*` |
| O1 | Windows file ACLs (0600 is Unix-only) | High on Windows | **Fixed in core, Windows 10 only** (2026-11-02, `core/src/winacl.rs`): library, backups, `write_atomic` files, private dirs, audit log and SFTP downloads get a protected DACL with a single full-control entry for the current user (no SYSTEM/Administrators by design; they can override via privileges anyway). Applied before secret bytes are written; audit log fails closed. `tests/winacl_tests.rs` (7) reads the DACL back. SFTP download path not exercised on Windows (no SSH server there). Windows 11 untested. |
| O2 | No dependency vulnerability scanning or SBOM yet | Medium | **SBOM done** (`scripts/sbom.sh`, CycloneDX 1.5 JSON per shipped crate from the locked graph); vulnerability scanning **done**: `scripts/audit-deps.sh` (cargo-audit over every shipped crate's Cargo.lock; fails on vulnerabilities). Accepted: RUSTSEC-2023-0071 (`rsa` Marvin timing, no upstream fix; via russh/IronRDP; prefer Ed25519 keys), reason in `scripts/audit-ignore.txt`. Not yet in CI |
| O7 | Vaultwarden provider (2026-11-02): master password and derived keys are `Zeroizing` and never stored; server KDF parameters bounded (PBKDF2 5k–2M, Argon2 16–1024 MiB / 2–10 iters / 1–16 lanes); every EncString MAC-verified before decryption; no redirects followed; https required except loopback http | Info | Compatible with Vaultwarden 1.37.5 (live test 2026-11-02). App: master password typed per unlock, never stored (only server URL, e-mail and a device id in `vaultwarden.json`); decrypted items stay in Rust, the UI gets names/usernames only; Lock Credentials locks Vaultwarden; https only except loopback http. Two-step: authenticator codes only, device never remembered (`twoFactorRemember=0`); refresh token and account key in memory only, dropped on Lock; org items not supported |
| O8 | Update channel (2026-11-02): manifest signature over exact payload bytes (Ed25519, `verify_strict`), trusted key compiled into the app, expiry ≤ 400 days enforced (freeze), version must not be lower than installed (rollback), channel pinned, 64 KiB limit, files need https + SHA-256 + size, no redirects | Info | **Limits**: one key signs everything (no TUF roles/threshold/rotation); newest-seen manifest not persisted (an older unexpired manifest that is still ≥ installed is accepted); nothing is installed yet. The compiled key is a development key whose private half was deleted; the release key must be generated offline and swapped in before shipping |
| O3 | Vault key not yet wrapped by Keychain / DPAPI; master-password only | Medium | **macOS: fixed in core** (`provider::KeychainProvider` + `vault_key`, real Keychain test `keychain_wraps_vault_key`; macOS app wired 2026-11-02: `CredentialVault` (core-ffi) opens `credentials.vault` with a Keychain-held key per vault path; secrets only go in through the FFI and connects read them inside Rust (`SshLogin::Vault`). Unsigned dev builds prompt for Keychain access after each rebuild; signed bundles do not). **Windows: fixed in core**: `DpapiProvider` compiles and its test passes on Windows 10 22H2 (2026-11-02); app wiring pending; Windows 11 untested. |

## Dynamic folders (B15, planned)
Not built. Security review and build conditions: `docs/reviews/B15-SECURITY-REVIEW.md` (go with conditions, 2026-11-16); threats T28–T28.10 in `THREAT_MODEL.md`.

## Release gates
A release is blocked by any item in the spec's §22 list. O1–O3 are fixed in core as the table says; what is still open for them is the platform verification each row names (Windows 11 for O1/O3, CI-free release-process scanning for O2). No public release exists yet.

## Security documents
| Document | Status |
|---|---|
| THREAT_MODEL.md | v1 |
| SECURITY_CONTROL_MATRIX.md | v1 (seed) |
| SECURITY_ARCHITECTURE.md, CIS_ALIGNMENT.md, SOC2_READINESS.md, ISO27001_ALIGNMENT.md, PRIVACY.md, VULNERABILITY_MANAGEMENT.md, INCIDENT_RESPONSE.md, SECURE_BUILD.md, DEPENDENCY_INVENTORY.md, SECURITY_TEST_RESULTS.md | Planned. They will be written when there is real content (CI, release pipeline, UI) rather than as empty templates. |

## Native interop on Windows (`core-cabi`, `apps/windows/Interop`)
- C ABI rules (ownership, UTF-8, errors through an out-parameter, `catch_unwind` on every entry point, NULL and range checks, ABI version check, struct-layout check at startup) are listed in ARCHITECTURE.md and covered by `core-cabi/tests` (12 tests, incl. concurrent terminal calls).
- `bastion_cabi.dll` is loaded from the application directory only (`DefaultDllImportSearchPaths(ApplicationDirectory)`), not from the current directory or PATH.
- Secrets that cross the C ABI, host to core only unless named: protected-document credential passwords (`bastion_document_save_password_credential` and the document unlock/export calls take `ptr,len` UTF-8 buffers the host owns and should wipe after the call), vault saves (`bastion_credentials_save_password` / `_save_ssh_key`), and generator results core → host (`bastion_generate_password` returns a secret-bearing string the host frees with the matching `_free`; host-language copies such as .NET strings cannot be wiped). `bastion_session_connect` takes either a credential ID (vault logins: the secret stays in Rust) or a password the user typed (NUL-terminated, host-owned); `bastion_password_strength_bits` reads a candidate password. The terminal carries what the user types, so terminal content is never logged.
- Open: Authenticode signing of `Gantry.exe` and `bastion_cabi.dll`, integrity check of the DLL before load, signed updates (release pipeline, not started).

## Local IPC (`core/src/ipc.rs`)
- The Unix socket is created 0600 in the per-user data folder. Connections whose peer uid differs from ours are dropped before reading.
- One request per connection, capped at 64 KiB, parsed as a closed enum. Malformed input gets an error reply and does not crash the app.
- A live socket owned by another instance is never replaced; only a stale file is removed.
- Every request carries the per-launch token: 32 random bytes (OS RNG), hex, written with `write_atomic` (0600, temp file + rename) to `<data dir>/bastion.ipc-token` at app start, compared in constant time, removed on quit. A wrong, missing or stale token gets "not authorised" and the handler never runs. A second instance never overwrites the token of a live one.
- No secrets, hosts or credentials travel over IPC; `open` names an existing connection and goes through the normal connect sheet, so the user still signs in and confirms host keys in the app. Ambiguous names are refused (use the id).
- The macOS app serves the socket (`AppIpc.swift`); verified end to end 2026-11-03 (`apps/macos/uitests/p0-cli.txt`).
- Socket paths longer than `sockaddr_un` allows are refused with a clear error instead of being truncated.
- Windows: a named pipe server exists in core (`core/src/ipc.rs`, `windows::named_pipe`); whether each Windows app serves it and its DACL are tracked in `AUDIT.md`, not asserted here.

## Terminal and credential controls (2026-11-03, macOS)
- OSC 52: the emulator accepts copy only (paste/read requests are never answered); copies go through `terminal.osc52` (off / ask, the default / allow), are capped at 64 KiB and shown with a preview before Allow.
- Session logs are opt-in per connection/folder or per tab; they hold program output only (never keystrokes; typed passwords are not echoed by servers), in new 0600 files (`create_new`, never overwritten) inside a 0700 `session-logs` folder; a write error stops logging, not the session.
- Snippets refuse text that looks like a key block or an inline password; multi-line snippets need confirmation; nothing runs on its own.
- Broadcast input needs an explicit selection and a confirmation naming every host; a banner shows while it is active.
- Credentials lock on screen lock and fast user switching (default on). Optional LocalAuthentication confirmation before the vault key is read (an OS confirmation; the key is not yet bound to biometry).
- SSH second factor: codes are used for one dial, never brokered, never retried; the agent's private keys never enter the process.
- RDP: "Require NLA" refuses servers that do not do CredSSP instead of falling back to a server-side login screen.
- Web tabs: only http(s); TLS errors are terminal (no override); the address bar marks http and mixed content as Not secure.
- Web sign-in fill (B13): off by default per connection, policy `forbid_web_autofill` turns it off everywhere. Only a click on "Fill sign-in" fills, only on an https page with no insecure content, only in the top frame, and only when the page origin equals the saved address exactly. The core releases the connection's own or inherited password login and writes `credential.release.web` or `web.autofill.refused` with the page origin (never the path, user name or password). The clipboard is never used.

## P3 controls (2026-11-03, macOS)
- CLI aliases are opt-in symlinks in a folder the user names; a name that already resolves on `PATH` is refused (nothing is shadowed or intercepted, no shell rc file is edited); uninstall removes only links recorded in `cli-aliases.json` that still point to `bastion`. All IPC verbs (`open`, `open-tunnel`) end in the app's own connect sheet.
- Tunnels: local listeners bind 127.0.0.1 only; remote forwards bind the server's loopback (the transport refuses others); saved definitions hold no secrets; two saved tunnels cannot share a local port.
- Multi-host exec: one line only (no hidden second command), the confirmation names every host and the command, sensitive hosts need an explicit acknowledgement enforced in the bridge as well as the UI, unknown host keys fail rather than prompting mid-run, output is capped, CSV export escapes spreadsheet formulas.

## SSH host certificates (2026-11-03)
- A CA is trusted only through an explicit `@cert-authority <patterns> <key>` line the user adds (Host Certificate Authorities sheet); it vouches only for hosts its patterns match. Certificate host-key algorithms are offered only for those hosts, so other servers keep the strict known-hosts check.
- A presented certificate must be a host certificate, signed by a trusted CA (signature verified), within its validity window, list the host among its principals, and carry no critical options; `@revoked` CA or host keys are refused. Trusting a certificate never writes the server key into known_hosts. Hashed host patterns are not supported on CA lines.
- SSHFP (DNS-published fingerprints) is not used: without DNSSEC validation a spoofed DNS answer could vouch for an attacker's key.

## SCP and FTPS (2026-11-03)
- SCP runs over the same SSH connection rules as SFTP (strict host keys, policy, brokered credentials, audit). Paths reach the server's shell only single-quoted; SCP control lines from the server are validated (`C<mode> <size> <name>` only, no `/`, `..` or directories), so a server cannot make a download write anywhere but the chosen file.
- FTPS requires explicit TLS before the login (`AUTH TLS`) and protects every data connection (`PROT P`); a server that refuses TLS is refused, and plain FTP stays disabled by policy. The certificate is pinned on first use (SHA-256 of the leaf), the pin is checked on the control and every data connection, and a different certificate is prompted again as changed. Each FTPS sign-in is written to the audit log. The FTPS password is used for one sign-in and not stored.

## RDP redirection (2026-11-03)
- Clipboard (default on, like mstsc): Unicode text only, both directions, 8 MiB cap; no files, images or other formats are offered or requested. Text marked concealed on the Mac pasteboard (`org.nspasteboard.ConcealedType`, used by password managers) is never offered. Turn it off per connection or per folder (Redirection → Share clipboard) for servers that should not see what you copy.
- Shared folder (off unless set): the server can read, change and delete everything inside it. Paths must be absolute and cannot be `/`; the backend resolves server paths beneath the folder one component at a time and never follows symbolic links, so `..`, rooted paths and links cannot leave it. The connect sheet lists what will be shared before connecting.
- Sound (default on): playback only; the microphone is never captured.
- The drive backend is a vendored copy of `ironrdp-rdpdr-native` 0.9.0 with two reviewed changes (`rdp-ffi/vendor/ironrdp-rdpdr-native/BASTION-PATCH.md`); the upstream traversal tests still pass.

## Session supervision and gateways (2026-11-03)
- Reconnects (opt-in per connection, "Reconnect automatically") redial through the same orchestrator: policy, strict host keys (trust given for the first dial is not re-applied; the key is in known_hosts), audit per attempt. Secrets come only from the broker's leases, so a reconnect after the 15-minute inactivity / 60-minute absolute limit fails with "sign in again" and is never retried. Authentication failures, unknown/changed host keys and expired leases are never retried.
- Split panes and SFTP tabs reconnect under the same rules (opt-in, brokered leases only, strict host keys, never after an auth failure). An SFTP write that was cut off is not repeated after the reconnect, since it may already have taken effect.
- Sleep: supervised links are dropped before sleep and redialled on wake (same rules). Without opt-in, sleep/wake leaves the session alone.
- Gateways hold host, port, user and notes only (no secrets). A gateway is an ordinary jump hop: its own host-key verification, credential (asked at connect time), customer-scope check and audit record. A connection whose gateway reference no longer resolves fails instead of connecting directly; deleting a gateway in use is refused.
- RDP, VNC and web through a gateway: the gateway is dialled as an SSH target with the same orchestrator rules, then a forward (RDP/VNC) or SOCKS5 proxy (web) listens on 127.0.0.1 on an OS-chosen port for as long as the tab is open. Like `ssh -L`/`-D`, any local process of any user on this Mac can connect to that port while it is open; the SOCKS proxy has no authentication (RFC 1929 would put a password in the same process). The RDP certificate is pinned and checked against the real host name, not the loopback address. VNC through a gateway is encrypted only between this Mac and the gateway; the sheet says so. A web tab with a gateway sends every request over the proxy (no direct fallback).
