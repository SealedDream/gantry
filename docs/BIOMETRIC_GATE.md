# Touch ID / Windows Hello gate (Tauri app)

Status: design, 2026-11-03. Implemented for macOS (Touch ID, or the login password when Touch ID
is unavailable) and Windows (Windows Hello).

## What it protects

Gantry keeps secrets the user saved so they need not be typed again:

| Secret | Where it lives | Gated |
| --- | --- | --- |
| Saved SSH / RDP passwords (`creds::save`) | macOS Keychain / Windows Credential Manager | yes |
| Credential-vault entries (passwords, SSH keys) | core vault, key in the Keychain | yes |
| Vaultwarden items (after the user unlocked Vaultwarden) | memory only | yes |
| Key-file passphrases | asked every time, never saved | no (nothing saved) |
| Passwords typed into a prompt for this connect | the prompt itself | no (the person is present) |

The threat is someone at an unlocked, unattended Mac (or a remote-control session) opening
connections with the owner's saved logins. The gate makes using a *saved* secret require the
owner's presence; it does not encrypt anything further (the Keychain / vault already do).

## When it asks

- The setting **Require Touch ID to use saved logins** is off by default. Turning it **on** is
  free; turning it **off** asks first (otherwise the person at the keyboard could just disable it).
- With the setting on, the first use of a saved secret asks once; later uses pass until Gantry
  locks again. Gantry locks on screen lock, sleep and the existing idle/lock paths
  (`security::os_locked`, Lock in Credentials), which also drop broker leases today, so the gate
  re-arms at exactly the same moments the credentials do.
- If the person cancels or fails, the connect fails with "Touch ID was not confirmed" and the
  secret is not read.
- macOS policy: `LAPolicyDeviceOwnerAuthentication` (Touch ID, Apple Watch, or the login
  password as fallback), so a Mac without Touch ID still works.

## Storage

`biometric.json` beside the library: `{"required": true}`. Missing file = off. A file that exists
but cannot be read or parsed counts as **required** (fail closed), unlike view state.

## Windows Hello

`IUserConsentVerifierInterop::RequestVerificationForWindowAsync` (the desktop-app form of
`UserConsentVerifier::RequestVerificationAsync`) via the `windows` crate, owned by Gantry's main
window so the dialog comes to the front. Same gate and storage. Windows Hello means PIN,
fingerprint or face, whatever the account has set up. `CheckAvailabilityAsync` decides whether
the setting can be turned on; without Hello set up, Settings shows why (for example "Windows
Hello is not set up for this account").

## Verification

A person must touch the sensor: automated runs can only check that the gate is called, that a
cancelled prompt blocks the secret, and that locking re-arms it. `BASTION_SPIKE_BIOMETRIC=deny|allow`
answers the prompt in bench runs only (with `BASTION_SPIKE_BENCH`), for those checks.
