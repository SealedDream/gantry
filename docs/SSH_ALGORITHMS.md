# SSH algorithms

Core module: `core/src/algorithms.rs`. Gantry offers russh 0.65's safe lists by default and
changes them only through a connection's (or folder's, or type default's) `ssh_algorithms`
setting, or an imported `~/.ssh/config`.

## Settings

`ssh_algorithms` is JSON, inherited as a unit like every other property:

```json
{ "kex": "+diffie-hellman-group14-sha1", "ciphers": "^aes128-ctr", "macs": "-hmac-sha2-512*",
  "host_keys": null, "compression": true, "allow_weak": false }
```

Each list uses OpenSSH syntax: a bare list replaces, `+` appends, `-` removes (wildcards), `^`
puts first. Several lines in one field apply in order. Unknown or unimplemented names are
dropped with a warning; a list that ends up empty is rejected when saving.

## Weak algorithms

Weak: `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`,
`diffie-hellman-group-exchange-sha1`, `3des-cbc`, `aes128/192/256-cbc`, `hmac-sha1`,
`hmac-sha1-etm@openssh.com`, `ssh-rsa` (SHA-1 host key signatures).

- Off by default; named in a list they still stay off until `allow_weak` is true.
- Managed policy `forbid_weak_ssh_algorithms: true` overrides `allow_weak` everywhere.
- An import never sets `allow_weak`; such hosts get the `weak_algorithms_requested` flag.
- Connecting with weak algorithms enabled writes a `ssh.weak_algorithms` security-warning audit event.
- `none` ciphers and MACs are never offered.
- `core/tests/kexinit_offer_tests.rs` checks the client KEXINIT on the wire: the default host-key list ends `rsa-sha2-512,rsa-sha2-256` with no `ssh-rsa`.

## When negotiation fails

`CoreError::NoCommonAlgorithm { kind, server_offers, weak_allowable }`, for example:

> no common key exchange algorithm: the server offers only diffie-hellman-group1-sha1 (weak; can be allowed for this host: diffie-hellman-group1-sha1)

When `weak_allowable` is non-empty the UI offers **Allow for this host**, which calls
`properties::allow_weak_algorithms` (C ABI `bastion_library_allow_weak_algorithms`,
UniFFI `Library.allow_weak_algorithms`). It writes the connection's own setting, so it does not
leak to siblings. Policy is still checked on the next connect.

Surfaces: C ABI outcome `CONNECT_NO_COMMON_ALGORITHM` (6) with JSON `{kind, serverOffers,
weakAllowable}` in the `fingerprint` out-param; UniFFI `FfiError::NoCommonAlgorithm`; Tauri
`OpenError::NoCommonAlgorithm` (`kind: "noCommonAlgorithm"`, `algorithm`, `serverOffers`,
`weakAllowable`). Auto-reconnect never retries it.

## Not implemented by russh 0.65

Named in warnings rather than silently ignored:

| Kind | Algorithms |
|---|---|
| Key exchange | `sntrup761x25519-sha512`, `sntrup761x25519-sha512@openssh.com`, `mlkem768nistp256-sha256`, `mlkem1024nistp384-sha384` |
| Cipher | `arcfour`, `arcfour128`, `arcfour256`, `blowfish-cbc`, `cast128-cbc`, `rijndael-cbc@lysator.liu.se` |
| MAC | `umac-64@openssh.com`, `umac-128@openssh.com`, their `-etm` forms, `hmac-md5`, `hmac-md5-96`, `hmac-sha1-96`, `hmac-ripemd160` |
| Host key | `ssh-dss`, `ssh-dss-cert-v01@openssh.com` |

`mlkem768x25519-sha256` (post-quantum hybrid) is implemented and preferred first.
`PubkeyAcceptedAlgorithms` is imported and kept in metadata, but russh chooses the client
RSA signature hash itself (SHA-512, then SHA-256), so it does not change behaviour yet.

## Imported directives

Besides the earlier set, `~/.ssh/config` import now reads `KexAlgorithms`, `Ciphers`, `MACs`,
`HostKeyAlgorithms`, `PubkeyAcceptedAlgorithms` (and the old `PubkeyAcceptedKeyTypes`),
`Compression`, `SendEnv`, `SetEnv`, `RequestTTY`, `RemoteCommand`, `AddKeysToAgent`,
`ExitOnForwardFailure`. Algorithm lists become `ssh_algorithms`; the rest go into connection
metadata under their OpenSSH names (`SendEnv` space-separated, `SetEnv` one per line).
`RemoteCommand` is stored verbatim and never run locally.

`sshworkflow::reimport_hosts` re-imports without duplicates: a host already in the library is
refreshed in place (the user's "Allow for this host" survives), and a host imported earlier
from another checkout of the same tree (same customer folder and alias) takes the new identity.

## Tests

- `cargo test --lib algorithms` (list syntax, weak/policy, unsupported names, error text).
- `cargo test --test weak_algorithms_integration`: real SSH handshake against an in-process
  russh server on loopback that offers only `diffie-hellman-group14-sha1`: refused with the
  precise error, connects after Allow for this host (reaches strict host-key checking), refused
  again under the policy veto.
- `cargo test --test sshworkflow_tests` (directive import, non-duplicating re-import).
- `core-cabi`: `properties_cabi_tests::ssh_algorithms_inherit_validate_and_allow_for_host`.
- Live `BASTION_SSH_TEST=1 cargo test --test ssh_integration` against bastion-sshd: 12/12 pass
  with the explicit default lists (the key-login test needs `BASTION_SSH_KEY`).
