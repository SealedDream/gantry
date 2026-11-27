# Proxmox VE

Shows the guests of a Proxmox VE node or cluster: ID, name, node, type, state, CPU and memory.
Read-only unless the entry's **Allow changes (snapshots)** is on.

Add a Proxmox VE connection with the server's address and port 8006. For its login, use an API
token with the PVEAuditor role: User is the token ID (`user@realm!name`), the secret is the token's
secret. A privilege-separated token needs its own PVEAuditor ACL on `/`.

Or add a **Proxmox VE (password)** connection: User is `user@realm` (`root@pam`, `admin@pve`),
the password is that user's. Gantry logs in for a ticket, keeps it, and logs in again when
it expires (2 h). Either login stays in Gantry's vault; the plugin never sees it. Test
Connection checks the certificate and then the login, with the calls the guest list makes.

If the server uses a
self-signed certificate, trust it in the connection's Certificate section after comparing its
fingerprint.

## Snapshots

The dashboard's tree lists each node's guests and, under each guest, its snapshots (name, with or
without RAM, when taken). On an API-token entry with **Allow changes (snapshots)** on, a guest's
menu has **Take Snapshot** (named `gantry-1`, `gantry-2`, …, disks only) and a snapshot's menu
has **Rollback** and **Delete Snapshot**. Each one asks first. The token needs `VM.Snapshot` (and
`VM.Snapshot.Rollback` to roll back) on those guests. Password entries stay read-only.
