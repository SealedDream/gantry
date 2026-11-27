# Proxmox VE

Shows the guests of a Proxmox VE node or cluster: ID, name, node, type, state, CPU and memory.
Read-only in this version.

Add a Proxmox VE connection with the server's address and port 8006. For its login, use an API
token with the PVEAuditor role: User is the token ID (`user@realm!name`), the secret is the token's
secret. The token stays in Bastion's vault; the plugin never sees it. If the server uses a
self-signed certificate, trust it in the connection's Certificate section after comparing its
fingerprint.
