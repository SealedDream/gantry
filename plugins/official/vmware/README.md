# VMware

Shows the hosts and VMs of a VMware vCenter Server (7.0 or later) or a standalone ESXi host (7.0
or later): name, ID, state, CPUs and memory; connect to a VM, and with "Allow changes" power and
snapshot actions.

Add a VMware vCenter connection with the server's address and port 443. For its login, use a
vCenter account with the Read-only role. The password stays in Gantry's vault; the plugin never
sees it: the core adds it to each request as HTTP Basic login, over TLS only. If the server uses a
self-signed certificate, trust it in the connection's Certificate section after comparing its
fingerprint.

For a standalone ESXi host, add a VMware ESXi connection (port 443) with a host account, such as a
read-only local user. ESXi has only the SOAP API, whose login sends the password in the request
body: Gantry's core sends that login itself, keeps the session cookie and adds it to the plugin's
requests, so the plugin never sees the password or the cookie. Gantry logs the session out when
the view closes. ESXi limits the sessions per host; Gantry keeps at most two per host.
