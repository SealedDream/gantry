# Kubernetes

Shows a Kubernetes cluster: pods (status, ready, restarts, node, age, and CPU and memory when
metrics-server is installed), deployments (ready / desired), services and nodes, with a
namespace filter. Opens a pod's log (the last 500 lines). No kubectl and no Docker are needed:
the plugin talks to the API server over HTTPS through the app.

Add a **Kubernetes cluster** connection with the API server's address and port (6443 by
default). Put a ServiceAccount token in the password; the user name is not used. The token
stays in Bastion's vault and the plugin never sees it. Trust the cluster's certificate in the
connection's Certificate section after comparing its fingerprint (clusters usually use their
own CA). To reach a cluster on another network, give the connection an SSH jump route as for
any other connection.

A read-only token is enough for the dashboard and logs, for example:

```
kubectl -n kube-system create serviceaccount bastion-viewer
kubectl create clusterrolebinding bastion-viewer --clusterrole=view --serviceaccount=kube-system:bastion-viewer
kubectl -n kube-system create token bastion-viewer --duration=720h
```

(`view` does not list nodes; bind `system:node-reader`-style access, or leave the Nodes tab
empty.)

**Allow changes** in the connection turns on Delete Pod, Scale and Restart (rollout restart).
Each asks first. They need a role that may delete pods and patch deployments and their `scale`.

Errors say what went wrong: an unreachable API server, a refused or expired token, or an RBAC
refusal with the server's own message.

Not in this version (needs plugin API and core work): kubeconfig import with contexts, client
certificate logins, exec into a pod in a terminal tab, and live-streamed logs.
