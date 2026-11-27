# Docker

Shows a Linux host's Docker Engine: containers (image, state, ports, CPU, memory), images, volumes and networks. With "Allow changes" on, a container can be started, stopped, restarted and removed, and you can open a shell in it.

Docker Desktop is not needed, on this computer or anywhere. Gantry connects to the host over SSH and runs the `docker` commands listed in the plugin's manifest. It works offline on a LAN.

## Set up

1. Add a **Docker host** connection with the server's address and SSH port (22), and give it an SSH login, as for an SSH connection. A gateway or jump host works the same way.
2. Connect to the host once by SSH, so its host key is trusted.
3. The SSH user must be able to use Docker: add it to the `docker` group (`sudo usermod -aG docker <user>`), then sign in again.

## Errors

| Code | Meaning | What to do |
|---|---|---|
| GT-PLUG-003 | `docker` is not on the host, or not on the user's PATH | Install Docker Engine |
| GT-PLUG-004 | The user may not use the Docker socket | Add the user to the `docker` group |
| GT-PLUG-005 | The Docker daemon is not running | `sudo systemctl start docker` |

## Notes

- Every change (start, stop, restart, remove, shell) is confirmed by Gantry itself, showing the exact command, and is recorded in the audit log.
- Logs show the last 500 lines in a window; they do not follow new lines yet.
- Commands are quoted for a POSIX login shell (sh, bash, zsh). A host whose login shell is fish or csh may read the quotes differently.
