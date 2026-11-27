# Throwaway systemd + OpenSSH host for the Services / Processes / Event Log tests (TESTING.md).
# Run: docker run -d --name bastion-systemd --privileged --cgroupns=host \
#        -v /sys/fs/cgroup:/sys/fs/cgroup:rw -p 127.0.0.1:2240:22 bastion-systemd-test
# then set root's password: docker exec bastion-systemd sh -c 'echo "root:<generated>" | chpasswd'
FROM debian:12-slim
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd systemd-sysv openssh-server procps bsdutils \
 && apt-get clean \
 && sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config \
 && systemctl enable ssh
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
