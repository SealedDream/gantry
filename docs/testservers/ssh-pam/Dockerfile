# Throwaway test server for keyboard-interactive, TOTP (pam_oath) and agent auth. Not shared.
FROM alpine:3.21
RUN apk add --no-cache openssh-server-pam linux-pam oath-toolkit-pam_oath oath-toolkit-oathtool shadow \
 && ssh-keygen -A \
 && for u in kbd mfa agent; do adduser -D -s /bin/sh $u; done \
 && echo 'kbd:kbd-pass-321' | chpasswd && echo 'mfa:mfa-pass-789' | chpasswd && echo 'agent:unused-pass-0' | chpasswd \
 && echo 'HOTP/T30 mfa - 3132333435363738393031323334353637383930' > /etc/users.oath && chmod 600 /etc/users.oath \
 && mkdir -p /home/agent/.ssh
# Generate first, next to this file: ssh-keygen -t ed25519 -N "" -f agentkey
COPY agentkey.pub /home/agent/.ssh/authorized_keys
COPY sshd-pam /etc/pam.d/sshd
RUN chown -R agent:agent /home/agent/.ssh && chmod 700 /home/agent/.ssh && chmod 600 /home/agent/.ssh/authorized_keys \
 && printf 'UsePAM yes\nPasswordAuthentication no\nKbdInteractiveAuthentication yes\nPubkeyAuthentication yes\nPerSourcePenalties no\n' >> /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd.pam", "-D", "-e"]
