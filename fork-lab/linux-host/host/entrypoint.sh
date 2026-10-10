#!/bin/sh
# Installs the audit account's public key from the read-only lab mount, then runs sshd in the foreground.
set -eu
test -s /run/lab/audit.pub || { echo "missing /run/lab/audit.pub" >&2; exit 1; }
ssh-keygen -A >/dev/null
install -m 0600 -o audit -g audit /run/lab/audit.pub /home/audit/.ssh/authorized_keys
mkdir -p /run/sshd
exec /usr/sbin/sshd -D -e
