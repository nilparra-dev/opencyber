#!/bin/sh
# Shared by every host variant: the read-only audit account (key-only, no password), an auditors group that can
# read sudo policy without root, and the crontab files the audit reads.
set -eu
groupadd --gid 1100 auditors
useradd --create-home --shell /bin/sh --uid 1000 --groups auditors audit
install -d -m 0700 -o audit -g audit /home/audit/.ssh
install -d -m 0755 /etc/cron.d
printf '%s\n' 'SHELL=/bin/sh' 'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' > /etc/crontab
chmod 0644 /etc/crontab
chgrp auditors /etc/sudoers
chmod 0640 /etc/sudoers
mkdir -p /run/sshd
for policy in /etc/sudoers.d/*; do
  chgrp auditors "$policy"
  chmod 0640 "$policy"
done
