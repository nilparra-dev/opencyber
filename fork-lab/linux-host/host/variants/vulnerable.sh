#!/bin/sh
# Known-positive configuration. Each change below is one documented finding in fork-cyber-host.md.
set -eu
install -m 0644 /opt/lab/variants/vulnerable.sshd_config /etc/ssh/sshd_config
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t99999/' /etc/login.defs
chmod 0644 /etc/shadow
useradd --create-home --shell /bin/sh --uid 1001 ops
printf '%s\n' 'ops ALL=(root) NOPASSWD: /usr/bin/tar' > /etc/sudoers.d/ops
chgrp auditors /etc/sudoers.d/ops
chmod 0640 /etc/sudoers.d/ops
cp /bin/true /usr/local/bin/backup-helper
chmod 4755 /usr/local/bin/backup-helper
setcap cap_dac_read_search+ep /usr/local/bin/backup-helper
: > /etc/cron.d/maint
chmod 0666 /etc/cron.d/maint
