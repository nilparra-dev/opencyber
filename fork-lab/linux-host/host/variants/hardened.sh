#!/bin/sh
# Hardened baseline: every audit check passes. Only the audit account may log in.
set -eu
install -m 0644 /opt/lab/variants/hardened.sshd_config /etc/ssh/sshd_config
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' /etc/login.defs
chmod 0640 /etc/shadow
chmod 0644 /etc/passwd
