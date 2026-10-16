#!/bin/sh
# Output policy: loopback, replies to accepted connections, and SSH to the two lab hosts. Everything else is dropped.
set -eu
: "${HARDENED_ADDR:?}" "${VULNERABLE_ADDR:?}"
iptables -P OUTPUT DROP
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -p tcp -d "$HARDENED_ADDR" --dport 22 -j ACCEPT
iptables -A OUTPUT -p tcp -d "$VULNERABLE_ADDR" --dport 22 -j ACCEPT
socat TCP-LISTEN:2201,fork,reuseaddr TCP:"$HARDENED_ADDR":22 &
exec socat TCP-LISTEN:2202,fork,reuseaddr TCP:"$VULNERABLE_ADDR":22
