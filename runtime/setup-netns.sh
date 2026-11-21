#!/bin/sh
# runtime/setup-netns.sh - runs in the jill-netns container, which OWNS the
# network namespace that opencode-serve joins (network_mode: service:jill-netns).
# jill-netns has CAP_NET_ADMIN; opencode-serve has no capabilities, so the
# model cannot change these rules. Then it sleeps; it runs nothing else.
#
#   INPUT   the serve API (4747) only from api-proxy, never over loopback
#   OUTPUT  no connection to 4747 at all (no loopback API, no nested client)
#           no packets to the network's gateway address (the Docker bridge /
#           Colima VM: sshd and any host port, red-team round 2 H3)
#           no packets to api-proxy (serve never calls it)
#           otherwise only the jill-internal subnet (the gateway sidecars)
#           IPv6 off
set -eu
: "${INTERNAL_SUBNET:?}" "${INTERNAL_GATEWAY:?}" "${API_PROXY_IP:?}"
ipt() { iptables -w 5 "$@"; }

ipt -P INPUT ACCEPT
ipt -P OUTPUT ACCEPT
ipt -F INPUT
ipt -F OUTPUT

ipt -A INPUT -i lo -p tcp --dport 4747 -j REJECT --reject-with tcp-reset
ipt -A INPUT -p tcp --dport 4747 -s "$API_PROXY_IP" -j ACCEPT
ipt -A INPUT -p tcp --dport 4747 -j DROP

ipt -A OUTPUT -p tcp --dport 4747 -j REJECT --reject-with tcp-reset
ipt -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
ipt -A OUTPUT -o lo -j ACCEPT
ipt -A OUTPUT -d "$INTERNAL_GATEWAY" -j REJECT
ipt -A OUTPUT -d "$API_PROXY_IP" -j REJECT
ipt -A OUTPUT -d "$INTERNAL_SUBNET" -j ACCEPT
ipt -A OUTPUT -j REJECT

for chain in INPUT OUTPUT FORWARD; do ip6tables -w 5 -P "$chain" DROP 2>/dev/null || true; done
ip6tables -w 5 -A INPUT -i lo -j ACCEPT 2>/dev/null || true
ip6tables -w 5 -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true

iptables -S > /tmp/netns-rules
touch /tmp/netns-ready
echo "[jill-netns] firewall up: $(wc -l < /tmp/netns-rules) rules"
exec sleep infinity
