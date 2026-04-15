#!/bin/bash
set +e
exec > /var/log/kali-setup.log 2>&1

echo "=== Kali Attacker Setup ==="

export DEBIAN_FRONTEND=noninteractive
apt-get update -y
# dnsutils provides `dig` — without it, the DNS-tunneling stages of
# run_attacks.sh silently no-op on Kali ("dig: command not found")
# and rules 9000101-112 / 9000213-214 can never fire.
apt-get install -y nmap curl hydra nikto xxd hping3 dnsutils \
  smbclient impacket-scripts python3-impacket

echo "=== Kali setup complete ==="
