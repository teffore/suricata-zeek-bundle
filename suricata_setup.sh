#!/bin/bash
set +e
exec > /var/log/suricata-setup.log 2>&1

echo "=== Suricata IDS Setup (Ubuntu) ==="

# Wait for any apt locks to release
while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
  echo "Waiting for apt lock..."
  sleep 5
done

# Detect the primary network interface BEFORE installing
# (ens5 on Nitro-based instances)
PRIMARY_IF=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -1)
echo "Primary interface: ${PRIMARY_IF}"

# Install Suricata from the OISF stable PPA.
# Ubuntu 22.04's default repo ships Suricata 6.0.x which reached EOL on
# 2024-08-01. The OISF stable PPA tracks the latest supported major (8.0.x
# as of 2026-03), which unblocks HTTP/2, QUIC/HTTP/3, and JA4.
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y software-properties-common
add-apt-repository -y ppa:oisf/suricata-stable
apt-get update -y
apt-get install -y suricata jq logrotate

# Stop suricata (apt auto-starts it with eth0 which fails)
systemctl stop suricata || true

# Fix /etc/default/suricata — Ubuntu service reads IFACE from here
sed -i "s/IFACE=eth0/IFACE=${PRIMARY_IF}/" /etc/default/suricata
sed -i "s/RUN=no/RUN=yes/" /etc/default/suricata

# dpkg may have saved config as .dpkg-new if it detected conflicts
if [ ! -f /etc/suricata/suricata.yaml ] && [ -f /etc/suricata/suricata.yaml.dpkg-new ]; then
  cp /etc/suricata/suricata.yaml.dpkg-new /etc/suricata/suricata.yaml
fi

# Restore classification.config and reference.config if missing
for f in classification.config reference.config threshold.config; do
  if [ ! -f "/etc/suricata/${f}" ] && [ -f "/etc/suricata/${f}.dpkg-new" ]; then
    cp "/etc/suricata/${f}.dpkg-new" "/etc/suricata/${f}"
  fi
done

# Enable extra rule sources
suricata-update enable-source tgreen/hunting
suricata-update enable-source ptresearch/attackdetection
suricata-update enable-source sslbl/ssl-fp-blacklist
suricata-update enable-source sslbl/ja3-fingerprints
suricata-update enable-source etnetera/aggressive

# Update rules (puts them in /var/lib/suricata/rules/)
suricata-update

# Fix interface in suricata.yaml AFTER suricata-update
sed -i "s/interface: eth0/interface: ${PRIMARY_IF}/g" /etc/suricata/suricata.yaml

# Point rules to where suricata-update puts them
sed -i 's|default-rule-path: /etc/suricata/rules|default-rule-path: /var/lib/suricata/rules|' /etc/suricata/suricata.yaml

# Set HOME_NET to all RFC 1918 space (10/8, 172.16/12, 192.168/16). Suricata's
# default already uses these; we reassert with an explicit value so rules can
# reliably reference $HOME_NET regardless of downstream config drift.
sed -i 's|HOME_NET: "\[192\.168\.0\.0/16.*\]"|HOME_NET: "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]"|' /etc/suricata/suricata.yaml

# ---------- Enhancement #1: Community ID ----------
# Adds a standardized flow hash (1:xxxxx) to every event so you can
# correlate the same connection across Suricata, Zeek, and SIEM tools.
sed -i 's/community-id: false/community-id: true/' /etc/suricata/suricata.yaml
# If the line doesn't exist, add it under the eve-log outputs
grep -q "community-id: true" /etc/suricata/suricata.yaml || \
  sed -i '/^outputs:/,/eve-log:/{/eve-log:/a\      community-id: true}' /etc/suricata/suricata.yaml

# ---------- Enhancement #2: TLS/JA3 Logging ----------
# Logs every TLS handshake including certificate info and JA3 fingerprints.
# JA3 fingerprints identify malware C2 even when traffic is encrypted.
# Enable JA3 globally and add tls logging to eve-log
sed -i 's/#\s*ja3-fingerprints: auto/ja3-fingerprints: auto/' /etc/suricata/suricata.yaml
sed -i 's/ja3-fingerprints: no/ja3-fingerprints: yes/' /etc/suricata/suricata.yaml

# ---------- Enhancement #3: Alert Metadata ----------
# Adds CVE numbers, affected products, attack descriptions, and
# rule references to alert output — gives full context instead of
# just the rule name.
# Enable metadata in eve-log alert section
python3 -c "
import sys
data = open('/etc/suricata/suricata.yaml').read()
# Enable metadata in alert output
data = data.replace('# metadata: no', 'metadata: yes')
data = data.replace('metadata: no', 'metadata: yes')
open('/etc/suricata/suricata.yaml', 'w').write(data)
"

# ---------- Enhancement #6: Hyperscan Pattern Matching ----------
# Switches multi-pattern matching from default (AC) to Hyperscan,
# which is significantly faster for large rule sets (49k+ rules).
# Hyperscan is already compiled into Ubuntu's Suricata package.
sed -i 's/mpm-algo: auto/mpm-algo: hs/' /etc/suricata/suricata.yaml
sed -i 's/spm-algo: auto/spm-algo: hs/' /etc/suricata/suricata.yaml

# ---------- Enhancement #9: Tunings per Suricata 8.0 docs ----------
# (a) async-oneside: AWS Traffic Mirroring delivers each direction as
#     a separate session (we have two — victim, attacker), which is
#     asymmetric by design. Without this, Suricata may drop alerts on
#     flows it only sees one direction of. The OISF default yaml has
#     this commented as `#   async-oneside: false` under the `stream:`
#     block — we just uncomment and flip to true.
# (b) max-pending-packets: docs recommend 10000+ for typical sensors;
#     default 1024 can drop packets under attack-burst conditions.
sed -i 's/^#   async-oneside: false.*/  async-oneside: true/' /etc/suricata/suricata.yaml
sed -i 's/^max-pending-packets: 1024/max-pending-packets: 10000/' /etc/suricata/suricata.yaml

# ---------- Enhancement #7: Anomaly Logging ----------
# Logs protocol violations and malformed packets — catches things
# that signature rules don't, like unusual TCP flags, truncated
# headers, and protocol mismatches. Attackers often trigger these.
python3 -c "
import sys
data = open('/etc/suricata/suricata.yaml').read()
# Make sure anomaly is enabled in eve-log types
if 'anomaly:' not in data or '# - anomaly' in data:
    data = data.replace('# - anomaly', '- anomaly')
# Enable anomaly logging with packet info
data = data.replace('#   enabled: yes\n          #   types:', '  enabled: yes\n            types:')
open('/etc/suricata/suricata.yaml', 'w').write(data)
"

# ---------- Enhancement #8: Run as Non-Root ----------
# Drops privileges to the 'suricata' user after startup. Limits
# the blast radius if Suricata itself has a vulnerability.
# Create suricata user if it doesn't exist
id suricata &>/dev/null || useradd -r -s /sbin/nologin -d /var/lib/suricata suricata
mkdir -p /var/run/suricata /var/log/suricata /var/lib/suricata
chown -R suricata:suricata /var/log/suricata /var/lib/suricata /var/run/suricata
# Update systemd service to run as suricata user
mkdir -p /etc/systemd/system/suricata.service.d
cat > /etc/systemd/system/suricata.service.d/user.conf <<EOF
[Service]
# Enhancement #8: Drop privileges after startup
ExecStart=
ExecStart=/usr/bin/suricata -D --af-packet -c /etc/suricata/suricata.yaml --pidfile /run/suricata.pid --user=suricata --group=suricata
EOF
systemctl daemon-reload

# ---------- Enhancement #4: Daily Rule Updates ----------
# ET Open updates daily, abuse.ch updates every 5 minutes.
# Without regular updates, detection degrades as new threats emerge.
cat > /etc/cron.d/suricata-update <<'CRON'
# Update Suricata rules daily at 3:00 AM UTC
0 3 * * * root suricata-update && suricatasc -c reload-rules /var/run/suricata/suricata-command.socket 2>/dev/null || systemctl restart suricata
CRON
chmod 644 /etc/cron.d/suricata-update

# ---------- Enhancement #5: Log Rotation ----------
# Without rotation, eve.json fills the 10GB disk in days on a busy
# network. Suricata keeps logging until the disk is full, then crashes.
cat > /etc/logrotate.d/suricata <<'LOGROTATE'
/var/log/suricata/*.log /var/log/suricata/*.json {
    daily
    rotate 7
    missingok
    notifempty
    compress
    delaycompress
    create 0640 suricata suricata
    sharedscripts
    postrotate
        # Per Suricata 8.0 docs: send SIGHUP to reopen log files in
        # append mode without restarting (avoids 49k-rule reload + downtime).
        /bin/kill -HUP $(cat /run/suricata.pid 2>/dev/null) 2>/dev/null || true
    endscript
}
LOGROTATE

# Install custom rules from the bundle. BUNDLE_DIR is exported by install.sh;
# fall back to the directory of this script if invoked standalone.
: "${BUNDLE_DIR:=$(dirname "$(readlink -f "$0")")}"
if [ -f "${BUNDLE_DIR}/custom.rules" ]; then
  cp "${BUNDLE_DIR}/custom.rules" /var/lib/suricata/rules/custom.rules
  cat /var/lib/suricata/rules/custom.rules >> /var/lib/suricata/rules/suricata.rules
  echo "Custom rules installed from ${BUNDLE_DIR}/custom.rules"
else
  echo "WARN: custom.rules not found at ${BUNDLE_DIR}/custom.rules — skipping"
fi

echo "Config updated with interface: ${PRIMARY_IF}"
echo "Enhancements applied: community-id, tls/ja3, metadata, daily updates, log rotation (HUP), hyperscan, anomaly, non-root, async-oneside, max-pending-packets"

# Validate config (as the suricata user so it doesn't create
# root-owned log files in /var/log/suricata that block the daemon
# when it later drops privileges).
sudo -u suricata suricata -T -c /etc/suricata/suricata.yaml

# Re-chown one more time in case anything between the earlier chown
# and now (suricata -T, package post-install hooks, etc.) recreated
# files in /var/log/suricata as root.
chown -R suricata:suricata /var/log/suricata /var/run/suricata /var/lib/suricata

# Enable and start Suricata
systemctl enable suricata
systemctl start suricata

echo "=== Suricata setup complete ==="
