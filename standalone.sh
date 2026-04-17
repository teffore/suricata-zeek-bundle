#!/bin/bash
# standalone.sh — single-file Suricata 8 + Zeek 8 installer for Ubuntu 22.04.
#
# Usage:
#   sudo bash standalone.sh [--force] [--preserve-config] [--iface <name>]
set -e

FORCE=0
PRESERVE=0
IFACE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --force) FORCE=1; shift ;;
    --preserve-config) PRESERVE=1; shift ;;
    --iface) IFACE="$2"; shift 2 ;;
    -h|--help) sed -n '2,5p' "$0"; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: must run as root" >&2; exit 1
fi

TS="$(date +%Y%m%d-%H%M%S)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "=== standalone install starting ($(date -u +%FT%TZ)) ==="

# ---------- Prior-install detection + backup ----------
SURICATA_PRESENT=0; ZEEK_PRESENT=0
command -v suricata >/dev/null 2>&1 && SURICATA_PRESENT=1
{ [ -x /opt/zeek/bin/zeek ] || command -v zeek >/dev/null 2>&1; } && ZEEK_PRESENT=1

if { [ "$SURICATA_PRESENT" = 1 ] || [ "$ZEEK_PRESENT" = 1 ]; } && [ "$FORCE" = 0 ]; then
  echo "Prior install detected. Re-run with --force (existing configs will be backed up)."
  exit 3
fi
if [ "$SURICATA_PRESENT" = 1 ] && [ -d /etc/suricata ]; then
  cp -a /etc/suricata "/etc/suricata.bak.${TS}"
  echo "Backed up /etc/suricata -> /etc/suricata.bak.${TS}"
  systemctl stop suricata || true
fi
if [ "$ZEEK_PRESENT" = 1 ] && [ -d /opt/zeek/etc ]; then
  cp -a /opt/zeek/etc "/opt/zeek-etc.bak.${TS}"
  echo "Backed up /opt/zeek/etc -> /opt/zeek-etc.bak.${TS}"
  /opt/zeek/bin/zeekctl stop 2>/dev/null || true
fi

# ---------- Interface override ----------
if [ -n "$IFACE" ] && ! ip link show "$IFACE" >/dev/null 2>&1; then
  echo "ERROR: interface '$IFACE' not found" >&2; exit 4
fi

# ---------- Shared helpers ----------
detect_iface() {
  if [ -n "${IFACE:-}" ]; then
    printf '%s\n' "$IFACE"
  else
    ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -1
  fi
}

wait_for_apt_lock() {
  while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
    echo "Waiting for apt lock..."
    sleep 5
  done
}

apt_update_noninteractive() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
}

# Rule content lives past the exit 0 at the bottom of this file; pulled out at
# runtime via marker lines so the 600-line rule block doesn't dominate the
# script's control flow.
extract_custom_rules() {
  sed -n '/^# ---BEGIN CUSTOM_RULES---$/,/^# ---END CUSTOM_RULES---$/{//!p}' "$0" > "$1"
}

PRIMARY_IF=$(detect_iface)
export PRIMARY_IF IFACE
echo "Primary interface: ${PRIMARY_IF}"

BUNDLE_DIR="$WORK"
export BUNDLE_DIR

# ---------- Extract custom.rules to work dir (content at end of file) ----------
extract_custom_rules "$WORK/custom.rules"

# Preserve-config short path
if [ "$PRESERVE" = 1 ]; then
  install -d -m 0755 /var/lib/suricata/rules
  cp "$WORK/custom.rules" /var/lib/suricata/rules/custom.rules
  cat /var/lib/suricata/rules/custom.rules >> /var/lib/suricata/rules/suricata.rules
  suricata-update || true
  [ -x /opt/zeek/intel/build-intel.sh ] && /opt/zeek/intel/build-intel.sh || true
  systemctl restart suricata || true
  /opt/zeek/bin/zeekctl deploy 2>/dev/null || true
  echo "=== preserve-config install complete ==="
  exit 0
fi


# =============================================================
#   Suricata setup
# =============================================================
echo "=== Suricata IDS Setup (Ubuntu) ==="
wait_for_apt_lock

# Install Suricata from the OISF stable PPA.
# Ubuntu 22.04's default repo ships Suricata 6.0.x which reached EOL on
# 2024-08-01. The OISF stable PPA tracks the latest supported major (8.0.x
# as of 2026-03), which unblocks HTTP/2, QUIC/HTTP/3, and JA4.
apt_update_noninteractive
apt-get install -y software-properties-common

# If a pre-8 Suricata is already installed (e.g. distro 6.0.x, or a leftover
# from the OISF 7.0 LTS PPA), purge it before bringing in 8. The 7.0 PPA
# ships an LSB init.d wrapper (not a native systemd unit) that leaves stale
# pidfiles behind, which then break the 8.x systemd unit on first start.
if command -v suricata >/dev/null 2>&1; then
  CURRENT_VER=$(suricata --build-info 2>/dev/null | awk '/^This is Suricata version/ {print $5}' | head -1)
  MAJOR=${CURRENT_VER%%.*}
  if [ -n "$MAJOR" ] && [ "$MAJOR" -lt 8 ] 2>/dev/null; then
    echo "Found Suricata ${CURRENT_VER} (< 8); purging before reinstall"
    systemctl stop suricata 2>/dev/null || true
    rm -f /run/suricata.pid /var/run/suricata.pid
    apt-get purge -y suricata suricata-update 2>/dev/null || true
    add-apt-repository -y --remove ppa:oisf/suricata-7.0 2>/dev/null || true
    add-apt-repository -y --remove ppa:oisf/suricata-6.0 2>/dev/null || true
  fi
fi

add-apt-repository -y ppa:oisf/suricata-stable
apt-get update -y
apt-get install -y suricata jq logrotate

# yq for path-targeted edits to suricata.yaml (replaces fragile string-replace).
# Ubuntu's apt yq is a different tool (jq-wrapper); we want Mike Farah's Go yq.
if ! command -v yq >/dev/null 2>&1; then
  YQ_VERSION=v4.44.3
  curl -fsSL "https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}/yq_linux_amd64" \
    -o /usr/local/bin/yq
  chmod +x /usr/local/bin/yq
fi

# Stop suricata (apt auto-starts it with eth0 which fails)
systemctl stop suricata || true

# Fix /etc/default/suricata — older Ubuntu Suricata packages read IFACE from
# here. The OISF stable PPA build of Suricata 8.0.4 no longer ships this file
# (the systemd unit reads /etc/suricata/suricata.yaml directly), so guard the
# edits.
if [ -f /etc/default/suricata ]; then
  sed -i "s/IFACE=eth0/IFACE=${PRIMARY_IF}/" /etc/default/suricata
  sed -i "s/RUN=no/RUN=yes/" /etc/default/suricata
fi

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
# just the rule name. yq walks the parsed yaml tree and flips any
# 'metadata' key it finds to true; robust against layout drift.
yq -i '(.. | select(has("metadata"))).metadata = true' /etc/suricata/suricata.yaml

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
# sed (not yq) because yq discards comments — and these edits are
# uncommenting comment-hidden yaml entries.
sed -i 's/^\(\s*\)# - anomaly$/\1- anomaly/' /etc/suricata/suricata.yaml
sed -i -z 's/#   enabled: yes\n          #   types:/  enabled: yes\n            types:/' /etc/suricata/suricata.yaml

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

# =============================================================
#   Zeek setup
# =============================================================
# Wait for any apt locks (the Suricata install may still hold them)
wait_for_apt_lock

# ---------- Add OBS Zeek repo ----------
export DEBIAN_FRONTEND=noninteractive
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
  | gpg --batch --yes --dearmor -o /etc/apt/trusted.gpg.d/security_zeek.gpg
echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /" \
  > /etc/apt/sources.list.d/security_zeek.list
apt-get update -y

# ---------- Install Zeek 8.0 ----------
# zeek-8.0 is the versioned package name; pulls the latest 8.0.x patch.
apt-get install -y zeek-8.0
/opt/zeek/bin/zeek --version

# ---------- node.cfg: standalone on primary interface ----------
sed -i "s/interface=eth0/interface=${PRIMARY_IF}/" /opt/zeek/etc/node.cfg

# ---------- networks.cfg: define HOME_NET (all RFC 1918) ----------
# Zeek's Site::local_nets drives which connections are logged as local-vs-
# external in conn.log and triggers some default heuristics. Use the full
# RFC 1918 space so the sensor treats all private-address flows as internal.
cat >> /opt/zeek/etc/networks.cfg <<'EOF'
10.0.0.0/8       RFC 1918 / AWS lab VPC
172.16.0.0/12    RFC 1918
192.168.0.0/16   RFC 1918
EOF

# ---------- local.zeek: enable detection + correlation ----------
# - VXLAN: Zeek 8 default PacketAnalyzer::VXLAN::vxlan_ports already
#   includes 4789/udp, no redef needed.
# - Community ID hash on conn.log lets us correlate Zeek records with
#   Suricata alerts that share the same flow.
# - Built-in detection scripts that cost nothing at idle and produce
#   notices on real traffic patterns.
cat >> /opt/zeek/share/zeek/site/local.zeek <<'EOF'

# Community ID hash on conn.log for SIEM correlation with Suricata
@load policy/protocols/conn/community-id-logging

# Built-in detection scripts (free signal, no extra packages)
@load protocols/ssh/detect-bruteforcing
@load protocols/ftp/detect-bruteforcing
@load protocols/http/detect-webapps
@load frameworks/files/detect-MHR
@load frameworks/intel/seen

# Lower SSH brute-force threshold to match short-burst test runs
redef SSH::password_guesses_limit = 5;

# Iteration 8 — volumetric detection via stats framework. Stock
# Zeek 8 doesn't ship misc/scan (that's a zkg package, separate
# install). policy/misc/stats IS available and emits periodic
# engine stats to stats.log; useful telemetry for offline
# behavioral / rate-based analysis even though it doesn't emit
# notices itself.
@load misc/stats
redef Stats::report_interval = 60 sec;

# Intel Framework — load abuse.ch feeds from /opt/zeek/intel/intel.dat.
# Assembled by build-intel.sh below from URLhaus (malware domains)
# and Feodo Tracker (C2 IPs). Hits appear in intel.log with source
# attribution. base/frameworks/intel is already loaded by Zeek by
# default; we just point it at the feed file.
redef Intel::read_files += { "/opt/zeek/intel/intel.dat" };
EOF

# ---------- Zeek Intel Framework feeds (Iteration 7) ----------
# Fetch abuse.ch URLhaus (malware URLs, domains) and Feodo Tracker
# (botnet C2 IPs) feeds. Convert them to Zeek's intel.dat format
# (tab-separated: indicator, type, meta.source, meta.desc, meta.url).
mkdir -p /opt/zeek/intel
cat > /opt/zeek/intel/build-intel.sh <<'INTELSH'
#!/bin/bash
# Build /opt/zeek/intel/intel.dat from abuse.ch feeds.
set +e
DAT=/opt/zeek/intel/intel.dat
TMP=$(mktemp)
{
  printf "#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url\n"

  # URLhaus — hostfile format is "127.0.0.1 malicious-domain.com",
  # so we want $2 (the domain), and we strip Windows line endings.
  curl -fsSL --max-time 30 https://urlhaus.abuse.ch/downloads/hostfile/ 2>/dev/null \
    | tr -d '\r' \
    | awk '/^[^#]/ && NF>=2 {print $2 "\tIntel::DOMAIN\tabuse.ch/urlhaus\tMalware delivery host\t-"}'

  # Feodo Tracker — botnet C2 IPs (one per line)
  curl -fsSL --max-time 30 https://feodotracker.abuse.ch/downloads/ipblocklist.txt 2>/dev/null \
    | tr -d '\r' \
    | awk '/^[0-9]/ {print $1 "\tIntel::ADDR\tabuse.ch/feodo\tBotnet C2 IP\t-"}'
} > "$TMP"

# Only replace the live file if the build got more than just the header
if [ "$(wc -l < "$TMP")" -gt 1 ]; then
  mv "$TMP" "$DAT"
  chown suricata:suricata "$DAT" 2>/dev/null || true
else
  rm -f "$TMP"
fi
INTELSH
chmod +x /opt/zeek/intel/build-intel.sh
/opt/zeek/intel/build-intel.sh

# Refresh intel daily at 4:30am
echo "30 4 * * * root /opt/zeek/intel/build-intel.sh >/dev/null 2>&1" \
  > /etc/cron.d/zeek-intel
chmod 644 /etc/cron.d/zeek-intel

# ---------- Logrotate (zeekctl already rotates hourly; keep 7d compressed) ----------
cat > /etc/logrotate.d/zeek <<'LOGROTATE'
/opt/zeek/logs/*/*.log {
    daily
    rotate 7
    missingok
    compress
    delaycompress
    notifempty
}
LOGROTATE

# ---------- zeekctl cron (rotation, restart on crash, daily checks) ----------
echo "0 4 * * * root /opt/zeek/bin/zeekctl cron >/dev/null 2>&1" \
  > /etc/cron.d/zeek-cron
chmod 644 /etc/cron.d/zeek-cron

# ---------- systemd unit (auto-start on boot, clean shutdown) ----------
# zeekctl is the control surface; wrap it in a oneshot systemd unit so the
# kernel no longer SIGKILLs Zeek at shutdown (which caused "crashed" state
# on next boot) and so Zeek restarts with the host rather than waiting for
# the 04:00 zeekctl-cron job.
cat > /etc/systemd/system/zeek.service <<'UNIT'
[Unit]
Description=Zeek Network Security Monitor
Documentation=https://docs.zeek.org/
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/opt/zeek/bin/zeekctl start
ExecStop=/opt/zeek/bin/zeekctl stop
ExecReload=/opt/zeek/bin/zeekctl restart
TimeoutStopSec=60

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable zeek.service

# ---------- Deploy ----------
/opt/zeek/bin/zeekctl deploy
/opt/zeek/bin/zeekctl status

echo "=== Zeek setup complete ==="

echo ""
echo "=== standalone install complete ==="
echo "Log: /var/log/suricata-setup.log"

exit 0
: <<'CUSTOM_RULES_PAYLOAD'
# ---BEGIN CUSTOM_RULES---

# ========== Traffic mirror validation rules ==========
# sid:9000001 (TEST - ICMP) removed — pure noise (447 alerts/run, top of the
# histogram by volume). Real ICMP is covered by Suricata's decoder-event
# rules + ET ICMP + our C2 - Large ICMP payload sig (9000612).
alert tcp any any -> $HOME_NET 22 (msg:"TEST - SSH connection to HOME_NET"; sid:9000002; rev:2;)
alert tcp any any -> $HOME_NET any (msg:"TEST - TCP SYN scan detected"; flags:S,12; threshold:type both, track by_src, count 5, seconds 60; sid:9000003; rev:2;)

# ========== DNS tunneling detection rules ==========

# Long subdomain names (>40 chars in single label) — classic iodine/dnscat2 pattern
alert dns any any -> any any (msg:"DNS TUNNEL - Long subdomain label (>40 chars)"; \
  dns.query; pcre:"/^[a-z0-9]{40,}\./i"; \
  sid:9000101; rev:1; classtype:bad-unknown;)

# Very long subdomain names (>60 chars) — high confidence tunneling
alert dns any any -> any any (msg:"DNS TUNNEL - Very long subdomain label (>60 chars)"; \
  dns.query; pcre:"/^[a-z0-9]{60,}\./i"; \
  sid:9000102; rev:1; classtype:bad-unknown;)

# Hex-encoded subdomain (common in DNS exfiltration tools)
alert dns any any -> any any (msg:"DNS TUNNEL - Hex-encoded subdomain"; \
  dns.query; pcre:"/^[a-f0-9]{20,}\./i"; \
  sid:9000103; rev:1; classtype:bad-unknown;)

# Base64-like subdomain pattern
alert dns any any -> any any (msg:"DNS TUNNEL - Base64-like subdomain"; \
  dns.query; pcre:"/^[A-Za-z0-9+\/=]{30,}\./"; \
  sid:9000104; rev:1; classtype:bad-unknown;)

# High-frequency DNS queries from single source (volume-based tunneling)
alert dns any any -> any any (msg:"DNS TUNNEL - High query rate from single source"; \
  threshold:type both, track by_src, count 20, seconds 10; \
  sid:9000105; rev:1; classtype:bad-unknown;)

# Suspicious TLDs commonly used by malware/tunneling
alert dns any any -> any any (msg:"DNS POLICY - Query to suspicious TLD (.tk)"; \
  dns.query; content:".tk"; endswith; nocase; \
  sid:9000106; rev:1; classtype:policy-violation;)

alert dns any any -> any any (msg:"DNS POLICY - Query to .xyz TLD"; \
  dns.query; content:".xyz"; endswith; nocase; \
  sid:9000107; rev:1; classtype:policy-violation;)

alert dns any any -> any any (msg:"DNS POLICY - Query to .onion (Tor)"; \
  dns.query; content:".onion"; endswith; nocase; \
  sid:9000108; rev:1; classtype:policy-violation;)

# DNS zone transfer attempt (AXFR)
alert tcp any any -> $HOME_NET 53 (msg:"DNS RECON - Zone transfer attempt (AXFR)"; \
  dsize:>10; content:"|00 00 FC|"; \
  sid:9000109; rev:1; classtype:attempted-recon;)

# NULL record queries (dnscat2 signature)
alert dns any any -> any any (msg:"DNS TUNNEL - NULL record query (dnscat2)"; \
  dns.query; content:"|00 00 0A|"; \
  sid:9000110; rev:1; classtype:bad-unknown;)

# Excessive TXT record requests (data exfiltration channel)
alert dns any any -> any any (msg:"DNS TUNNEL - High volume TXT record queries"; \
  dns.query; pcre:"/^.+\.exfil\./i"; \
  threshold:type both, track by_src, count 5, seconds 30; \
  sid:9000111; rev:1; classtype:bad-unknown;)

# Entropy-like patterns (all-random-looking subdomain)
alert dns any any -> any any (msg:"DNS TUNNEL - High-entropy subdomain (mixed chars)"; \
  dns.query; pcre:"/^(?=[a-z0-9]{25,})(?=(?:[a-z0-9]*[0-9]){5,})(?=(?:[a-z0-9]*[a-z]){10,})[a-z0-9]+\./i"; \
  sid:9000112; rev:1; classtype:bad-unknown;)

# ========== URL encoding evasion detection (Iteration 1) ==========

# Double URL encoding of path traversal (%252e = .)
alert http any any -> any any (msg:"EVASION - Double URL-encoded path traversal"; \
  http.uri; content:"%252e%252e"; nocase; \
  sid:9000201; rev:1; classtype:web-application-attack;)

# Triple URL encoding
# NOTE: Use http.uri.raw — http.uri is normalized (URL-decoded once)
# so the literal encoded form '%25252e' is gone before content matching.
alert http any any -> any any (msg:"EVASION - Triple URL-encoded path traversal"; \
  http.uri.raw; content:"%25252e"; nocase; \
  sid:9000202; rev:2; classtype:web-application-attack;)

# Unicode full-width character bypass — match on http.uri (post-normalize)
# OR http.request.body (POST body) since attacks may use either.
alert http any any -> any any (msg:"EVASION - Unicode full-width char in URL/body"; \
  pcre:"/[\xef\xbc\x8e\xef\xbc\x8f]/H"; \
  sid:9000203; rev:2; classtype:web-application-attack;)

# Double-encoded SQLi (also needs raw to see %25 prefix)
alert http any any -> any any (msg:"EVASION - Double URL-encoded SQLi keyword"; \
  http.uri.raw; content:"%2527"; nocase; content:"%2520OR%2520"; nocase; \
  sid:9000204; rev:2; classtype:web-application-attack;)

# CRLF injection in URL
alert http any any -> any any (msg:"EVASION - CRLF injection in URL"; \
  http.uri.raw; content:"%0d%0a"; nocase; \
  sid:9000205; rev:2; classtype:web-application-attack;)

# ========== Cloud metadata access patterns (Iteration 1) ==========

# Azure metadata access via SSRF
alert http any any -> any any (msg:"CLOUD - Azure IMDS access via SSRF"; \
  http.uri; content:"169.254.169.254/metadata/instance"; nocase; \
  sid:9000210; rev:1; classtype:attempted-recon;)

# Azure metadata token endpoint
alert http any any -> any any (msg:"CLOUD - Azure managed identity token request via SSRF"; \
  http.uri; content:"169.254.169.254/metadata/identity/oauth2/token"; nocase; \
  sid:9000211; rev:1; classtype:attempted-recon;)

# GCP metadata access
alert http any any -> any any (msg:"CLOUD - GCP metadata access via SSRF"; \
  http.uri; content:"metadata.google.internal"; nocase; \
  sid:9000212; rev:1; classtype:attempted-recon;)

# Azure Storage enumeration
alert dns any any -> any any (msg:"CLOUD - Azure Blob Storage enumeration"; \
  dns.query; content:".blob.core.windows.net"; endswith; nocase; \
  sid:9000213; rev:1; classtype:attempted-recon;)

# GCP Storage enumeration
alert dns any any -> any any (msg:"CLOUD - GCP Cloud Storage enumeration"; \
  dns.query; content:".storage.googleapis.com"; endswith; nocase; \
  sid:9000214; rev:1; classtype:attempted-recon;)

# Azure AD credential theft attempt
alert http any any -> any any (msg:"CLOUD - Azure AD token endpoint credential attempt"; \
  http.uri; content:"login.microsoftonline.com"; nocase; \
  http.request_body; content:"grant_type=password"; nocase; \
  sid:9000215; rev:1; classtype:attempted-admin;)

# AWS credential format in POST body (AKIA pattern)
alert http any any -> any any (msg:"EXFIL - AWS access key format in POST body"; \
  http.request_body; pcre:"/AKIA[0-9A-Z]{16}/"; \
  sid:9000216; rev:1; classtype:credential-theft;)

# GCP service account key format exfil
alert http any any -> any any (msg:"EXFIL - GCP service account key format in POST"; \
  http.request_body; content:"\"type\":\"service_account\""; nocase; \
  content:"\"private_key\""; nocase; \
  sid:9000217; rev:1; classtype:credential-theft;)

# ========== Web Shell Detection (Iteration 2) ==========

alert http any any -> any any (msg:"WEBSHELL - Request for c99 shell"; \
  http.uri; content:"c99.php"; nocase; \
  sid:9000301; rev:1; classtype:web-application-attack;)

alert http any any -> any any (msg:"WEBSHELL - Request for r57 shell"; \
  http.uri; content:"r57.php"; nocase; \
  sid:9000302; rev:1; classtype:web-application-attack;)

alert http any any -> any any (msg:"WEBSHELL - Request for b374k shell"; \
  http.uri; content:"b374k.php"; nocase; \
  sid:9000303; rev:1; classtype:web-application-attack;)

alert http any any -> any any (msg:"WEBSHELL - Request for WSO shell"; \
  http.uri; content:"wso.php"; nocase; \
  sid:9000304; rev:1; classtype:web-application-attack;)

alert http any any -> any any (msg:"WEBSHELL - Generic shell.php request"; \
  http.uri; content:"/shell.php"; nocase; \
  sid:9000305; rev:1; classtype:web-application-attack;)

alert http any any -> any any (msg:"WEBSHELL - China Chopper pattern (z0 base64)"; \
  http.request_body; content:"z0="; depth:5; \
  sid:9000306; rev:1; classtype:web-application-attack;)

alert http any any -> any any (msg:"WEBSHELL - JSP webshell cmd parameter"; \
  http.uri; content:".jsp"; nocase; content:"cmd="; \
  sid:9000307; rev:1; classtype:web-application-attack;)

# ========== SQL Injection Custom Rules ==========

alert http any any -> any any (msg:"SQLI - Time-based SQLi (SLEEP)"; \
  http.uri; content:"SLEEP("; nocase; \
  sid:9000310; rev:1; classtype:web-application-attack;)

alert http any any -> any any (msg:"SQLI - Time-based SQLi (WAITFOR DELAY)"; \
  http.uri; content:"WAITFOR"; nocase; content:"DELAY"; nocase; \
  sid:9000311; rev:1; classtype:web-application-attack;)

alert http any any -> any any (msg:"SQLI - Error-based SQLi (extractvalue)"; \
  http.uri; content:"extractvalue"; nocase; \
  sid:9000312; rev:1; classtype:web-application-attack;)

alert http any any -> any any (msg:"SQLI - UNION SELECT LOAD_FILE exfil"; \
  http.uri; content:"UNION"; nocase; content:"LOAD_FILE"; nocase; \
  sid:9000313; rev:1; classtype:web-application-attack;)

alert http any any -> any any (msg:"SQLI - INTO OUTFILE webshell write"; \
  http.uri; content:"INTO"; nocase; content:"OUTFILE"; nocase; \
  sid:9000314; rev:1; classtype:web-application-attack;)

# ========== XSS Custom Rules ==========

alert http any any -> any any (msg:"XSS - SVG onload payload"; \
  http.uri; pcre:"/svg[\x00-\x20]*\/?[\x00-\x20]*onload/i"; \
  sid:9000320; rev:1; classtype:web-application-attack;)

alert http any any -> any any (msg:"XSS - javascript: protocol"; \
  http.uri; content:"javascript"; nocase; content:":alert"; nocase; \
  sid:9000321; rev:1; classtype:web-application-attack;)

alert http any any -> any any (msg:"XSS - body onload payload"; \
  http.uri; pcre:"/<body[\x00-\x20]+onload/i"; \
  sid:9000322; rev:1; classtype:web-application-attack;)

alert http any any -> any any (msg:"XSS - img onerror payload"; \
  http.uri; pcre:"/<img[^>]+onerror=/i"; \
  sid:9000323; rev:1; classtype:web-application-attack;)

# ========== XXE, SSTI, LFI, NoSQL Detection ==========

alert http any any -> any any (msg:"XXE - External entity with file:// protocol"; \
  http.request_body; content:"<!ENTITY"; nocase; content:"SYSTEM"; nocase; content:"file://"; nocase; \
  sid:9000330; rev:1; classtype:web-application-attack;)

alert http any any -> any any (msg:"SSTI - Template injection {{7*7}}"; \
  http.uri; content:"{{7*7}}"; \
  sid:9000331; rev:1; classtype:web-application-attack;)

alert http any any -> any any (msg:"LFI - PHP filter wrapper"; \
  http.uri; content:"php://filter"; nocase; \
  sid:9000332; rev:1; classtype:web-application-attack;)

alert http any any -> any any (msg:"LFI - PHP data:// wrapper with base64"; \
  http.uri; content:"data://text/plain|3b|base64"; nocase; \
  sid:9000333; rev:1; classtype:web-application-attack;)

alert http any any -> any any (msg:"LFI - expect:// wrapper (RCE)"; \
  http.uri; content:"expect://"; nocase; \
  sid:9000334; rev:1; classtype:web-application-attack;)

alert http any any -> any any (msg:"NOSQLI - MongoDB \$ne operator injection"; \
  http.request_body; content:"{\"$ne\":"; \
  sid:9000335; rev:1; classtype:web-application-attack;)

# ========== Active Directory / LDAP / Kerberos Detection (Iteration 3) ==========

# LDAP injection patterns in URL
alert http any any -> any any (msg:"LDAPI - LDAP injection wildcard in parameter"; \
  http.uri; pcre:"/[?&][a-z_]+=\*\)\(/i"; \
  sid:9000401; rev:1; classtype:web-application-attack;)

alert http any any -> any any (msg:"LDAPI - LDAP filter bypass (objectClass=*)"; \
  http.uri; content:"objectClass=*"; nocase; \
  sid:9000402; rev:1; classtype:web-application-attack;)

# NTLM authentication attempts in HTTP (pass-the-hash / relay)
alert http any any -> any any (msg:"AD - NTLM authentication type 1 negotiate"; \
  http.header; content:"Authorization: NTLM TlRMTVNTUAAB"; nocase; \
  sid:9000410; rev:1; classtype:attempted-admin;)

alert http any any -> any any (msg:"AD - NTLM authentication type 3 response (auth)"; \
  http.header; content:"Authorization: NTLM TlRMTVNTUAAD"; nocase; \
  sid:9000411; rev:1; classtype:attempted-admin;)

# Kerberoasting - SPN-based service ticket requests in URLs
alert http any any -> any any (msg:"AD - Kerberoasting SPN in URL parameter"; \
  http.uri; content:"spn="; nocase; pcre:"/spn=(HTTP|MSSQLSvc|CIFS|HOST|LDAP)\//i"; \
  sid:9000412; rev:1; classtype:attempted-admin;)

# BloodHound/SharpHound discovery
alert http any any -> any any (msg:"AD - BloodHound SharpHound tool usage"; \
  http.uri; content:"sharphound"; nocase; \
  sid:9000413; rev:1; classtype:trojan-activity;)

alert http any any -> any any (msg:"AD - Impacket tool user-agent"; \
  http.user_agent; content:"impacket"; nocase; \
  sid:9000414; rev:1; classtype:trojan-activity;)

alert http any any -> any any (msg:"AD - Responder tool user-agent"; \
  http.user_agent; content:"Responder"; \
  sid:9000415; rev:1; classtype:trojan-activity;)

# DNS queries for AD SRV records (domain controller discovery)
alert dns any any -> any any (msg:"AD - LDAP SRV record discovery (_ldap._tcp)"; \
  dns.query; content:"_ldap._tcp"; nocase; \
  sid:9000420; rev:1; classtype:attempted-recon;)

alert dns any any -> any any (msg:"AD - Kerberos SRV record discovery (_kerberos._tcp)"; \
  dns.query; content:"_kerberos._tcp"; nocase; \
  sid:9000421; rev:1; classtype:attempted-recon;)

alert dns any any -> any any (msg:"AD - Global Catalog SRV discovery (_gc._tcp)"; \
  dns.query; content:"_gc._tcp"; nocase; \
  sid:9000422; rev:1; classtype:attempted-recon;)

# ADCS (Certificate Services) abuse
alert http any any -> any any (msg:"AD - Active Directory Certificate Services access"; \
  http.uri; content:"/certsrv/"; nocase; \
  sid:9000423; rev:1; classtype:attempted-admin;)

# Group Policy Preferences password file (cpassword)
alert http any any -> any any (msg:"AD - Group Policy Preferences Groups.xml access"; \
  http.uri; content:"Groups.xml"; nocase; content:"Preferences"; nocase; \
  sid:9000424; rev:1; classtype:policy-violation;)

# NTDS.dit database file access
alert http any any -> any any (msg:"AD - ntds.dit database file access attempt"; \
  http.uri; content:"ntds.dit"; nocase; \
  sid:9000425; rev:1; classtype:attempted-admin;)

# DCSync pattern
alert http any any -> any any (msg:"AD - DCSync DRSUAPI replication request"; \
  http.request_body; content:"DRSUAPI"; nocase; content:"GetNCChanges"; nocase; \
  sid:9000426; rev:1; classtype:attempted-admin;)

# Direct LDAP/Kerberos TCP connection to victim
alert tcp any any -> $HOME_NET 88 (msg:"AD - Kerberos direct TCP connection"; \
  flow:to_server; flags:S,12; \
  sid:9000430; rev:2; classtype:attempted-recon;)

alert tcp any any -> $HOME_NET 389 (msg:"AD - LDAP direct TCP connection"; \
  flow:to_server; flags:S,12; \
  sid:9000431; rev:2; classtype:attempted-recon;)

alert tcp any any -> $HOME_NET 636 (msg:"AD - LDAPS direct TCP connection"; \
  flow:to_server; flags:S,12; \
  sid:9000432; rev:2; classtype:attempted-recon;)

# ========== Supply Chain Attack Detection (Iteration 4) ==========

# Malicious package postinstall scripts
alert http any any -> any any (msg:"SUPPLYCHAIN - Malicious postinstall script in npm package"; \
  http.request_body; content:"postinstall"; nocase; content:"curl"; nocase; \
  sid:9000501; rev:1; classtype:trojan-activity;)

alert http any any -> any any (msg:"SUPPLYCHAIN - Cryptominer in npm postinstall"; \
  http.request_body; content:"postinstall"; nocase; content:"xmrig"; nocase; \
  sid:9000502; rev:1; classtype:trojan-activity;)

# PyPI malicious setup.py
alert http any any -> any any (msg:"SUPPLYCHAIN - Malicious PyPI setup.py with shell exec"; \
  http.request_body; content:"os.system"; nocase; content:"curl"; nocase; \
  sid:9000503; rev:1; classtype:trojan-activity;)

# GitHub token exfiltration
alert http any any -> any any (msg:"EXFIL - GitHub token (ghs_ pattern) in POST body"; \
  http.request_body; pcre:"/ghs_[A-Za-z0-9]{36,}/"; \
  sid:9000504; rev:1; classtype:credential-theft;)

alert http any any -> any any (msg:"EXFIL - GitHub PAT (ghp_ pattern) in POST body"; \
  http.request_body; pcre:"/ghp_[A-Za-z0-9]{36,}/"; \
  sid:9000505; rev:1; classtype:credential-theft;)

# Typosquatted package names (common real-world examples)
alert http any any -> any any (msg:"SUPPLYCHAIN - Known npm typosquat (eventstram)"; \
  http.uri; content:"eventstram"; nocase; \
  sid:9000510; rev:1; classtype:trojan-activity;)

alert http any any -> any any (msg:"SUPPLYCHAIN - Known pip typosquat (reqeusts)"; \
  http.uri; content:"reqeusts"; nocase; \
  sid:9000511; rev:1; classtype:trojan-activity;)

# Terraform registry spoofing
alert http any any -> any any (msg:"SUPPLYCHAIN - Suspicious Terraform registry TLD"; \
  http.uri; pcre:"/registry\.terraform\.(xyz|tk|top|ml|ga)/i"; \
  sid:9000512; rev:1; classtype:trojan-activity;)

# CLI tool user-agents from HTTP (outside proper package manager contexts)
alert http any any -> any any (msg:"SUPPLYCHAIN - npm CLI accessing non-registry endpoint"; \
  http.user_agent; content:"npm/"; nocase; \
  http.uri; content:"/api/"; pcre:"/\/api\/(keys|secrets|admin)/i"; \
  sid:9000513; rev:1; classtype:policy-violation;)

# ========== Anomaly Tuning / Noise Suppression ==========
# Note: These use pass rules to whitelist specific patterns. Pass rules
# are evaluated before alert rules and prevent alerts.

# Suppress internal Nmap scans from known hosts (placeholder example)
# pass tcp $HOME_NET any -> any any (msg:"Whitelisted scanner"; sid:9000990; rev:1;)

# Note: Can't easily suppress already-fired alerts via custom rules.
# Production tuning is done via threshold.config or suricata-update --disable.

# ========== Advanced C2 Framework Detection (Iteration 5) ==========

alert http any any -> any any (msg:"C2 - Havoc framework news.html beacon URI"; \
  http.uri; content:"/news.html?id="; nocase; \
  sid:9000601; rev:1; classtype:trojan-activity;)

alert http any any -> any any (msg:"C2 - Brute Ratel BRC4 api/search pattern"; \
  http.uri; pcre:"/\/api\/search\/[a-f0-9]{16}/i"; \
  sid:9000602; rev:1; classtype:trojan-activity;)

alert http any any -> any any (msg:"C2 - Mythic agent_message endpoint"; \
  http.uri; content:"/api/v1.4/agent_message"; nocase; \
  sid:9000603; rev:1; classtype:trojan-activity;)

alert http any any -> any any (msg:"C2 - Poshc2/Empire news.php task beacon"; \
  http.uri; content:"/news.php?task="; nocase; \
  sid:9000604; rev:1; classtype:trojan-activity;)

# Beaconing behavioral patterns
alert http any any -> any any (msg:"C2 - Repeated CA00 submit.php beacon pattern"; \
  http.uri; content:"/submit.php?id=CA00"; nocase; \
  threshold:type both, track by_src, count 3, seconds 30; \
  sid:9000605; rev:1; classtype:trojan-activity;)

# DNS beaconing
alert dns any any -> any any (msg:"C2 - Periodic DNS beacon pattern"; \
  dns.query; pcre:"/^beacon-[0-9]{10}\./i"; \
  threshold:type both, track by_src, count 3, seconds 30; \
  sid:9000606; rev:1; classtype:trojan-activity;)

# Reverse shell command patterns
alert http any any -> any any (msg:"RCE - Bash reverse shell in URL"; \
  http.uri; content:"bash"; nocase; content:"%2Fdev%2Ftcp%2F"; nocase; \
  sid:9000610; rev:1; classtype:attempted-admin;)

alert http any any -> any any (msg:"RCE - Python reverse shell import pattern"; \
  http.uri; content:"python"; nocase; content:"socket%2Csubprocess%2Cos"; nocase; \
  sid:9000611; rev:1; classtype:attempted-admin;)

# ICMP tunneling (large data payload)
alert icmp any any -> any any (msg:"C2 - Large ICMP payload (possible tunneling)"; \
  dsize:>512; itype:8; \
  sid:9000612; rev:1; classtype:bad-unknown;)

alert icmp any any -> any any (msg:"C2 - ICMP with repeating pattern (tunneling)"; \
  content:"AAAAAAAAAAAAAAAA"; depth:16; \
  sid:9000613; rev:1; classtype:bad-unknown;)

# DNS-over-HTTPS to known DoH resolvers (potential tunneling)
alert http any any -> any any (msg:"C2 - DoH query to cloudflare-dns"; \
  http.uri; content:"cloudflare-dns.com/dns-query"; nocase; \
  sid:9000614; rev:1; classtype:policy-violation;)

# ========== Container/Kubernetes Detection (Iteration 6) ==========

alert http any any -> any any (msg:"CONTAINER - Docker socket access attempt"; \
  http.uri; content:"docker.sock"; nocase; \
  sid:9000701; rev:1; classtype:attempted-admin;)

alert http any any -> any any (msg:"CONTAINER - Privileged container creation"; \
  http.request_body; content:"Privileged"; nocase; content:"true"; nocase; \
  sid:9000702; rev:1; classtype:attempted-admin;)

alert http any any -> any any (msg:"CONTAINER - nsenter host namespace escape"; \
  http.request_body; content:"nsenter"; nocase; content:"/proc/1/ns/mnt"; nocase; \
  sid:9000703; rev:1; classtype:attempted-admin;)

alert tcp any any -> $HOME_NET 6443 (msg:"K8S - Direct Kubernetes API server connection"; \
  flow:to_server; flags:S,12; \
  sid:9000710; rev:2; classtype:attempted-recon;)

alert tcp any any -> $HOME_NET 10250 (msg:"K8S - Kubelet API direct connection"; \
  flow:to_server; flags:S,12; \
  sid:9000711; rev:2; classtype:attempted-recon;)

alert tcp any any -> $HOME_NET 2379 (msg:"K8S - etcd direct unauthenticated access"; \
  flow:to_server; flags:S,12; \
  sid:9000712; rev:2; classtype:attempted-admin;)

alert http any any -> any any (msg:"K8S - Kubelet exec endpoint access"; \
  http.uri; content:"/exec/"; pcre:"/\/exec\/[a-z]+\/[a-z0-9-]+\/[a-z0-9-]+/i"; \
  sid:9000713; rev:1; classtype:attempted-admin;)

alert http any any -> any any (msg:"K8S - Secrets API enumeration"; \
  http.uri; content:"/api/v1/namespaces/kube-system/secrets"; nocase; \
  sid:9000714; rev:1; classtype:attempted-admin;)

alert http any any -> any any (msg:"K8S - ClusterRoleBindings enumeration"; \
  http.uri; content:"/clusterrolebindings"; nocase; \
  sid:9000715; rev:1; classtype:attempted-recon;)

alert http any any -> any any (msg:"CONTAINER - Cgroup release_agent escape"; \
  http.uri; content:"/sys/fs/cgroup/release_agent"; nocase; \
  sid:9000716; rev:1; classtype:attempted-admin;)

alert http any any -> any any (msg:"K8S - Service account token theft"; \
  http.uri; content:"/var/run/secrets/kubernetes.io/serviceaccount/token"; nocase; \
  sid:9000717; rev:1; classtype:credential-theft;)

alert http any any -> any any (msg:"CONTAINER - Registry catalog enumeration"; \
  http.uri; content:"/v2/_catalog"; \
  sid:9000718; rev:1; classtype:attempted-recon;)

# ========== API Abuse Detection (Iteration 7) ==========

alert http any any -> any any (msg:"API - GraphQL introspection query"; \
  http.request_body; content:"__schema"; nocase; \
  sid:9000801; rev:1; classtype:attempted-recon;)

alert http any any -> any any (msg:"API - JWT with 'none' algorithm"; \
  http.header; content:"Bearer eyJ"; content:"alg\":\"none"; distance:0; within:200; \
  sid:9000802; rev:1; classtype:attempted-admin;)

alert http any any -> any any (msg:"API - Mass assignment with is_admin=true"; \
  http.request_body; content:"is_admin"; nocase; content:"true"; distance:0; within:20; \
  sid:9000803; rev:1; classtype:web-application-attack;)

alert http any any -> any any (msg:"API - OpenAPI/Swagger enumeration"; \
  http.uri; pcre:"/\/(swagger|openapi|api-docs|v[23]\/api-docs)(\.json)?/i"; \
  sid:9000804; rev:1; classtype:attempted-recon;)

alert http any any -> any any (msg:"API - HTTP verb tampering (X-HTTP-Method-Override)"; \
  http.header; content:"X-HTTP-Method-Override"; nocase; \
  sid:9000805; rev:1; classtype:web-application-attack;)

alert http any any -> any any (msg:"API - Rate limit bypass (X-Originating-IP header)"; \
  http.header; content:"X-Originating-IP"; nocase; \
  sid:9000806; rev:1; classtype:web-application-attack;)

alert http any any -> any any (msg:"API - Webhook SSRF to IMDS"; \
  http.request_body; content:"webhook_url"; nocase; content:"169.254.169.254"; \
  sid:9000807; rev:1; classtype:attempted-recon;)

alert http any any -> any any (msg:"API - IDOR private resource enumeration"; \
  http.uri; pcre:"/\/api\/[a-z]+\/[0-9]+\/private/i"; \
  sid:9000808; rev:1; classtype:attempted-recon;)

# ========== SaaS Exfil Destinations (Iteration 3) ==========
# Detect outbound TLS to commonly-abused SaaS endpoints used for data
# exfiltration / C2. SNI-based — works without TLS decryption.

alert tls any any -> any any (msg:"EXFIL - TLS connection to Pastebin"; \
  tls.sni; content:"pastebin.com"; nocase; \
  sid:9000901; rev:1; classtype:policy-violation;)

alert tls any any -> any any (msg:"EXFIL - TLS connection to transfer.sh"; \
  tls.sni; content:"transfer.sh"; nocase; \
  sid:9000902; rev:1; classtype:policy-violation;)

alert tls any any -> any any (msg:"EXFIL - TLS connection to Discord webhook"; \
  tls.sni; content:"discord.com"; nocase; \
  sid:9000903; rev:1; classtype:policy-violation;)

alert tls any any -> any any (msg:"EXFIL - TLS connection to GitHub gist"; \
  tls.sni; content:"gist.githubusercontent.com"; nocase; \
  sid:9000904; rev:1; classtype:policy-violation;)

alert tls any any -> any any (msg:"EXFIL - TLS connection to telegra.ph"; \
  tls.sni; content:"telegra.ph"; nocase; \
  sid:9000905; rev:1; classtype:policy-violation;)

# Also catch via DNS query (covers cases where TLS isn't established)
alert dns any any -> any any (msg:"EXFIL - DNS query for Pastebin"; \
  dns.query; content:"pastebin.com"; nocase; endswith; \
  sid:9000910; rev:1; classtype:policy-violation;)

alert dns any any -> any any (msg:"EXFIL - DNS query for transfer.sh"; \
  dns.query; content:"transfer.sh"; nocase; endswith; \
  sid:9000911; rev:1; classtype:policy-violation;)

# ========== Tunneling-Service Reverse-Shell IOCs (Iteration 3) ==========
# Outbound to ngrok / cloudflare tunnel / serveo / localtunnel — strong
# pentester / red-team / unauthorized-tunnel indicator.

alert dns any any -> any any (msg:"TUNNEL - DNS query for ngrok"; \
  dns.query; content:"ngrok"; nocase; \
  sid:9000920; rev:1; classtype:trojan-activity;)

alert tls any any -> any any (msg:"TUNNEL - TLS SNI to ngrok"; \
  tls.sni; content:"ngrok"; nocase; \
  sid:9000921; rev:1; classtype:trojan-activity;)

alert dns any any -> any any (msg:"TUNNEL - DNS query for trycloudflare"; \
  dns.query; content:"trycloudflare.com"; nocase; \
  sid:9000922; rev:1; classtype:trojan-activity;)

alert tls any any -> any any (msg:"TUNNEL - TLS SNI to trycloudflare"; \
  tls.sni; content:"trycloudflare.com"; nocase; \
  sid:9000923; rev:1; classtype:trojan-activity;)

alert dns any any -> any any (msg:"TUNNEL - DNS query for serveo"; \
  dns.query; content:"serveo.net"; nocase; endswith; \
  sid:9000924; rev:1; classtype:trojan-activity;)

alert dns any any -> any any (msg:"TUNNEL - DNS query for localtunnel"; \
  dns.query; content:"loca.lt"; nocase; endswith; \
  sid:9000925; rev:1; classtype:trojan-activity;)

# ========== Lateral Movement — SMB / DCERPC (Iteration 4) ==========
# Detect Windows-style lateral movement primitives reaching our victim
# (Linux samba). Even when auth fails, the SMB protocol exchange is
# enough to populate Suricata's smb.named_pipe and dcerpc.iface buffers.
# MITRE T1021.002 (SMB/Admin shares) and T1021.003 (DCOM/RPC) family.

# Admin-share tree connects (ADMIN$, C$) — strong PsExec / lateral move IOC
alert smb any any -> $HOME_NET any (msg:"LATERAL - SMB tree connect to ADMIN$"; \
  smb.share; content:"ADMIN$"; nocase; \
  sid:9001001; rev:1; classtype:attempted-admin;)

alert smb any any -> $HOME_NET any (msg:"LATERAL - SMB tree connect to C$"; \
  smb.share; content:"C$"; nocase; \
  sid:9001002; rev:1; classtype:attempted-admin;)

alert smb any any -> $HOME_NET any (msg:"LATERAL - SMB tree connect to IPC$ (enumeration)"; \
  smb.share; content:"IPC$"; nocase; \
  sid:9001003; rev:1; classtype:attempted-recon;)

# Specific named pipes used by lateral move tools.
# Iter-6 note: SMB2/3 transmits named pipe names as UTF-16LE. Zeek
# decodes that transparently; Suricata needs the explicit hex-byte
# form. Each char c becomes "c 00" in the byte stream.
alert tcp any any -> $HOME_NET 445 (msg:"LATERAL - PsExec service named pipe (PSEXESVC)"; \
  flow:to_server,established; \
  content:"|50 00 53 00 45 00 58 00 45 00 53 00 56 00 43 00|"; nocase; \
  sid:9001010; rev:3; classtype:attempted-admin;)

alert tcp any any -> $HOME_NET 445 (msg:"LATERAL - svcctl named pipe (Service Control)"; \
  flow:to_server,established; \
  content:"|73 00 76 00 63 00 63 00 74 00 6c 00|"; nocase; \
  sid:9001011; rev:3; classtype:attempted-admin;)

alert tcp any any -> $HOME_NET 445 (msg:"LATERAL - winreg named pipe (Remote Registry)"; \
  flow:to_server,established; \
  content:"|77 00 69 00 6e 00 72 00 65 00 67 00|"; nocase; \
  sid:9001012; rev:3; classtype:attempted-admin;)

alert tcp any any -> $HOME_NET 445 (msg:"LATERAL - atsvc named pipe (AT scheduler)"; \
  flow:to_server,established; \
  content:"|61 00 74 00 73 00 76 00 63 00|"; nocase; \
  sid:9001013; rev:3; classtype:attempted-admin;)

alert tcp any any -> $HOME_NET 445 (msg:"LATERAL - samr named pipe (account enum)"; \
  flow:to_server,established; \
  content:"|73 00 61 00 6d 00 72 00|"; nocase; \
  sid:9001014; rev:3; classtype:attempted-recon;)

alert tcp any any -> $HOME_NET 445 (msg:"LATERAL - lsarpc named pipe (LSA / DCSync setup)"; \
  flow:to_server,established; \
  content:"|6c 00 73 00 61 00 72 00 70 00 63 00|"; nocase; \
  sid:9001015; rev:3; classtype:attempted-admin;)

# DCERPC interface UUIDs (alert on bind/call to these RPC interfaces)
# 367abb81-9844-35f1-ad32-98f038001003 = svcctl (Service Control Mgr)
alert dcerpc any any -> $HOME_NET any (msg:"LATERAL - DCERPC bind to svcctl interface"; \
  dcerpc.iface:367abb81-9844-35f1-ad32-98f038001003; \
  sid:9001020; rev:2; classtype:attempted-admin;)

# 12345778-1234-abcd-ef00-0123456789ac = SAMR
alert dcerpc any any -> $HOME_NET any (msg:"LATERAL - DCERPC bind to SAMR (account enum)"; \
  dcerpc.iface:12345778-1234-abcd-ef00-0123456789ac; \
  sid:9001021; rev:2; classtype:attempted-recon;)
# ---END CUSTOM_RULES---
CUSTOM_RULES_PAYLOAD
