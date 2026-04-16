#!/bin/bash
# zeek_setup.sh — runs after suricata_setup.sh on the sensor box.
# Installs Zeek 8.0.x from the openSUSE OBS security:zeek repo
# (versioned package zeek-8.0 currently maps to 8.0.6) alongside
# Suricata. Both readers coexist on the primary NIC: Suricata via
# af-packet, Zeek via libpcap.
set +e
exec >> /var/log/suricata-setup.log 2>&1
echo "=== Zeek 8.0 Setup ==="

# Wait for any apt locks (the Suricata install may still hold them)
while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
  echo "Waiting for apt lock (zeek)..."
  sleep 5
done

PRIMARY_IF=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -1)
echo "Primary interface: ${PRIMARY_IF}"

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
