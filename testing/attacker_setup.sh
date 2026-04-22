#!/bin/bash
# attacker_setup.sh — installs the toolkit run_attacks.sh expects on the
# attacker box. Distro-aware: runs on Kali Linux (CI default) AND on plain
# Ubuntu 22.04 (fallback, also used for local dev).
#
# On Kali almost everything is preinstalled; we still run apt-get so the
# package db is fresh and any missing bits (nghttp2-client, python3-paramiko
# on older images) are pulled in. On Ubuntu we install from universe and
# hand-roll impacket-* wrappers because Ubuntu's python3-impacket ships only
# the Python sources under /usr/share/ — no shims.
#
# Per-package install (not a single apt-get line) so one missing package in
# universe doesn't roll back the whole batch and leave the attack run
# silently calling 'command not found'.
#
# Output streams back through SSH — no /var/log redirect — so CI sees what
# installed.

set -e
export DEBIAN_FRONTEND=noninteractive

echo "=== Attacker toolkit setup ==="

# Detect distro so we pick the right impacket-provisioning path.
IS_KALI=0
if grep -qi '^ID=kali' /etc/os-release 2>/dev/null \
   || grep -qi 'kali' /etc/os-release 2>/dev/null; then
  IS_KALI=1
  echo "  distro: Kali Linux"
else
  echo "  distro: $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
fi

apt-get update -y -qq

# Required tools — install failure aborts the script.
#   nmap        — port/service/vuln scans
#   curl        — HTTP probes (webshells, SQLi, CVE payloads)
#   hydra       — SSH/SMB/FTP/RDP brute-force
#   nikto       — web app scanner
#   xxd         — hex encoding for shellcode / DNS tunneling payloads
#   hping3      — IP fragmentation evasion (one probe; nmap -f covers most)
#   dnsutils    — dig, for DNS tunneling probes (rules 9000101-112, 9000213-214)
#   smbclient   — SMB tree-connect probes
#   python3-impacket — provides impacket.* Python module; Kali additionally
#                      ships impacket-scripts which installs /usr/bin/impacket-*
#                      wrappers natively.
#   python3-paramiko — SSH attribution probes (HASSH fingerprint via
#                      SSH-2.0-paramiko_* client banner, exercised by the
#                      impacket-ad-chain group)
#   nghttp2-client — nghttp/nghttpx for HTTP/2 prior-knowledge evasion probes
#                    (triggers Suricata 2260000/2290006 + Zeek weird)
REQUIRED=(nmap curl hydra nikto xxd hping3 dnsutils smbclient python3-impacket python3-paramiko nghttp2-client)

# On Kali, add impacket-scripts — provides /usr/bin/impacket-* shims out of the
# box and skips the hand-rolled wrapper pass below. On Ubuntu the package
# doesn't exist in universe so we keep REQUIRED Ubuntu-compatible.
if [ "$IS_KALI" = 1 ]; then
  REQUIRED+=(impacket-scripts)
fi

installed=()
failed=()
for pkg in "${REQUIRED[@]}"; do
  if apt-get install -y -qq "$pkg"; then
    installed+=("$pkg")
  else
    failed+=("$pkg")
  fi
done

echo ""
echo "Installed: ${#installed[@]}/${#REQUIRED[@]}"
for p in "${installed[@]}"; do echo "  OK  $p"; done
for p in "${failed[@]}"; do echo "  FAIL $p"; done

if [ "${#failed[@]}" -gt 0 ]; then
  echo ""
  echo "ERROR: ${#failed[@]} package(s) failed to install" >&2
  exit 1
fi

# ---------- Ensure impacket-* wrappers are available ----------
# Kali's impacket-scripts package (installed above) ships /usr/bin/impacket-*
# as shell shims. Ubuntu has no such package — its python3-impacket installs
# only the Python sources, so we generate wrappers by hand.
if command -v impacket-psexec >/dev/null 2>&1; then
  echo ""
  echo "  impacket-* wrappers already provided by packages: $(ls /usr/bin/impacket-* 2>/dev/null | wc -l) found"
else
  EXAMPLE_PY=$(find /usr/share -maxdepth 4 -name psexec.py -path "*impacket*" 2>/dev/null | head -1)
  if [ -n "$EXAMPLE_PY" ]; then
    EXAMPLES_DIR=$(dirname "$EXAMPLE_PY")
    echo ""
    echo "Creating impacket-* wrappers from ${EXAMPLES_DIR}"
    for tool in psexec services reg samrdump atexec lookupsid smbclient \
                smbserver wmiexec dcomexec secretsdump GetNPUsers GetUserSPNs; do
      if [ -f "${EXAMPLES_DIR}/${tool}.py" ]; then
        cat > "/usr/local/bin/impacket-${tool}" <<WRAPPER
#!/bin/bash
exec python3 "${EXAMPLES_DIR}/${tool}.py" "\$@"
WRAPPER
        chmod +x "/usr/local/bin/impacket-${tool}"
      fi
    done
    echo "  wrappers: $(ls /usr/local/bin/impacket-* 2>/dev/null | wc -l) created"
  else
    echo "WARN: impacket examples not found under /usr/share — impacket-* commands unavailable" >&2
    exit 1
  fi
fi

# --- nuclei (ProjectDiscovery) ---
# CVE-template-based vulnerability scanner. One Go binary + template repo
# that nuclei maintains itself. Good density of labeled attack patterns;
# the templates map 1:1 to published CVEs so alert triage is straightforward.
echo "=== Installing nuclei ==="
if ! command -v nuclei >/dev/null 2>&1; then
  # Release assets are versioned (e.g. nuclei_3.4.1_linux_amd64.zip) so the
  # /releases/latest/download/<name> shortcut 404s. Resolve the real asset
  # URL via the API.
  apt-get install -y -qq unzip jq
  NUCLEI_URL=$(curl -fsSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
    | jq -r '.assets[] | select(.name | test("linux_amd64\\.zip$")) | .browser_download_url' \
    | head -1)
  if [ -z "$NUCLEI_URL" ]; then
    echo "FAIL: could not resolve nuclei linux_amd64.zip asset URL from upstream release" >&2
    exit 1
  fi
  curl -fsSL "$NUCLEI_URL" -o /tmp/nuclei.zip
  unzip -o /tmp/nuclei.zip -d /tmp/nuclei-extract
  mv /tmp/nuclei-extract/nuclei /usr/local/bin/nuclei
  chmod +x /usr/local/bin/nuclei
  rm -rf /tmp/nuclei.zip /tmp/nuclei-extract
fi
# Update templates now so the attack step doesn't pay the ~10s cost.
# -silent so the 10k+ template-update log doesn't dominate CI output.
nuclei -update-templates -silent || true
echo "  nuclei: $(nuclei -version 2>&1 | head -1)"

# --- flightsim (AlphaSOC) ---
# Purpose-built IDS validator: generates known-bad traffic patterns
# (C2 domains, DGA, DNS tunnel, mining) to external destinations.
# Requires the attacker-ENI mirror session to be captured at all
# (victim-ENI mirror alone won't see attacker->internet traffic).
echo "=== Installing flightsim ==="
if ! command -v flightsim >/dev/null 2>&1; then
  # Flightsim ships a prebuilt .deb (flightsim_<ver>_linux_64-bit.deb)
  # which is simpler than extracting the tarball. apt resolves deps for us.
  FLIGHTSIM_URL=$(curl -fsSL https://api.github.com/repos/alphasoc/flightsim/releases/latest \
    | jq -r '.assets[] | select(.name | test("linux_64-bit\\.deb$")) | .browser_download_url' \
    | head -1)
  if [ -z "$FLIGHTSIM_URL" ]; then
    echo "FAIL: could not resolve flightsim linux_64-bit.deb asset URL from upstream release" >&2
    exit 1
  fi
  curl -fsSL "$FLIGHTSIM_URL" -o /tmp/flightsim.deb
  apt-get install -y -qq /tmp/flightsim.deb
  rm -f /tmp/flightsim.deb
fi
echo "  flightsim: $(flightsim --help 2>&1 | head -1 || echo 'not installed')"

# ---------- TIER2: expanded atomic-red-team coverage ----------
# Second install pass for probes drawn from Atomic Red Team Linux atomics that
# produce network-observable signal beyond the TIER1 CI baseline. Same
# per-package install pattern as REQUIRED above — one failed package does not
# roll back the batch.
#
#   rsync          — T1105 rsync push/pull exfil (TCP/873, @RSYNCD banner)
#   socat          — T1059.004 TLS reverse shell (distinctive JA3)
#   masscan        — T1046 fast SYN scan (timing distinct from nmap)
#   gobuster/ffuf/feroxbuster — T1595.003 content discovery (404 burst + UA)
#   whois          — T1105 whois-as-tunnel probe (raw TCP/8443)
#   fping/arp-scan — T1018 host discovery sweeps
#   slowhttptest   — T1499.002 slowloris / slow-body DoS
#   dsniff         — T1557.002 arpspoof (ARP cache poison, Zeek arp.log)
#   knockd         — T1205 port-knocking client (provides /usr/bin/knock)
#   tor            — T1090.003 Tor bootstrap (SNI + Tor cert-subject pattern)
#   rclone         — T1567.002 cloud exfil (distinct JA3, *.s3.amazonaws.com)
#   apache2-utils  — T1499.002 ApacheBench flood (ab)
#   dnscat2        — T1071.004 DNS C2 (/usr/bin/dnscat client,
#                    /usr/bin/dnscat2-server server)
echo "=== Installing TIER2 atomic-red-team toolkit ==="
TIER2=(rsync socat masscan gobuster ffuf feroxbuster whois fping arp-scan \
       slowhttptest dsniff knockd tor rclone apache2-utils dnscat2)
t2_installed=()
t2_failed=()
for pkg in "${TIER2[@]}"; do
  if apt-get install -y -qq "$pkg"; then
    t2_installed+=("$pkg")
  else
    t2_failed+=("$pkg")
  fi
done
echo "  TIER2: ${#t2_installed[@]}/${#TIER2[@]} installed"
for p in "${t2_failed[@]}"; do echo "  FAIL $p"; done
if [ "${#t2_failed[@]}" -gt 0 ]; then
  echo "ERROR: ${#t2_failed[@]} TIER2 package(s) failed" >&2
  exit 1
fi

# --- cloudflared (Cloudflare Tunnel client) ---
# T1572 — spawns TLS to *.trycloudflare.com with distinctive SNI+JA3.
echo "=== Installing cloudflared ==="
if ! command -v cloudflared >/dev/null 2>&1; then
  curl -fsSL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
    -o /usr/local/bin/cloudflared
  chmod +x /usr/local/bin/cloudflared
fi
echo "  cloudflared: $(cloudflared --version 2>&1 | head -1)"

# --- devtunnel (Microsoft Dev Tunnels CLI) ---
# T1572 — SNI *.devtunnels.ms. aka.ms redirect resolves to tunnelsassets blob.
echo "=== Installing devtunnel ==="
if ! command -v devtunnel >/dev/null 2>&1; then
  curl -fsSL "https://aka.ms/TunnelsCliDownload/linux-x64" -o /usr/local/bin/devtunnel
  chmod +x /usr/local/bin/devtunnel
fi
echo "  devtunnel: $(devtunnel --version 2>&1 | head -1)"

# --- code (VSCode CLI, for `code tunnel`) ---
# T1572 — SNI *.tunnels.api.visualstudio.com + GitHub device-code OAuth.
echo "=== Installing VSCode CLI (code) ==="
if ! command -v code >/dev/null 2>&1; then
  curl -fsSL "https://code.visualstudio.com/sha/download?build=stable&os=cli-alpine-x64" \
    -o /tmp/vscode-cli.tar.gz
  tar -xzf /tmp/vscode-cli.tar.gz -C /usr/local/bin/
  chmod +x /usr/local/bin/code
  rm -f /tmp/vscode-cli.tar.gz
fi
echo "  code: $(code --version 2>&1 | head -1)"

# --- icmpdoor (ICMP C2 tunnel) ---
# T1095 — full ICMP reverse shell (vs. our existing ICMP-large/ICMP-exfil one-shots).
# Binaries live under /opt/icmpdoor; pinned to a specific commit SHA so the
# file MD5 is deterministic for detection-rule authoring.
echo "=== Installing icmpdoor ==="
if [ ! -x /opt/icmpdoor/icmpdoor ]; then
  mkdir -p /opt/icmpdoor
  BASE=https://github.com/krabelize/icmpdoor/raw/2398f7e0b8548d8ef2891089e4199ee630e84ef6/binaries/x86_64-linux
  curl -fsSL "$BASE/icmp-cnc" -o /opt/icmpdoor/icmp-cnc
  curl -fsSL "$BASE/icmpdoor" -o /opt/icmpdoor/icmpdoor
  chmod +x /opt/icmpdoor/icmp-cnc /opt/icmpdoor/icmpdoor
fi
echo "  icmpdoor: $(/opt/icmpdoor/icmpdoor --help 2>&1 | head -1)"

echo "=== Attacker toolkit setup complete ==="
