#!/bin/bash
# attacker_setup.sh — installs the toolkit run_attacks.sh expects, on a
# plain Ubuntu 22.04 box. Originally "kali_setup.sh" from when this was
# run on a Kali box; renamed because the attack box is now vanilla Ubuntu
# and the package list has to fit what Ubuntu's repos actually ship.
#
# Per-package install (not a single apt-get line) so one missing package
# in universe doesn't roll back the whole batch and leave the attack run
# silently calling 'command not found'.
#
# Output streams back through SSH — no /var/log redirect — so CI sees what
# installed.

set -e
export DEBIAN_FRONTEND=noninteractive

echo "=== Attacker toolkit setup ==="
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
#   python3-impacket — provides impacket-psexec/services/reg/samrdump/atexec
#                      entry points, used by run_attacks.sh lateral-movement
#                      section. (Kali's impacket-scripts is NOT available in
#                      Ubuntu universe — do not install it.)
#   python3-paramiko — SSH attribution probes (HASSH fingerprint via
#                      SSH-2.0-paramiko_* client banner, exercised by the
#                      impacket-ad-chain group)
#   nghttp2-client — nghttp/nghttpx for HTTP/2 prior-knowledge evasion probes
#                    (triggers Suricata 2260000/2290006 + Zeek weird)
REQUIRED=(nmap curl hydra nikto xxd hping3 dnsutils smbclient python3-impacket python3-paramiko nghttp2-client)

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

# ---------- Create impacket-* shell wrappers ----------
# Kali's impacket-scripts package ships /usr/bin/impacket-psexec (and friends)
# as small shell wrappers. Ubuntu's python3-impacket installs only the Python
# sources under /usr/share/... — no shims — so run_attacks.sh's calls like
# 'impacket-psexec ...' fail with 'command not found'. Generate the wrappers
# here so the attack battery's lateral-movement section actually runs.
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

echo "=== Attacker toolkit setup complete ==="
