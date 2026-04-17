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
REQUIRED=(nmap curl hydra nikto xxd hping3 dnsutils smbclient python3-impacket)

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

echo "=== Attacker toolkit setup complete ==="
