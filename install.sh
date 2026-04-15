#!/bin/bash
# install.sh — bundled installer for Suricata + Zeek + custom rules.
# Target: fresh or existing Ubuntu 22.04 machine with outbound internet.
#
# Usage:
#   sudo ./install.sh [--force] [--preserve-config] [--iface <name>]
#
# Flags:
#   --force             Skip the "prior install" prompt; back up and proceed.
#   --preserve-config   Keep existing /etc/suricata/suricata.yaml and
#                       /opt/zeek/etc/* — only refresh rules and intel feeds.
#   --iface <name>      Capture interface. Default: first non-loopback NIC.

set -e

FORCE=0
PRESERVE=0
IFACE=""

while [ $# -gt 0 ]; do
  case "$1" in
    --force) FORCE=1; shift ;;
    --preserve-config) PRESERVE=1; shift ;;
    --iface) IFACE="$2"; shift 2 ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: must run as root (sudo ./install.sh)" >&2
  exit 1
fi

BUNDLE_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
export BUNDLE_DIR
TS="$(date +%Y%m%d-%H%M%S)"

echo "=== Bundle install starting ($(date -u +%FT%TZ)) ==="
echo "Bundle dir: ${BUNDLE_DIR}"

# ---------- Detect prior installs ----------
SURICATA_PRESENT=0
ZEEK_PRESENT=0
if command -v suricata >/dev/null 2>&1; then
  SURICATA_PRESENT=1
  echo "Detected existing Suricata: $(suricata --build-info 2>/dev/null | head -1 || true)"
fi
if [ -x /opt/zeek/bin/zeek ] || command -v zeek >/dev/null 2>&1; then
  ZEEK_PRESENT=1
  echo "Detected existing Zeek: $(/opt/zeek/bin/zeek --version 2>/dev/null || zeek --version 2>/dev/null || true)"
fi

if { [ "$SURICATA_PRESENT" = 1 ] || [ "$ZEEK_PRESENT" = 1 ]; } && [ "$FORCE" = 0 ]; then
  echo ""
  echo "A prior install was detected. Re-run with --force to proceed."
  echo "Existing configs will be backed up to /etc/suricata.bak.<ts>/ and /opt/zeek.bak.<ts>/."
  echo "Use --preserve-config to keep existing YAML/config and only refresh rules."
  exit 3
fi

# ---------- Back up existing config ----------
if [ "$SURICATA_PRESENT" = 1 ] && [ -d /etc/suricata ]; then
  BKP="/etc/suricata.bak.${TS}"
  echo "Backing up /etc/suricata -> ${BKP}"
  cp -a /etc/suricata "${BKP}"
  systemctl stop suricata || true
fi
if [ "$ZEEK_PRESENT" = 1 ] && [ -d /opt/zeek/etc ]; then
  BKP="/opt/zeek-etc.bak.${TS}"
  echo "Backing up /opt/zeek/etc -> ${BKP}"
  cp -a /opt/zeek/etc "${BKP}"
  /opt/zeek/bin/zeekctl stop 2>/dev/null || true
fi

# ---------- Interface override ----------
# The setup scripts auto-detect the first non-loopback NIC. If the caller
# passed --iface, bring it to the top of `ip link show` output by renaming
# through a small wrapper: simplest approach is to export PRIMARY_IF and
# let the scripts respect it if set.
if [ -n "$IFACE" ]; then
  if ! ip link show "$IFACE" >/dev/null 2>&1; then
    echo "ERROR: interface '$IFACE' not found" >&2
    exit 4
  fi
  echo "Using capture interface: ${IFACE}"
  # Patch both setup scripts' detection line at runtime via env override.
  export PRIMARY_IF_OVERRIDE="$IFACE"
fi

# ---------- Preserve-config short path ----------
if [ "$PRESERVE" = 1 ]; then
  echo "--preserve-config: refreshing rules + intel only"
  install -d -m 0755 /var/lib/suricata/rules
  cp "${BUNDLE_DIR}/custom.rules" /var/lib/suricata/rules/custom.rules
  cat /var/lib/suricata/rules/custom.rules >> /var/lib/suricata/rules/suricata.rules
  suricata-update || true
  [ -x /opt/zeek/intel/build-intel.sh ] && /opt/zeek/intel/build-intel.sh || true
  systemctl restart suricata || true
  /opt/zeek/bin/zeekctl deploy 2>/dev/null || true
  echo "=== preserve-config install complete ==="
  exit 0
fi

# ---------- Run the setup scripts ----------
# Inject interface override if provided — both scripts use the same
# PRIMARY_IF detection pattern, so prepend an export.
run_setup() {
  local script="$1"
  if [ -n "${PRIMARY_IF_OVERRIDE:-}" ]; then
    # Wrap: override the detection line by exporting PRIMARY_IF first,
    # then exec the script which will reassign PRIMARY_IF via ip -o link.
    # Simplest correctness: sed the detection to use the override.
    local tmp
    tmp="$(mktemp)"
    sed "s|PRIMARY_IF=\$(ip -o link show.*|PRIMARY_IF=\"${PRIMARY_IF_OVERRIDE}\"|" "$script" > "$tmp"
    chmod +x "$tmp"
    bash "$tmp"
    rm -f "$tmp"
  else
    bash "$script"
  fi
}

echo ""
echo "--- Running suricata_setup.sh ---"
run_setup "${BUNDLE_DIR}/suricata_setup.sh"

echo ""
echo "--- Running zeek_setup.sh ---"
run_setup "${BUNDLE_DIR}/zeek_setup.sh"

echo ""
echo "=== Install complete ==="
echo "Log: /var/log/suricata-setup.log"
echo "Run ./verify.sh to validate."
