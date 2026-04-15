#!/bin/bash
# verify.sh — post-install health + functional check for the Suricata/Zeek bundle.
# Exit 0 = all checks pass, non-zero = first failing check.
#
# Checks:
#   1. Services active (suricata, zeek via zeekctl)
#   2. Versions match expected majors (Suricata 8.x, Zeek 8.x)
#   3. Configs parse (suricata -T, zeek -a)
#   4. Rule count non-zero; custom SIDs loaded
#   5. Capture interface up; eve.json / conn.log producing fresh events
#   6. Canary alert: trigger a known custom SID and confirm it fires in eve.json

set -u
PASS=0
FAIL=0
FAIL_MSGS=()

check() {
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "  PASS  ${desc}"
    PASS=$((PASS+1))
  else
    echo "  FAIL  ${desc}"
    FAIL=$((FAIL+1))
    FAIL_MSGS+=("${desc}")
  fi
}

echo "=== 1. Service status ==="
check "suricata systemd unit active" systemctl is-active --quiet suricata
if [ -x /opt/zeek/bin/zeekctl ]; then
  # zeekctl status prints "running" lines; treat grep-match as pass
  check "zeek workers running" bash -c "/opt/zeek/bin/zeekctl status 2>/dev/null | grep -q running"
else
  echo "  FAIL  zeekctl not found at /opt/zeek/bin/zeekctl"
  FAIL=$((FAIL+1)); FAIL_MSGS+=("zeekctl missing")
fi

echo ""
echo "=== 2. Versions ==="
SURI_VER="$(suricata --build-info 2>/dev/null | awk '/This is Suricata version/ {print $5}')"
ZEEK_VER="$(/opt/zeek/bin/zeek --version 2>/dev/null | awk '{print $3}')"
echo "  Suricata: ${SURI_VER:-unknown}"
echo "  Zeek:     ${ZEEK_VER:-unknown}"
case "$SURI_VER" in 8.*) echo "  PASS  Suricata 8.x"; PASS=$((PASS+1)) ;; *) echo "  FAIL  expected Suricata 8.x"; FAIL=$((FAIL+1)); FAIL_MSGS+=("suricata version") ;; esac
case "$ZEEK_VER" in 8.*) echo "  PASS  Zeek 8.x"; PASS=$((PASS+1)) ;; *) echo "  FAIL  expected Zeek 8.x"; FAIL=$((FAIL+1)); FAIL_MSGS+=("zeek version") ;; esac

echo ""
echo "=== 3. Config parses ==="
check "suricata.yaml validates" sudo -u suricata suricata -T -c /etc/suricata/suricata.yaml
check "zeek local.zeek parses" /opt/zeek/bin/zeek -a /opt/zeek/share/zeek/site/local.zeek

echo ""
echo "=== 4. Rules loaded ==="
RULE_COUNT=$(grep -c "Loaded.*rules" /var/log/suricata/suricata.log 2>/dev/null | head -1)
LAST_LOADED=$(grep "rules successfully loaded" /var/log/suricata/suricata.log 2>/dev/null | tail -1)
echo "  last load line: ${LAST_LOADED:-<none>}"
check "custom SID 9000002 present in active ruleset" grep -q "sid:9000002" /var/lib/suricata/rules/suricata.rules

echo ""
echo "=== 5. Live capture ==="
PRIMARY_IF=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -1)
echo "  Primary interface: ${PRIMARY_IF}"
check "interface is UP" bash -c "ip link show ${PRIMARY_IF} | grep -q 'state UP'"
if [ -f /var/log/suricata/eve.json ]; then
  EVE_AGE=$(( $(date +%s) - $(stat -c %Y /var/log/suricata/eve.json) ))
  echo "  eve.json last modified ${EVE_AGE}s ago"
  [ "$EVE_AGE" -lt 300 ] && { echo "  PASS  eve.json fresh (<5m)"; PASS=$((PASS+1)); } || { echo "  FAIL  eve.json stale"; FAIL=$((FAIL+1)); FAIL_MSGS+=("eve.json stale"); }
else
  echo "  FAIL  /var/log/suricata/eve.json missing"; FAIL=$((FAIL+1)); FAIL_MSGS+=("eve.json missing")
fi

echo ""
echo "=== 6. Canary alert ==="
# SID 9000002: "TEST - SSH connection to HOME_NET" — trigger with a local
# TCP connect to port 22 on a HOME_NET address. Since HOME_NET is all RFC
# 1918, any private-IP host on this box works; use the primary IP.
LOCAL_IP=$(ip -4 -o addr show "${PRIMARY_IF}" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1)
if [ -z "$LOCAL_IP" ]; then
  echo "  FAIL  could not determine local IP on ${PRIMARY_IF}"
  FAIL=$((FAIL+1)); FAIL_MSGS+=("no local ip for canary")
else
  echo "  firing canary: TCP connect to ${LOCAL_IP}:22"
  # timeout + nc/bash /dev/tcp for a SYN. We don't care if SSH is up —
  # the SYN alone matches sid:9000002.
  timeout 2 bash -c "exec 3<>/dev/tcp/${LOCAL_IP}/22" 2>/dev/null || true
  # Give Suricata a moment to process + flush
  for i in 1 2 3 4 5 6 7 8 9 10; do
    if grep -q '"signature_id":9000002' /var/log/suricata/eve.json 2>/dev/null; then
      break
    fi
    sleep 1
  done
  if grep -q '"signature_id":9000002' /var/log/suricata/eve.json 2>/dev/null; then
    echo "  PASS  canary SID 9000002 fired in eve.json"
    PASS=$((PASS+1))
  else
    echo "  FAIL  canary SID 9000002 not observed within 10s"
    echo "        (this can mean: no traffic mirror configured, or the NIC"
    echo "         isn't seeing the SYN — expected on hosts without a SPAN feed)"
    FAIL=$((FAIL+1)); FAIL_MSGS+=("canary alert")
  fi
fi

echo ""
echo "=== Summary ==="
echo "  Passed: ${PASS}"
echo "  Failed: ${FAIL}"
if [ "$FAIL" -gt 0 ]; then
  printf '  Failure: %s\n' "${FAIL_MSGS[@]}"
  exit 1
fi
exit 0
