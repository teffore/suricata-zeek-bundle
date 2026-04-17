#!/bin/bash
# verify_alerts.sh — Runs on the Suricata instance to check that alerts were generated.
# Usage: ./verify_alerts.sh
# Exit code: 0 = alerts detected (pass), 1 = no alerts (fail)
set +e

LOG="/var/log/suricata/fast.log"
EVE="/var/log/suricata/eve.json"
MIN_ALERTS=3

echo "=== Verifying Suricata alerts ==="

echo ""
echo "--- Suricata service status ---"
systemctl status suricata --no-pager 2>/dev/null | head -15 || true

echo ""
echo "--- Interface & VXLAN diagnostics ---"
PRIMARY_IF=$(ip -o link show | awk -F': ' '{print $2}' | grep -v lo | head -1)
echo "Primary interface: ${PRIMARY_IF}"
echo "Interface stats:"
ip -s link show "${PRIMARY_IF}" 2>/dev/null | head -8 || true
echo ""
echo "VXLAN packets received (UDP 4789):"
ss -u -a | grep 4789 || echo "  (no listeners on 4789 — expected for af-packet mode)"
echo ""
echo "Suricata VXLAN decoder config:"
grep -A2 'vxlan:' /etc/suricata/suricata.yaml 2>/dev/null || echo "  (not found in config)"

echo ""
echo "--- Capture stats from suricata.log ---"
grep -i "capture\|kernel\|packets\|decoder\|vxlan" /var/log/suricata/suricata.log 2>/dev/null | tail -20 || true

# Check fast.log exists and has content
echo ""
echo "=== Alert verification ==="
if [[ ! -f "${LOG}" ]]; then
  echo "FAIL: ${LOG} does not exist — Suricata may not be running"
  exit 1
fi

FAST_COUNT=$(wc -l < "${LOG}")
echo "fast.log entries: ${FAST_COUNT}"

# Check eve.json for alert events
if [[ -f "${EVE}" ]]; then
  ALERT_COUNT=$(grep -c '"event_type":"alert"' "${EVE}" || true)
  echo "eve.json alert count: ${ALERT_COUNT}"
else
  ALERT_COUNT=0
  echo "WARNING: eve.json not found"
fi

# Print the actual alerts for the CI log
echo ""
echo "--- fast.log alerts (last 50) ---"
tail -50 "${LOG}" || true

echo ""
echo "--- Alert signature summary (top 30) ---"
if [[ -f "${EVE}" ]]; then
  grep '"event_type":"alert"' "${EVE}" | \
    jq -r '.alert.signature' 2>/dev/null | \
    sort | uniq -c | sort -rn | head -30 || true

  # Also write the full (uncapped) breakdown to /tmp so CI can upload it.
  grep '"event_type":"alert"' "${EVE}" | \
    jq -r '.alert.signature' 2>/dev/null | \
    sort | uniq -c | sort -rn > /tmp/sig-breakdown.txt || true
fi

echo ""
echo "--- Alert categories ---"
if [[ -f "${EVE}" ]]; then
  grep '"event_type":"alert"' "${EVE}" | \
    jq -r '.alert.category // "uncategorized"' 2>/dev/null | \
    sort | uniq -c | sort -rn || true
fi

echo ""
echo "--- Traffic stats ---"
if [[ -f "${EVE}" ]]; then
  echo "Total events: $(wc -l < "${EVE}")"
  echo "Event types:"
  jq -r '.event_type' "${EVE}" 2>/dev/null | sort | uniq -c | sort -rn | head -15 || true
fi

echo ""
echo "--- Decoder stats from eve.json ---"
if [[ -f "${EVE}" ]]; then
  grep '"event_type":"stats"' "${EVE}" | tail -1 | \
    jq '.stats.decoder // empty' 2>/dev/null || true
fi

# Zeek summary (if installed)
ZEEK_LOGS=/opt/zeek/logs/current
if [[ -d "${ZEEK_LOGS}" ]]; then
  echo ""
  echo "=== Zeek summary ==="
  if /opt/zeek/bin/zeek --version >/dev/null 2>&1; then
    /opt/zeek/bin/zeek --version 2>&1 | head -1
  fi
  echo ""
  echo "--- Zeek log line counts ---"
  bash -c "wc -l ${ZEEK_LOGS}/*.log 2>/dev/null | sort -rn | head -20"
  echo ""
  echo "--- Zeek notices fired ---"
  if [[ -f "${ZEEK_LOGS}/notice.log" ]]; then
    jq -r '.note // empty' "${ZEEK_LOGS}/notice.log" 2>/dev/null | sort | uniq -c | sort -rn
  else
    echo "(no notice.log this rotation interval)"
  fi
  echo ""
  echo "--- Zeek tunnel.log (VXLAN decap evidence) ---"
  if [[ -f "${ZEEK_LOGS}/tunnel.log" ]]; then
    jq -r '.tunnel_type // empty' "${ZEEK_LOGS}/tunnel.log" 2>/dev/null | sort | uniq -c
  fi
  echo ""
  echo "--- Zeek inner-flow top conversations ---"
  if [[ -f "${ZEEK_LOGS}/conn.log" ]]; then
    jq -r '[(.["id.orig_h"] // "-"), "->", (.["id.resp_h"] // "-"), (.["id.resp_p"] // "-" | tostring), (.proto // "-"), (.service // "-")] | @tsv' \
      "${ZEEK_LOGS}/conn.log" 2>/dev/null | sort | uniq -c | sort -rn | head -10
  fi
fi

# Verdict
echo ""
TOTAL=$((FAST_COUNT + ALERT_COUNT))
if [[ "${TOTAL}" -ge "${MIN_ALERTS}" ]]; then
  echo "PASS: Suricata detected alerts (fast=${FAST_COUNT}, eve=${ALERT_COUNT})"
  exit 0
else
  echo "FAIL: Not enough alerts detected (fast=${FAST_COUNT}, eve=${ALERT_COUNT}, min=${MIN_ALERTS})"
  exit 1
fi
