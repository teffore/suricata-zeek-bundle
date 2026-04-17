#!/bin/bash
# verify_alerts.sh — Runs on the Suricata instance to check that the attack
# battery generated the alerts we expected (coverage gate), not just any alerts.
# Usage: ./verify_alerts.sh
# Exit code: 0 = both gates pass, 1 = either gate fails
#   Gate 1: MIN_ALERTS sanity — pipeline is alive
#   Gate 2: COVERAGE_MIN_PCT — at least N% of catalog scenarios had
#           an expected SID or Zeek notice fire
set +e

LOG="/var/log/suricata/fast.log"
EVE="/var/log/suricata/eve.json"
CATALOG="/tmp/probe_catalog.json"
COVERAGE_OUT="/tmp/probe-to-sid-coverage.json"
MIN_ALERTS=3
# Loose initial gate while the catalog stabilizes. Tighten to 80+ once the
# expected SIDs stop drifting.
COVERAGE_MIN_PCT=50

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

# === Coverage report — join fired SIDs/notices against the probe catalog ===
echo ""
echo "=== Coverage report (scenario -> expected SID / notice) ==="
COVERAGE_PASS=1   # 0 = fail, 1 = pass (default pass so missing catalog doesn't block)

if [[ ! -f "${CATALOG}" ]]; then
  echo "WARNING: ${CATALOG} not present on sensor; skipping coverage gate"
else
  # Fired Suricata SIDs (unique, as JSON array of numbers).
  FIRED_SIDS_JSON="/tmp/fired_sids.json"
  if [[ -f "${EVE}" ]]; then
    jq -r 'select(.event_type=="alert") | .alert.signature_id' "${EVE}" 2>/dev/null \
      | sort -un \
      | jq -nR '[inputs | select(length>0) | tonumber]' > "${FIRED_SIDS_JSON}"
  else
    echo '[]' > "${FIRED_SIDS_JSON}"
  fi

  # Fired Zeek notices (unique, as JSON array of strings).
  FIRED_NOTICES_JSON="/tmp/fired_notices.json"
  if [[ -f "${ZEEK_LOGS}/notice.log" ]]; then
    jq -r '.note // empty' "${ZEEK_LOGS}/notice.log" 2>/dev/null \
      | sort -u \
      | jq -nR '[inputs | select(length>0)]' > "${FIRED_NOTICES_JSON}"
  else
    echo '[]' > "${FIRED_NOTICES_JSON}"
  fi

  echo "Fired SIDs     : $(jq 'length' "${FIRED_SIDS_JSON}")"
  echo "Fired notices  : $(jq 'length' "${FIRED_NOTICES_JSON}")"

  # Join. Each scenario gets fired/missed lists for both SIDs and notices;
  # covered = no expectation, OR any expected SID fired, OR any expected notice fired.
  jq --slurpfile fsids "${FIRED_SIDS_JSON}" \
     --slurpfile fnotices "${FIRED_NOTICES_JSON}" '
    ($fsids[0]) as $FS |
    ($fnotices[0]) as $FN |
    (.scenarios | map(
      . as $s |
      {
        id: $s.id,
        category: $s.category,
        mitre: $s.mitre_technique,
        expected_sids: $s.expected_suricata_sids,
        fired_sids: [$s.expected_suricata_sids[] | select(. as $sid | $FS | index($sid))],
        missed_sids: [$s.expected_suricata_sids[] | select(. as $sid | ($FS | index($sid)) | not)],
        expected_notices: $s.expected_zeek_notices,
        fired_notices: [$s.expected_zeek_notices[] | select(. as $n | $FN | index($n))],
        missed_notices: [$s.expected_zeek_notices[] | select(. as $n | ($FN | index($n)) | not)]
      } |
      .covered = (
        (((.expected_sids | length) == 0) and ((.expected_notices | length) == 0))
        or ((.fired_sids | length) > 0)
        or ((.fired_notices | length) > 0)
      )
    )) as $scenarios |
    {
      total: ($scenarios | length),
      covered: ($scenarios | map(select(.covered)) | length),
      scenarios: $scenarios
    }' "${CATALOG}" > "${COVERAGE_OUT}"

  TOTAL_SCEN=$(jq '.total' "${COVERAGE_OUT}")
  COVERED_SCEN=$(jq '.covered' "${COVERAGE_OUT}")
  if [[ "${TOTAL_SCEN}" -gt 0 ]]; then
    PCT=$((100 * COVERED_SCEN / TOTAL_SCEN))
  else
    PCT=0
  fi

  echo ""
  echo "--- Per-scenario coverage (PASS/MISS, sids fired/expected, notices fired/expected) ---"
  jq -r '.scenarios[] | [
      (if .covered then "PASS" else "MISS" end),
      .id,
      "sids=\((.fired_sids|length))/\((.expected_sids|length))",
      "notices=\((.fired_notices|length))/\((.expected_notices|length))",
      .mitre
    ] | @tsv' "${COVERAGE_OUT}" | column -t -s $'\t'

  echo ""
  echo "--- Missed SIDs (scenarios where an expected SID did not fire) ---"
  jq -r '.scenarios[] | select(.missed_sids | length > 0) |
    "\(.id): missing \(.missed_sids | map(tostring) | join(","))"' "${COVERAGE_OUT}" | head -40

  echo ""
  echo "Coverage: ${COVERED_SCEN}/${TOTAL_SCEN} scenarios (${PCT}%, gate=${COVERAGE_MIN_PCT}%)"
  if [[ "${PCT}" -lt "${COVERAGE_MIN_PCT}" ]]; then
    COVERAGE_PASS=0
  fi
fi

# === Verdict ===
echo ""
TOTAL=$((FAST_COUNT + ALERT_COUNT))
SANITY_PASS=1
if [[ "${TOTAL}" -lt "${MIN_ALERTS}" ]]; then
  SANITY_PASS=0
fi

if [[ "${SANITY_PASS}" -eq 1 && "${COVERAGE_PASS}" -eq 1 ]]; then
  echo "PASS: sanity (fast=${FAST_COUNT}, eve=${ALERT_COUNT}) + coverage gate"
  exit 0
else
  [[ "${SANITY_PASS}" -eq 0 ]] && \
    echo "FAIL (sanity): fast=${FAST_COUNT}, eve=${ALERT_COUNT}, min=${MIN_ALERTS}"
  [[ "${COVERAGE_PASS}" -eq 0 ]] && \
    echo "FAIL (coverage): ${COVERED_SCEN}/${TOTAL_SCEN} covered (${PCT}%), gate=${COVERAGE_MIN_PCT}%"
  exit 1
fi
