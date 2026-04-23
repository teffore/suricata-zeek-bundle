#!/bin/bash
# speedtest.sh -- standardized 10-probe ART speed-test for the purple-agent.
#
# Runs the pinned benchmarks/probes-perf10.yaml pool end-to-end, captures
# wall-clock time, then invokes summarize.py to emit a comparable JSON
# result under benchmarks/results/benchmark-<ts>.json. Re-run with the same
# lab to compare optimizations against a baseline.
#
# Usage:
#   ./benchmarks/speedtest.sh                   # auto-source .lab-state
#   ./benchmarks/speedtest.sh \
#       --attacker-ip A --sensor-ip S \
#       --victim-ip V --key path/to/key
#
# Exit codes:
#   0  -- run completed and benchmark JSON written
#   1  -- bad/missing args or lab-state
#   2  -- purple-agent run failed (see reports/)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
POOL="$SCRIPT_DIR/probes-perf10.yaml"
RESULTS_DIR="$SCRIPT_DIR/results"
SUMMARIZE="$SCRIPT_DIR/summarize.py"
STATE_FILE="$AGENT_DIR/.lab-state"

ATTACKER_IP="${ATTACKER_IP:-}"
SENSOR_IP="${SENSOR_IP:-}"
VICTIM_IP="${VICTIM_IP:-}"
KEY="${KEY:-${KEY_FILE:-}}"

# ---------- arg parsing ----------
while [ $# -gt 0 ]; do
  case "$1" in
    --attacker-ip) ATTACKER_IP="$2"; shift 2 ;;
    --sensor-ip)   SENSOR_IP="$2";   shift 2 ;;
    --victim-ip)   VICTIM_IP="$2";   shift 2 ;;
    --key)         KEY="$2";         shift 2 ;;
    -h|--help)
      sed -n '2,18p' "$0"; exit 0 ;;
    *)
      echo "speedtest.sh: unknown arg '$1'" >&2
      echo "run with --help for usage" >&2
      exit 1 ;;
  esac
done

# ---------- auto-fill from .lab-state if needed ----------
# .lab-state exposes VICTIM_IP (public) + VICTIM_PRIVATE (VPC). purple_agent.py
# requires the PRIVATE IP because the SG only allows attacker->victim over the
# VPC private network. Explicit CLI args always win; when we fall back to the
# state file, prefer VICTIM_PRIVATE. An earlier version used `:=` defaulting,
# which silently kept the public IP set by `source` and caused every probe
# requiring a victim listener to time out (SG-blocked WAN->victim).
if [ -z "$ATTACKER_IP" ] || [ -z "$SENSOR_IP" ] || [ -z "$VICTIM_IP" ] || [ -z "$KEY" ]; then
  if [ -f "$STATE_FILE" ]; then
    _cli_attacker="$ATTACKER_IP"
    _cli_sensor="$SENSOR_IP"
    _cli_victim="$VICTIM_IP"
    _cli_key="$KEY"
    # shellcheck disable=SC1090
    source "$STATE_FILE"
    ATTACKER_IP="${_cli_attacker:-${ATTACKER_IP:-}}"
    SENSOR_IP="${_cli_sensor:-${SENSOR_IP:-}}"
    VICTIM_IP="${_cli_victim:-${VICTIM_PRIVATE:-${VICTIM_IP:-}}}"
    KEY="${_cli_key:-${KEY_FILE:-}}"
    unset _cli_attacker _cli_sensor _cli_victim _cli_key
  fi
fi

missing=()
[ -z "${ATTACKER_IP:-}" ] && missing+=("--attacker-ip")
[ -z "${SENSOR_IP:-}"   ] && missing+=("--sensor-ip")
[ -z "${VICTIM_IP:-}"   ] && missing+=("--victim-ip")
[ -z "${KEY:-}"         ] && missing+=("--key")
if [ ${#missing[@]} -gt 0 ]; then
  echo "speedtest.sh: missing ${missing[*]} (and no .lab-state fallback)" >&2
  exit 1
fi

[ -f "$POOL" ]      || { echo "speedtest.sh: pool not found: $POOL"       >&2; exit 1; }
[ -f "$SUMMARIZE" ] || { echo "speedtest.sh: summarizer not found: $SUMMARIZE" >&2; exit 1; }

# purple_agent.py expects the victim's VPC private address. If VICTIM_IP is
# outside RFC1918, the SG almost certainly blocks attacker->victim and every
# listener-dependent probe will time out. Warn loudly so a misconfigured run
# fails visibly instead of silently producing a garbage baseline.
if ! [[ "$VICTIM_IP" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.) ]]; then
  echo "speedtest.sh: WARNING VICTIM_IP=$VICTIM_IP is not RFC1918." >&2
  echo "  purple_agent.py expects the victim's VPC private IP; public IPs" >&2
  echo "  are typically SG-blocked and every listener probe will error." >&2
fi

mkdir -p "$RESULTS_DIR"

# ---------- run ----------
FOCUS="This is a speed-test benchmark. Execute all 10 probes in the order listed in the pool. Do not skip, reorder, or substitute. Call record_finding exactly once per probe. Do not add extra probes."

echo "========================================================================"
echo "speedtest: 10-probe ART benchmark"
echo "========================================================================"
echo "pool:     $POOL"
echo "agent:    $AGENT_DIR/purple_agent.py"
echo "attacker: $ATTACKER_IP"
echo "sensor:   $SENSOR_IP"
echo "victim:   $VICTIM_IP"
echo "key:      $KEY"
echo

START_EPOCH=$(date -u +%s)
START_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)

set +e
(
  cd "$AGENT_DIR"
  python purple_agent.py \
    --attacker-ip "$ATTACKER_IP" \
    --sensor-ip   "$SENSOR_IP" \
    --victim-ip   "$VICTIM_IP" \
    --key         "$KEY" \
    --probe-pool  "$POOL" \
    --max-attacks 10 \
    --budget      30 \
    --no-sweep \
    --focus       "$FOCUS"
)
RC=$?
set -e

END_EPOCH=$(date -u +%s)
END_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)
TOTAL_SEC=$(( END_EPOCH - START_EPOCH ))

echo
echo "========================================================================"
echo "speedtest: agent exit=$RC  wall_clock=${TOTAL_SEC}s"
echo "========================================================================"

if [ "$RC" -ne 0 ]; then
  echo "speedtest: purple-agent failed (exit $RC). Skipping summary." >&2
  exit 2
fi

# ---------- summarize ----------
python "$SUMMARIZE" \
  --agent-dir     "$AGENT_DIR" \
  --pool          "$POOL" \
  --results-dir   "$RESULTS_DIR" \
  --start-epoch   "$START_EPOCH" \
  --end-epoch     "$END_EPOCH" \
  --start-iso     "$START_ISO" \
  --end-iso       "$END_ISO"
