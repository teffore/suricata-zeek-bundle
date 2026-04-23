#!/bin/bash
# run.sh -- Agent Orange runner.
#
# Auto-sources purple-agent/.lab-state (the lab-up.sh state file) when
# CLI args aren't provided. Explicit --attacker-ip / --sensor-ip /
# --victim-ip / --key always win. Prefers VICTIM_PRIVATE (VPC) over
# VICTIM_IP (public) on the fallback path -- same fix that landed in
# purple-agent/benchmarks/speedtest.sh, applied here.
#
# Usage:
#   ./agent-orange/run.sh
#   ./agent-orange/run.sh --only art-masscan-syn-burst
#   ./agent-orange/run.sh --only-mitre T1046,T1090.003
#   ./agent-orange/run.sh --no-llm
#   ./agent-orange/run.sh \
#       --attacker-ip A --sensor-ip S --victim-ip V --key path/to/key
#
# Exit codes:
#   0  -- run completed, ledger written
#   1  -- missing args / lab-state not found
#   2  -- no attacks selected after filters
#   3  -- pipeline aborted (sensor unreachable, attacker setup missing)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
STATE_FILE="$REPO_ROOT/purple-agent/.lab-state"
RUN_PY="$SCRIPT_DIR/run.py"

ATTACKER_IP="${ATTACKER_IP:-}"
SENSOR_IP="${SENSOR_IP:-}"
VICTIM_IP="${VICTIM_IP:-}"
KEY="${KEY:-${KEY_FILE:-}}"

# Pass-through args destined for run.py.
ONLY=""
ONLY_MITRE=""
NO_LLM=""
NO_OPEN=""
ATTACKS_YAML=""

while [ $# -gt 0 ]; do
  case "$1" in
    --attacker-ip)   ATTACKER_IP="$2";  shift 2 ;;
    --sensor-ip)     SENSOR_IP="$2";    shift 2 ;;
    --victim-ip)     VICTIM_IP="$2";    shift 2 ;;
    --key)           KEY="$2";          shift 2 ;;
    --only)          ONLY="$2";         shift 2 ;;
    --only-mitre)    ONLY_MITRE="$2";   shift 2 ;;
    --no-llm)        NO_LLM="--no-llm"; shift 1 ;;
    --no-open)       NO_OPEN="--no-open"; shift 1 ;;
    --attacks-yaml)  ATTACKS_YAML="$2"; shift 2 ;;
    -h|--help)       sed -n '2,25p' "$0"; exit 0 ;;
    *)
      echo "run.sh: unknown arg '$1'" >&2
      echo "run with --help for usage" >&2
      exit 1 ;;
  esac
done

# ---------- auto-fill from .lab-state ----------
# See purple-agent/benchmarks/speedtest.sh for the rationale of the CLI-
# first pattern. Preserves explicit CLI args across `source`, preferring
# VICTIM_PRIVATE on fallback because purple_agent / run.py both require
# the VPC private IP -- public IPs are SG-blocked.
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
  echo "run.sh: missing ${missing[*]} (and no .lab-state fallback at $STATE_FILE)" >&2
  exit 1
fi

[ -f "$RUN_PY" ] || { echo "run.sh: run.py not found: $RUN_PY" >&2; exit 1; }

# RFC1918 sanity: flag a public VICTIM_IP immediately rather than waste
# a 15-minute run on SG-blocked traffic.
if ! [[ "$VICTIM_IP" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.) ]]; then
  echo "run.sh: WARNING VICTIM_IP=$VICTIM_IP is not RFC1918." >&2
  echo "  run.py expects the victim's VPC private IP; public IPs are" >&2
  echo "  typically SG-blocked and every listener-based attack fails." >&2
fi

echo "========================================================================"
echo "agent-orange: atomic red team run"
echo "========================================================================"
echo "attacker:  $ATTACKER_IP"
echo "sensor:    $SENSOR_IP"
echo "victim:    $VICTIM_IP"
echo "key:       $KEY"
[ -n "$ONLY" ]       && echo "only:      $ONLY"
[ -n "$ONLY_MITRE" ] && echo "only-mitre:$ONLY_MITRE"
[ -n "$NO_LLM" ]     && echo "no-llm:    true"
echo

CMD=(
  python "$RUN_PY"
  --attacker-ip "$ATTACKER_IP"
  --sensor-ip   "$SENSOR_IP"
  --victim-ip   "$VICTIM_IP"
  --key         "$KEY"
)
[ -n "$ONLY" ]         && CMD+=(--only "$ONLY")
[ -n "$ONLY_MITRE" ]   && CMD+=(--only-mitre "$ONLY_MITRE")
[ -n "$NO_LLM" ]       && CMD+=("$NO_LLM")
[ -n "$NO_OPEN" ]      && CMD+=("$NO_OPEN")
[ -n "$ATTACKS_YAML" ] && CMD+=(--attacks-yaml "$ATTACKS_YAML")

exec "${CMD[@]}"
