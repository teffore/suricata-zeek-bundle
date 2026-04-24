#!/bin/bash
# lab-down.sh — tear down whatever lab-up.sh stood up. Reads .lab-state and
# deletes in reverse order of creation. Every step is best-effort so one
# AWS API hiccup doesn't leak the rest.
#
# Usage:
#   ./lab-down.sh           # uses .lab-state (normal)
#   ./lab-down.sh --force   # .lab-state missing? Discover by PurpleLabRunTag tag

set -uo pipefail
export MSYS_NO_PATHCONV=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_FILE="$SCRIPT_DIR/.lab-state"
KEY_FILE="$SCRIPT_DIR/.lab-key"
LOG_DIR="$SCRIPT_DIR/.install-logs"

FORCE=0
[ "${1:-}" = "--force" ] && FORCE=1

destroy_by_tag() {
  local TAG="$1" IDS
  IDS=$(aws ec2 describe-traffic-mirror-sessions \
    --filters "Name=tag:PurpleLabRunTag,Values=$TAG" \
    --query 'TrafficMirrorSessions[].TrafficMirrorSessionId' --output text)
  for s in $IDS; do aws ec2 delete-traffic-mirror-session --traffic-mirror-session-id "$s" >/dev/null 2>&1 || true; done
  IDS=$(aws ec2 describe-traffic-mirror-filters \
    --filters "Name=tag:PurpleLabRunTag,Values=$TAG" \
    --query 'TrafficMirrorFilters[].TrafficMirrorFilterId' --output text)
  for f in $IDS; do aws ec2 delete-traffic-mirror-filter --traffic-mirror-filter-id "$f" >/dev/null 2>&1 || true; done
  IDS=$(aws ec2 describe-traffic-mirror-targets \
    --filters "Name=tag:PurpleLabRunTag,Values=$TAG" \
    --query 'TrafficMirrorTargets[].TrafficMirrorTargetId' --output text)
  for t in $IDS; do aws ec2 delete-traffic-mirror-target --traffic-mirror-target-id "$t" >/dev/null 2>&1 || true; done
  IDS=$(aws ec2 describe-instances \
    --filters "Name=tag:PurpleLabRunTag,Values=$TAG" \
              Name=instance-state-name,Values=pending,running,stopping,stopped \
    --query 'Reservations[].Instances[].InstanceId' --output text)
  if [ -n "$IDS" ]; then
    aws ec2 terminate-instances --instance-ids $IDS >/dev/null 2>&1 || true
    aws ec2 wait instance-terminated --instance-ids $IDS 2>/dev/null || true
  fi
  IDS=$(aws ec2 describe-security-groups \
    --filters "Name=tag:PurpleLabRunTag,Values=$TAG" \
    --query 'SecurityGroups[].GroupId' --output text)
  for g in $IDS; do aws ec2 delete-security-group --group-id "$g" >/dev/null 2>&1 || true; done
  aws ec2 delete-key-pair --key-name "$TAG" >/dev/null 2>&1 || true
}

if [ ! -f "$STATE_FILE" ]; then
  if [ $FORCE -eq 0 ]; then
    echo "No $STATE_FILE. Re-run with --force to discover lab resources by PurpleLabRunTag tag." >&2
    exit 1
  fi
  echo "=== --force mode: discovering labs by PurpleLabRunTag ==="
  export AWS_DEFAULT_REGION="${AWS_REGION:-us-east-1}"
  TAGS=$(aws ec2 describe-instances \
    --filters Name=tag-key,Values=PurpleLabRunTag \
              Name=instance-state-name,Values=pending,running,stopping,stopped \
    --query 'Reservations[].Instances[].Tags[?Key==`PurpleLabRunTag`].Value' \
    --output text | tr '\t' '\n' | sort -u)
  if [ -z "$TAGS" ]; then
    echo "No PurpleLabRunTag'd resources found. Nothing to do."
    exit 0
  fi
  for t in $TAGS; do
    echo "  found $t — tearing down"
    destroy_by_tag "$t"
  done
  rm -f "$KEY_FILE" "$KEY_FILE.pub"
  rm -rf "$LOG_DIR"
  echo "=== teardown complete ==="
  exit 0
fi

# shellcheck disable=SC1090
source "$STATE_FILE"
export AWS_DEFAULT_REGION="${REGION:-us-east-1}"

echo "=== tearing down $RUN_TAG ==="

# Mirror sessions first — they hold refs to filter + target.
for sid in "${SESS_A_ID:-}" "${SESS_ID:-}"; do
  [ -n "$sid" ] && { echo "  delete session $sid"; aws ec2 delete-traffic-mirror-session --traffic-mirror-session-id "$sid" >/dev/null 2>&1 || true; }
done
for fid in "${FILTER_A_ID:-}" "${FILTER_ID:-}"; do
  [ -n "$fid" ] && { echo "  delete filter $fid"; aws ec2 delete-traffic-mirror-filter --traffic-mirror-filter-id "$fid" >/dev/null 2>&1 || true; }
done
[ -n "${TGT_ID:-}" ] && { echo "  delete target $TGT_ID"; aws ec2 delete-traffic-mirror-target --traffic-mirror-target-id "$TGT_ID" >/dev/null 2>&1 || true; }

# Terminate instances (ENIs + source/dest-check clean up automatically on termination).
IDS=""
for id in "${SENSOR_ID:-}" "${VICTIM_ID:-}" "${ATTACKER_ID:-}"; do
  [ -n "$id" ] && IDS="$IDS $id"
done
if [ -n "$IDS" ]; then
  echo "  terminate$IDS"
  aws ec2 terminate-instances --instance-ids $IDS >/dev/null 2>&1 || true
  echo "  waiting for termination..."
  aws ec2 wait instance-terminated --instance-ids $IDS 2>/dev/null || true
fi

# SG depends on ENI release — wait above ensured it.
[ -n "${SG_ID:-}" ]  && { echo "  delete SG $SG_ID"; aws ec2 delete-security-group --group-id "$SG_ID" >/dev/null 2>&1 || true; }
[ -n "${RUN_TAG:-}" ] && { echo "  delete key-pair $RUN_TAG"; aws ec2 delete-key-pair --key-name "$RUN_TAG" >/dev/null 2>&1 || true; }

rm -f "$KEY_FILE" "$KEY_FILE.pub" "$STATE_FILE"
rm -rf "$LOG_DIR"

echo "=== teardown complete ==="
