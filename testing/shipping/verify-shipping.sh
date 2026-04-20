#!/bin/bash
# verify-shipping.sh — gates the shipping workflow by querying the
# Elasticsearch box for real Suricata + Zeek events.
#
# Usage: verify-shipping.sh <ELASTIC_PUBLIC_IP> <ELASTIC_PASSWORD>
#
# Runs from the GitHub Actions runner after the attack battery
# completes. Returns exit 0 if BOTH gates pass:
#   - ≥ SURICATA_MIN events with event.module:suricata in the last 5 min
#   - ≥ ZEEK_MIN     events with event.module:zeek     in the last 5 min
#
# Gates are deliberately low (10 each) — the point is to prove the
# pipeline transports data end-to-end, not to enforce volume.
# The existing validate-detections.yml coverage gate stays responsible
# for detection correctness.

set +e  # don't exit on first curl failure — we want to report both gates

ELASTIC_IP="${1:?Usage: $0 <ELASTIC_PUBLIC_IP> <ELASTIC_PASSWORD>}"
ELASTIC_PASS="${2:?Usage: $0 <ELASTIC_PUBLIC_IP> <ELASTIC_PASSWORD>}"
SURICATA_MIN="${SURICATA_MIN:-10}"
ZEEK_MIN="${ZEEK_MIN:-10}"
WINDOW="${WINDOW:-now-5m}"

ES="http://${ELASTIC_IP}:9200"
AUTH="-u elastic:${ELASTIC_PASS}"

echo "=== Verifying events landed in Elasticsearch ==="
echo "  target:       ${ES}"
echo "  time window:  last 5 min (from ${WINDOW})"
echo "  gates:        suricata ≥ ${SURICATA_MIN}, zeek ≥ ${ZEEK_MIN}"

# Give events a moment to traverse the pipeline. Elastic Agent's
# filestream input polls on ~1s intervals; Cribl flushes the bulk
# batch every ~250ms under load. 30s is generous for the POC.
sleep 30

# ---------- Count Suricata events ----------
# The index pattern matches what Cribl writes (logs-suricata-zeek-shipping-lab).
# Using `logs-*` as the datastream-style pattern + `.ds-logs-*` for
# hidden datastream backing indices covers both Cribl's direct-write
# and Elastic's auto-datastream behavior.
SURICATA_COUNT=$(curl -fsS $AUTH \
  -H 'Content-Type: application/json' \
  -X POST "${ES}/logs-*,.ds-logs-*/_count" \
  -d '{
    "query": {
      "bool": {
        "filter": [
          { "term": { "event.module": "suricata" } },
          { "range": { "@timestamp": { "gte": "'"$WINDOW"'" } } }
        ]
      }
    }
  }' | grep -oE '"count":[0-9]+' | cut -d: -f2)
SURICATA_COUNT="${SURICATA_COUNT:-0}"

# ---------- Count Zeek events ----------
ZEEK_COUNT=$(curl -fsS $AUTH \
  -H 'Content-Type: application/json' \
  -X POST "${ES}/logs-*,.ds-logs-*/_count" \
  -d '{
    "query": {
      "bool": {
        "filter": [
          { "term": { "event.module": "zeek" } },
          { "range": { "@timestamp": { "gte": "'"$WINDOW"'" } } }
        ]
      }
    }
  }' | grep -oE '"count":[0-9]+' | cut -d: -f2)
ZEEK_COUNT="${ZEEK_COUNT:-0}"

echo ""
echo "Suricata events shipped: ${SURICATA_COUNT} (gate=${SURICATA_MIN})"
echo "Zeek events shipped:     ${ZEEK_COUNT} (gate=${ZEEK_MIN})"

# ---------- Dump a sample so failures are diagnosable ----------
# Keep the output file path stable so the workflow can scp it as an artifact.
mkdir -p /tmp/shipping-artifacts
curl -fsS $AUTH \
  -H 'Content-Type: application/json' \
  -X POST "${ES}/logs-*,.ds-logs-*/_search?size=5" \
  -d '{
    "sort": [{ "@timestamp": "desc" }],
    "query": { "bool": { "filter": [ { "term": { "event.module": "suricata" } } ] } }
  }' > /tmp/shipping-artifacts/suricata-sample.json 2>/dev/null

curl -fsS $AUTH \
  -H 'Content-Type: application/json' \
  -X POST "${ES}/logs-*,.ds-logs-*/_search?size=5" \
  -d '{
    "sort": [{ "@timestamp": "desc" }],
    "query": { "bool": { "filter": [ { "term": { "event.module": "zeek" } } ] } }
  }' > /tmp/shipping-artifacts/zeek-sample.json 2>/dev/null

# Cluster health snapshot — useful when counts look wrong and we need
# to check if ES itself is wedged.
curl -fsS $AUTH "${ES}/_cluster/health" > /tmp/shipping-artifacts/cluster-health.json 2>/dev/null
curl -fsS $AUTH "${ES}/_cat/indices?format=json" > /tmp/shipping-artifacts/indices.json 2>/dev/null

# ---------- Gate ----------
fail=0
if [ "$SURICATA_COUNT" -lt "$SURICATA_MIN" ]; then
  echo "FAIL: Suricata shipping gate — got ${SURICATA_COUNT}, need ≥ ${SURICATA_MIN}"
  fail=1
fi
if [ "$ZEEK_COUNT" -lt "$ZEEK_MIN" ]; then
  echo "FAIL: Zeek shipping gate — got ${ZEEK_COUNT}, need ≥ ${ZEEK_MIN}"
  fail=1
fi

[ "$fail" = 0 ] && echo "PASS: both shipping gates cleared" || exit 1
