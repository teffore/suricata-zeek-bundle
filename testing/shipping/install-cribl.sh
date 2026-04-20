#!/bin/bash
# install-cribl.sh — provisions Cribl Stream Free Edition on a fresh
# Ubuntu 22.04 box for the shipping validation lab.
#
# Usage: install-cribl.sh <ELASTIC_PRIVATE_IP> <ELASTIC_API_KEY>
#
# Config layout was validated against a hands-on Cribl 4.8 single-
# instance lab (see commit history notes for runs 1-13). The key
# findings that took 13 failed iterations to nail down:
#
#   1. Cribl has NO "elastic_beats" / "beats" / "lumberjack" source.
#      Use the shipped `in_elastic` source (type: elastic, port 9200),
#      which speaks the real Elasticsearch bulk API. EA's elasticsearch
#      output talks to it directly — no "Beats protocol" hop needed.
#
#   2. Override the SHIPPED input (keep id `in_elastic`) by just
#      setting disabled: false + sendToRoutes: true. Don't create a
#      new input with a custom id — the shipped one already has the
#      right defaults.
#
#   3. Routes file lives at /opt/cribl/local/cribl/pipelines/route.yml
#      (SINGULAR route.yml, not routes.yml). Writing to any other path
#      is silently ignored.
#
#   4. Outputs file is /opt/cribl/local/cribl/outputs.yml with a
#      top-level `outputs:` map — that one works as expected.

set -e
export DEBIAN_FRONTEND=noninteractive

ELASTIC_PRIVATE="${1:?Usage: $0 <ELASTIC_PRIVATE_IP> <ELASTIC_API_KEY>}"
ELASTIC_API_KEY="${2:?Usage: $0 <ELASTIC_PRIVATE_IP> <ELASTIC_API_KEY>}"

echo "=== Cribl Stream install ==="

# ---------- Prereqs ----------
apt-get update -y -qq
apt-get install -y -qq curl jq tar

# ---------- Create cribl user ----------
id -u cribl >/dev/null 2>&1 || useradd -m -d /opt/cribl -s /bin/bash cribl

# ---------- Download + extract ----------
cd /opt
CRIBL_URL="https://cdn.cribl.io/dl/latest/cribl-linux-x64.tgz"
if ! curl -fsSL "$CRIBL_URL" -o /tmp/cribl.tgz; then
  echo "primary download failed; trying versioned URL"
  VER=$(curl -fsSL https://cdn.cribl.io/dl/versions | jq -r '.versions.stream[0].version // empty')
  if [ -z "$VER" ]; then
    echo "FAIL: could not resolve Cribl Stream version" >&2
    exit 1
  fi
  curl -fsSL "https://cdn.cribl.io/dl/${VER}/cribl-${VER}-linux-x64.tgz" -o /tmp/cribl.tgz
fi
rm -rf /opt/cribl
tar -xzf /tmp/cribl.tgz -C /opt
rm -f /tmp/cribl.tgz

# ---------- Write config files ----------
# Paths and shapes were validated on a hands-on lab run (see header).
mkdir -p /opt/cribl/local/cribl /opt/cribl/local/cribl/pipelines

# Enable the shipped `in_elastic` input on :9200. Cribl's elastic input
# mimics the ES bulk API — EA's elasticsearch output POSTs directly here.
cat >/opt/cribl/local/cribl/inputs.yml <<'YAML'
inputs:
  in_elastic:
    disabled: false
    sendToRoutes: true
    host: 0.0.0.0
    port: 9200
    elasticAPI: /
    type: elastic
    tls:
      disabled: true
YAML

# Destination: the real Elasticsearch cluster provisioned by
# install-elastic.sh, authenticated with the scoped api_key it created.
cat >/opt/cribl/local/cribl/outputs.yml <<EOF
outputs:
  elastic-out:
    type: elastic
    url: https://${ELASTIC_PRIVATE}:9200/_bulk
    index: logs-suricata-zeek-shipping-lab
    authType: apiKey
    apiKey: ${ELASTIC_API_KEY}
    onBackpressure: block
    compress: false
    tls:
      disabled: false
      rejectUnauthorized: false
EOF

# Route: everything from in_elastic → passthru → elastic-out. The
# shipped default route stays so any unmatched traffic goes to devnull
# (keeps Cribl's internal telemetry from piling up).
#
# Path is pipelines/route.yml (singular). The file shape mirrors what
# Cribl writes when you PATCH /api/v1/routes/default via the UI.
cat >/opt/cribl/local/cribl/pipelines/route.yml <<'YAML'
id: default
groups: null
comments: null
routes:
  - id: shipping
    name: shipping
    final: true
    disabled: false
    pipeline: passthru
    description: "in_elastic → passthru → elastic-out"
    clones: []
    enableOutputExpression: false
    outputExpression: null
    filter: "true"
    output: elastic-out
  - id: default
    name: default
    final: true
    disabled: false
    pipeline: main
    description: ""
    clones: []
    enableOutputExpression: false
    outputExpression: null
    filter: "true"
    output: default
YAML

chown -R cribl:cribl /opt/cribl

# ---------- Start as systemd service ----------
/opt/cribl/bin/cribl boot-start enable -m systemd -u cribl || true
systemctl daemon-reload
systemctl enable cribl.service
systemctl start cribl.service

echo "=== Waiting for Cribl API on :9000 ==="
for i in $(seq 1 60); do
  if curl -fsS -o /dev/null http://127.0.0.1:9000/api/v1/health 2>/dev/null; then
    break
  fi
  sleep 2
done

echo "=== Waiting for in_elastic listener on :9200 ==="
for i in $(seq 1 30); do
  if (echo > /dev/tcp/127.0.0.1/9200) 2>/dev/null; then
    echo "  :9200 bound"
    break
  fi
  sleep 2
done

if ! (echo > /dev/tcp/127.0.0.1/9200) 2>/dev/null; then
  echo "FAIL: Cribl didn't bind :9200 — config not loaded" >&2
  echo "--- /opt/cribl/local/cribl/inputs.yml ---" >&2
  cat /opt/cribl/local/cribl/inputs.yml >&2
  echo "--- /opt/cribl/local/cribl/outputs.yml ---" >&2
  cat /opt/cribl/local/cribl/outputs.yml >&2
  echo "--- /opt/cribl/local/cribl/pipelines/route.yml ---" >&2
  cat /opt/cribl/local/cribl/pipelines/route.yml 2>&1 >&2
  echo "--- cribl.log error/warn lines ---" >&2
  grep -iE 'error|fail|invalid|reject|schema|parse' /opt/cribl/log/cribl.log 2>&1 | head -40 >&2
  exit 1
fi

# Smoke-test: POST a dummy bulk event; Cribl returns 200 if config is
# wired correctly end-to-end (route → output accepted).
echo "=== Smoke-test: POST dummy event through Cribl ==="
SMOKE=$(curl -sS -o /dev/null -w '%{http_code}' \
  -H 'Content-Type: application/x-ndjson' \
  -XPOST 'http://127.0.0.1:9200/_bulk' \
  --data-binary $'{"index":{"_index":"test"}}\n{"@timestamp":"'"$(date -Is)"'","message":"install-cribl.sh smoke","event":{"module":"test"}}\n')
echo "  bulk POST → HTTP ${SMOKE}"
if [ "$SMOKE" != "200" ]; then
  echo "WARN: smoke POST returned $SMOKE, not 200 — pipeline may not be flowing" >&2
fi

echo "=== Cribl Stream install complete ==="
echo "  UI:      http://<cribl_public_ip>:9000  (admin / admin)"
echo "  Source:  in_elastic on :9200 (ES bulk API)"
echo "  Dest:    elastic-out → https://${ELASTIC_PRIVATE}:9200"
