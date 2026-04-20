#!/bin/bash
# install-cribl.sh — provisions Cribl Stream Free Edition on a fresh
# Ubuntu 22.04 box for the shipping validation lab.
#
# Usage: install-cribl.sh <ELASTIC_PRIVATE_IP> <ELASTIC_API_KEY>
#
# Configures Cribl via config files on disk rather than REST API calls.
# Earlier attempts guessed at Cribl's single-instance vs distributed
# API path conventions and kept hitting 404s; writing the YAML files
# directly removes that whole class of failure. Cribl reads the config
# at startup, the same way it does when you edit via the UI.

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

# ---------- Write config files directly ----------
# Cribl reads YAML config from /opt/cribl/local/cribl/ at startup.
# Writing these directly sidesteps the REST API path uncertainty that
# burned runs 7-9 (UI HTML was served for wrong paths; single-instance
# vs distributed API shape differences). The file layout here matches
# what Cribl's own UI writes when you configure via the web UI.

mkdir -p /opt/cribl/local/cribl /opt/cribl/local/cribl/pipelines

# ---------- Introspect supported input types ----------
# Cribl ships schemas that enumerate valid type values. The exact path
# varies by version (run 11 showed /opt/cribl/default/cribl/input/
# doesn't exist), so search instead of guess.
echo "=== Searching Cribl install for input schemas ==="
find /opt/cribl/default -maxdepth 5 -type d 2>/dev/null | grep -iE '(input|source)' | head -10
echo
echo "=== Looking for any file mentioning 'beats' or 'lumberjack' ==="
find /opt/cribl -maxdepth 6 -type f \( -name '*.json' -o -name '*.yml' -o -name '*.yaml' \) 2>/dev/null \
  | xargs grep -lEi 'elastic[-_]?beats|lumberjack' 2>/dev/null | head -10

# Try several candidate type names in descending likelihood. Cribl
# docs reference "elastic_beats" most commonly; fall back to hyphenated
# and bare forms. If none match a schema file on disk, default to
# "elastic_beats" and let the port-binding gate fail with a diagnostic.
BEATS_TYPE=""
for candidate in elastic_beats elastic-beats beats lumberjack; do
  if find /opt/cribl/default -maxdepth 6 \( -name "${candidate}.json" -o -name "${candidate}" -type d \) 2>/dev/null | grep -q .; then
    BEATS_TYPE="$candidate"
    break
  fi
done

# Fallback: if nothing matched, still try elastic_beats — this is what
# Cribl's community docs most often cite.
if [ -z "$BEATS_TYPE" ]; then
  echo "  no matching schema file found on disk; defaulting to elastic_beats"
  BEATS_TYPE="elastic_beats"
else
  echo "  auto-selected source type: ${BEATS_TYPE}"
fi

# ---------- Destination: Elasticsearch via api_key ----------
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

# ---------- Source: Beats listener on :5044 ----------
# Type value auto-resolved from /opt/cribl/default/cribl/input/ above.
# EA's `logstash` output speaks lumberjack to this port.
cat >/opt/cribl/local/cribl/inputs.yml <<EOF
inputs:
  beats-in:
    type: ${BEATS_TYPE}
    disabled: false
    host: 0.0.0.0
    port: 5044
    tls:
      disabled: true
EOF

# ---------- Route: beats-in → passthru → elastic-out ----------
# Routes file lives under local/cribl/pipelines/, NOT local/cribl/
# directly. Writing to the wrong path is silent — Cribl ignores unknown
# files — so the route simply wouldn't register.
cat >/opt/cribl/local/cribl/pipelines/routes.yml <<'EOF'
routes:
  - id: shipping-lab-all
    name: shipping-lab-all
    filter: "true"
    pipeline: passthru
    output: elastic-out
    description: Send all events from beats-in to elastic-out (POC passthru)
    final: true
EOF

chown -R cribl:cribl /opt/cribl

# ---------- Start as systemd service ----------
# boot-start enable wires up /etc/systemd/system/cribl.service. It emits
# a "needs root privileges" line in some versions even when invoked as
# root; the exit status is still 0 so the rest of the script proceeds.
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

echo "=== Waiting for beats-in listener on :5044 ==="
# If our inputs.yml was read correctly, port 5044 binds within a few
# seconds of Cribl coming up on :9000.
for i in $(seq 1 30); do
  if (echo > /dev/tcp/127.0.0.1/5044) 2>/dev/null; then
    echo "  :5044 bound — inputs.yml was read"
    break
  fi
  sleep 2
done

if ! (echo > /dev/tcp/127.0.0.1/5044) 2>/dev/null; then
  echo "FAIL: Cribl didn't bind :5044 — config not loaded" >&2
  echo "--- /opt/cribl/local/cribl/inputs.yml ---" >&2
  cat /opt/cribl/local/cribl/inputs.yml >&2
  echo "--- /opt/cribl/local/cribl/pipelines/routes.yml ---" >&2
  cat /opt/cribl/local/cribl/pipelines/routes.yml 2>&1 >&2
  echo "--- cribl.log: lines matching error/fail/invalid/reject/schema ---" >&2
  grep -iE 'error|fail|invalid|reject|schema|parse|bad input' /opt/cribl/log/cribl.log 2>&1 | head -80 >&2
  echo "--- cribl.log tail (last 80 lines) ---" >&2
  tail -80 /opt/cribl/log/cribl.log 2>&1 >&2
  exit 1
fi

echo "=== Cribl Stream install complete ==="
echo "  UI:      http://<cribl_public_ip>:9000  (admin / admin)"
echo "  Source:  beats-in on :5044 (elastic_beats)"
echo "  Dest:    elastic-out → https://${ELASTIC_PRIVATE}:9200"
