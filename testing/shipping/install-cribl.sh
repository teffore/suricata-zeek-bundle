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

# ---------- Introspect Cribl's on-disk config layout ----------
# Run 12's cribl.log showed our inputs.yml was never mentioned — not
# rejected, just ignored. The write path is wrong. Find out where
# Cribl actually reads config from by locating any shipped inputs.yml
# / outputs.yml / routes.yml files.
echo "=== /opt/cribl/ top-level ==="
ls -la /opt/cribl/ 2>&1
echo
echo "=== /opt/cribl/local/ ==="
ls -la /opt/cribl/local/ 2>&1 || echo "  (no /opt/cribl/local/)"
echo
echo "=== /opt/cribl/groups/ (distributed/worker-group layout?) ==="
ls -la /opt/cribl/groups/ 2>&1 || echo "  (no /opt/cribl/groups/)"
echo
echo "=== locations of inputs.yml / outputs.yml / routes.yml under /opt/cribl/ ==="
find /opt/cribl -name 'inputs.yml' -o -name 'outputs.yml' -o -name 'routes.yml' 2>/dev/null | head -20
echo
echo "=== any default config file that references a known type (e.g. syslog) ==="
grep -rlE 'type:\s*(syslog|http|tcp|elastic)' /opt/cribl/default/ 2>/dev/null | head -10
echo
echo "=== any file on disk mentioning elastic_beats / beats / lumberjack ==="
grep -rlE 'elastic[-_]?beats|lumberjack' /opt/cribl/ 2>/dev/null | head -10
echo

# Determine the correct config dir for single-instance mode by looking
# for an existing inputs.yml or outputs.yml. Cribl ships defaults
# somewhere; the mirror-image local dir is where we should write overrides.
SHIPPED_INPUTS=$(find /opt/cribl/default -name 'inputs.yml' 2>/dev/null | head -1)
if [ -n "$SHIPPED_INPUTS" ]; then
  # Default lives at .../default/cribl/inputs.yml → override at .../local/cribl/inputs.yml
  # (replace /default/ with /local/ in the path).
  CONFIG_DIR=$(echo "$SHIPPED_INPUTS" | sed 's|/default/|/local/|' | xargs dirname)
  echo "=== discovered config dir: $CONFIG_DIR (mirrors shipped default $SHIPPED_INPUTS) ==="
else
  # Fallback to the documented /opt/cribl/local/cribl/ path
  CONFIG_DIR=/opt/cribl/local/cribl
  echo "=== no shipped inputs.yml found; defaulting to $CONFIG_DIR ==="
fi

mkdir -p "$CONFIG_DIR" "$CONFIG_DIR/pipelines"

# Also write to /opt/cribl/groups/default/local/cribl/ as a
# belt-and-suspenders measure if that directory exists. Cribl 4.x
# introduced a groups layout even for single-instance.
ALT_DIRS=()
if [ -d /opt/cribl/groups/default ]; then
  ALT_DIRS+=(/opt/cribl/groups/default/local/cribl)
  mkdir -p /opt/cribl/groups/default/local/cribl /opt/cribl/groups/default/local/cribl/pipelines
fi

# Default to elastic_beats; the port-binding gate + cribl.log grep will
# name the issue if this is wrong.
BEATS_TYPE="elastic_beats"
echo "  source type: ${BEATS_TYPE}"

# Prepare content once; write to discovered dir + any alt dirs.
OUTPUTS_YML="outputs:
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
"

INPUTS_YML="inputs:
  beats-in:
    type: ${BEATS_TYPE}
    disabled: false
    host: 0.0.0.0
    port: 5044
    tls:
      disabled: true
"

ROUTES_YML='routes:
  - id: shipping-lab-all
    name: shipping-lab-all
    filter: "true"
    pipeline: passthru
    output: elastic-out
    description: Send all events from beats-in to elastic-out (POC passthru)
    final: true
'

for DIR in "$CONFIG_DIR" "${ALT_DIRS[@]}"; do
  [ -z "$DIR" ] && continue
  echo "  writing config under: $DIR"
  printf '%s' "$OUTPUTS_YML" > "$DIR/outputs.yml"
  printf '%s' "$INPUTS_YML"  > "$DIR/inputs.yml"
  # Try both locations for routes.yml: directly under the config dir
  # AND under pipelines/. Cribl will read whichever one is correct and
  # silently ignore the other.
  printf '%s' "$ROUTES_YML" > "$DIR/routes.yml"
  printf '%s' "$ROUTES_YML" > "$DIR/pipelines/routes.yml"
done

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
