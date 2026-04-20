#!/bin/bash
# install-elastic.sh — provisions Elasticsearch 8 + Kibana on a fresh
# Ubuntu 22.04 box for the shipping validation lab (validate-shipping.yml).
#
# On success, emits two lines prefixed "ELASTIC_OUTPUT:" to stdout that
# the workflow greps and hoists into step-outputs:
#
#   ELASTIC_OUTPUT:password=<superuser password>
#   ELASTIC_OUTPUT:api_key=<base64 id:api_key for ingest auth>
#
# Cribl uses the api_key; the workflow uses the superuser password for
# verification queries.
#
# POC-shape choices:
# - xpack security ON (ES 8 default; free password auth, no TLS)
# - network.host 0.0.0.0 so Cribl can reach :9200 over the intra-SG wire
# - single-node discovery to skip cluster formation wait
# - Kibana installed but optional — the workflow doesn't depend on it
#   beyond proving the port is up (if the ops team wants to browse data
#   during the run's lifetime, Kibana is there on :5601).
#
# Output streams back through SSH — no /var/log redirect — so CI sees
# what installed.

set -e
export DEBIAN_FRONTEND=noninteractive

echo "=== Elasticsearch + Kibana install ==="

# ---------- Apt repo setup ----------
apt-get update -y -qq
apt-get install -y -qq apt-transport-https ca-certificates curl gnupg

curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch \
  | gpg --dearmor -o /usr/share/keyrings/elastic-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elastic-archive-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" \
  > /etc/apt/sources.list.d/elastic-8.x.list
apt-get update -y -qq

# ---------- Install ----------
# ES 8.19's postinst runs security auto-configuration: generates certs,
# a keystore, and an initial superuser password. The password is printed
# to the postinst's own stdout with the exact line:
#   The generated password for the elastic built-in superuser is : <PASS>
# We tee apt's output so we can parse that line reliably without racing
# on /var/log/syslog or running elasticsearch-reset-password (which
# would require ES to already be up).
APT_LOG=$(mktemp)
apt-get install -y elasticsearch kibana 2>&1 | tee "$APT_LOG"

# ---------- Minimal config ----------
# Single-node so discovery doesn't wait on peers. Bind to all ifaces so
# Cribl can reach us.
#
# Only add keys that aren't already set by the auto-config — duplicate
# keys in elasticsearch.yml crash the daemon on start. Leave all the
# xpack.security.* lines auto-config wrote (they match the keystore).
add_key_if_absent() {
  local key="$1" value="$2"
  if ! grep -qE "^[[:space:]]*${key}[[:space:]]*:" /etc/elasticsearch/elasticsearch.yml; then
    echo "${key}: ${value}" >> /etc/elasticsearch/elasticsearch.yml
  fi
}
add_key_if_absent "network.host"   "0.0.0.0"
# Do NOT add `discovery.type: single-node`. ES 8's postinst auto-config
# already writes `cluster.initial_master_nodes: ["<hostname>"]`, and
# those two settings are mutually exclusive — ES refuses to boot with
# both set. The single-entry master-nodes list already gives us effective
# single-node behavior.

# No heap override: ES 8 auto-sizes to half of /proc/meminfo RAM. On
# t3.medium that's ~2 GB, which is plenty for the POC and leaves room
# for Kibana on the same box.

# Kibana: point at local ES over HTTPS (auto-config made that mandatory),
# skip cert verification for the POC. Bind wide for optional browser
# access from the GHA runner's IP.
ELASTIC_PRIVATE=$(ip -4 -o addr show | awk '/ens5|eth0/ {print $4}' | cut -d/ -f1 | head -1)
cat >>/etc/kibana/kibana.yml <<EOF

# --- shipping-lab tuning ---
server.host: "0.0.0.0"
elasticsearch.hosts: ["https://${ELASTIC_PRIVATE}:9200"]
elasticsearch.ssl.verificationMode: none
EOF

# ---------- Start ES ----------
systemctl daemon-reload
systemctl enable elasticsearch.service
if ! systemctl start elasticsearch.service; then
  echo "=== ES failed to start — dumping diagnostic ==="
  echo "--- journalctl -xeu elasticsearch.service ---"
  journalctl -xeu elasticsearch.service --no-pager -n 120 || true
  echo "--- /etc/elasticsearch/elasticsearch.yml ---"
  cat /etc/elasticsearch/elasticsearch.yml || true
  echo "--- /var/log/elasticsearch/ ---"
  ls -la /var/log/elasticsearch/ 2>&1 || true
  for f in /var/log/elasticsearch/*.log; do
    [ -f "$f" ] && { echo "--- $f ---"; tail -60 "$f"; }
  done
  exit 1
fi

# ---------- Capture the postinst-generated password ----------
# Auto-config line looks like:
#   The generated password for the elastic built-in superuser is : XYZ
# with any amount of whitespace around the value. Extract the trailing
# token after the final `: `.
ELASTIC_PASSWORD=$(grep "generated password for the elastic" "$APT_LOG" \
                   | sed -E 's/.*:[[:space:]]+([^[:space:]]+)[[:space:]]*$/\1/' \
                   | head -1)

if [ -z "$ELASTIC_PASSWORD" ]; then
  echo "FAIL: could not parse elastic password from apt postinst output:" >&2
  grep -A2 "Security autoconfiguration" "$APT_LOG" >&2 || tail -60 "$APT_LOG" >&2
  exit 1
fi

echo "=== Waiting for Elasticsearch to accept HTTPS connections ==="
# ES 8 cold start typically 30-60s. Auto-config made HTTPS mandatory, so
# every probe below uses -k (skip cert verification — POC scope).
for i in $(seq 1 60); do
  CODE=$(curl -sSk -o /dev/null -w "%{http_code}" https://127.0.0.1:9200/ 2>/dev/null || echo "000")
  # 401 means daemon is up but our empty auth was rejected — good enough.
  if [ "$CODE" = "401" ] || [ "$CODE" = "200" ]; then break; fi
  sleep 2
done

# ---------- Wait for cluster green/yellow (not red) ----------
echo "=== Waiting for cluster health ==="
for i in $(seq 1 60); do
  STATUS=$(curl -fsSk -u "elastic:${ELASTIC_PASSWORD}" \
    "https://127.0.0.1:9200/_cluster/health?wait_for_status=yellow&timeout=5s" \
    | grep -oE '"status":"[a-z]+"' | cut -d'"' -f4 || echo "")
  if [ "$STATUS" = "yellow" ] || [ "$STATUS" = "green" ]; then
    echo "  cluster status: $STATUS"
    break
  fi
  sleep 2
done

# ---------- Create an API key for Cribl ----------
# Cribl's elasticsearch destination will auth with this key rather than
# the superuser password — same as a realistic deployment would.
API_KEY_JSON=$(curl -fsSk -u "elastic:${ELASTIC_PASSWORD}" \
  -H 'Content-Type: application/json' \
  -X POST https://127.0.0.1:9200/_security/api_key \
  -d '{
    "name": "cribl-shipping-lab",
    "role_descriptors": {
      "ingest": {
        "cluster": ["monitor"],
        "indices": [{"names": ["logs-*", ".ds-logs-*"], "privileges": ["create_index","create","write","auto_configure"]}]
      }
    }
  }')

API_KEY_ENCODED=$(echo "$API_KEY_JSON" | grep -oE '"encoded":"[^"]+"' | cut -d'"' -f4)

if [ -z "$API_KEY_ENCODED" ]; then
  echo "FAIL: could not create API key" >&2
  echo "$API_KEY_JSON" >&2
  exit 1
fi

# ---------- Start Kibana (non-blocking) ----------
# We don't wait for it to come up; the workflow's gate is ES, not Kibana.
# Kibana is here for optional browser access during the run's ~15m life.
systemctl enable kibana.service
systemctl start kibana.service

# ---------- Emit step-outputs ----------
# Workflow greps for these two lines. Keep the format stable.
echo ""
echo "ELASTIC_OUTPUT:password=${ELASTIC_PASSWORD}"
echo "ELASTIC_OUTPUT:api_key=${API_KEY_ENCODED}"
echo ""
echo "=== Elasticsearch + Kibana install complete ==="
echo "  ES health: $(curl -fsSk -u elastic:${ELASTIC_PASSWORD} https://127.0.0.1:9200/_cluster/health | head -1)"
