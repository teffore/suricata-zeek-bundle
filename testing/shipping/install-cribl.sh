#!/bin/bash
# install-cribl.sh — provisions Cribl Stream Free Edition on a fresh
# Ubuntu 22.04 box for the shipping validation lab.
#
# Usage: install-cribl.sh <ELASTIC_PRIVATE_IP> <ELASTIC_API_KEY>
#   ELASTIC_API_KEY is the base64 id:api_key string that install-elastic.sh
#   emits (Cribl's elasticsearch destination accepts this as the "api_key"
#   auth type).
#
# On success, starts the Cribl Stream daemon on :9000 (UI/admin) and
# configures:
#   - Source:       Elastic Bulk API on :9200 (what Elastic Agent will ship to)
#   - Destination:  Elasticsearch at http://ELASTIC_PRIVATE:9200 using the api_key
#   - Route:        catch-all → passthru pipeline → elastic destination
#
# Default admin creds are admin/admin. Workflow changes the password
# only if it needs to hand the creds to a browsing operator; for the
# ephemeral POC they stay at admin/admin.

set -e
export DEBIAN_FRONTEND=noninteractive

ELASTIC_PRIVATE="${1:?Usage: $0 <ELASTIC_PRIVATE_IP> <ELASTIC_API_KEY>}"
ELASTIC_API_KEY="${2:?Usage: $0 <ELASTIC_PRIVATE_IP> <ELASTIC_API_KEY>}"

echo "=== Cribl Stream install ==="

# ---------- Prereqs ----------
# Cribl ships its own bundled runtime (Node), so no Java or OpenJDK
# required despite older docs. Just curl + tar.
apt-get update -y -qq
apt-get install -y -qq curl jq tar

# ---------- Create cribl user + directories ----------
# Running as root is supported but the Cribl docs recommend a
# dedicated service user for single-instance mode.
id -u cribl >/dev/null 2>&1 || useradd -m -d /opt/cribl -s /bin/bash cribl

# ---------- Download + extract ----------
# Cribl's documented download URL for Stream Linux x64. No auth / account
# required for the Free Edition. Earlier URL had a duplicate "latest" and
# returned 404; this is the form Cribl's official docs publish.
cd /opt
CRIBL_URL="https://cdn.cribl.io/dl/latest/cribl-linux-x64.tgz"
if ! curl -fsSL "$CRIBL_URL" -o /tmp/cribl.tgz; then
  # Fallback: resolve the current version via Cribl's JSON metadata and
  # build the versioned tarball URL. Catches edge cases where /latest/
  # is temporarily out of sync with the CDN.
  echo "primary download failed; trying versioned URL"
  VER=$(curl -fsSL https://cdn.cribl.io/dl/versions | jq -r '.versions.stream[0].version // empty')
  if [ -z "$VER" ]; then
    echo "FAIL: could not resolve Cribl Stream version from $CRIBL_URL or /dl/versions" >&2
    exit 1
  fi
  curl -fsSL "https://cdn.cribl.io/dl/${VER}/cribl-${VER}-linux-x64.tgz" -o /tmp/cribl.tgz
fi
rm -rf /opt/cribl
tar -xzf /tmp/cribl.tgz -C /opt
rm -f /tmp/cribl.tgz
chown -R cribl:cribl /opt/cribl

# ---------- Start as a systemd service ----------
# Cribl ships a helper that generates /etc/systemd/system/cribl.service
# pointing at the right user + install path.
/opt/cribl/bin/cribl boot-start enable -m systemd -u cribl
systemctl daemon-reload
systemctl enable cribl.service
systemctl start cribl.service

echo "=== Waiting for Cribl API to accept connections ==="
# First boot takes 30-60s while Cribl generates its default config.
for i in $(seq 1 60); do
  if curl -fsS -o /dev/null http://127.0.0.1:9000/api/v1/health 2>/dev/null; then
    break
  fi
  sleep 2
done

# ---------- Log in and grab an auth token ----------
# Default creds: admin/admin. The login endpoint returns a bearer token
# valid for subsequent /api/v1/ calls.
TOKEN=$(curl -fsS -X POST http://127.0.0.1:9000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin"}' \
  | jq -r '.token')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
  echo "FAIL: could not obtain Cribl API token" >&2
  exit 1
fi
echo "  Cribl API token acquired"

auth() { echo "Authorization: Bearer $TOKEN"; }

# ---------- Configure destination: Elasticsearch ----------
# Cribl's elastic destination talks the bulk API. We use the api_key
# auth mode so the superuser password never leaves the elastic box.
curl -fsS -X POST http://127.0.0.1:9000/m/default/lib/outputs \
  -H "$(auth)" -H 'Content-Type: application/json' \
  -d @- <<EOF
{
  "id": "elastic-out",
  "type": "elastic",
  "url": "https://${ELASTIC_PRIVATE}:9200/_bulk",
  "index": "logs-suricata-zeek-shipping-lab",
  "authType": "apiKey",
  "apiKey": "${ELASTIC_API_KEY}",
  "onBackpressure": "block",
  "compress": false,
  "tls": {
    "disabled": false,
    "rejectUnauthorized": false
  }
}
EOF

echo "  destination created: elastic-out"

# ---------- Configure source: Elastic Bulk API listener on :9200 ----------
# Elastic Agent's elasticsearch output will POST /_bulk to this port,
# thinking it's talking to a real ES cluster. Cribl accepts the bulk
# payload, splits it into events, and routes them.
curl -fsS -X POST http://127.0.0.1:9000/m/default/lib/inputs \
  -H "$(auth)" -H 'Content-Type: application/json' \
  -d @- <<'EOF'
{
  "id": "elastic-in",
  "type": "elastic",
  "disabled": false,
  "host": "0.0.0.0",
  "port": 9200,
  "authTokens": [],
  "tls": { "disabled": true }
}
EOF

echo "  source created: elastic-in (listening on :9200)"

# ---------- Configure route: send everything from elastic-in to elastic-out ----------
# The default "passthru" pipeline is a no-op; good enough for the POC.
# Future work: add a Cribl pipeline that enriches ECS fields or drops
# the high-volume zeek conn.log events before shipping.
curl -fsS -X PUT http://127.0.0.1:9000/m/default/system/routes \
  -H "$(auth)" -H 'Content-Type: application/json' \
  -d @- <<'EOF'
{
  "id": "default",
  "routes": [
    {
      "id": "shipping-lab-all",
      "name": "shipping-lab-all",
      "filter": "true",
      "pipeline": "passthru",
      "output": "elastic-out",
      "description": "Send all events from elastic-in to elastic-out (POC passthru)",
      "final": true
    }
  ]
}
EOF

echo "  route created: shipping-lab-all (filter=true → passthru → elastic-out)"

# ---------- Commit + deploy the config ----------
# Cribl stages config changes in the "default" workspace; this call
# applies them so the listener actually starts.
curl -fsS -X POST http://127.0.0.1:9000/m/default/version/commit \
  -H "$(auth)" -H 'Content-Type: application/json' \
  -d '{"message":"shipping-lab initial config"}' >/dev/null

curl -fsS -X POST http://127.0.0.1:9000/m/default/version/deploy \
  -H "$(auth)" -H 'Content-Type: application/json' \
  -d '{}' >/dev/null

echo "  config committed and deployed"

# ---------- Wait for source listener to bind ----------
for i in $(seq 1 30); do
  if (echo > /dev/tcp/127.0.0.1/9200) 2>/dev/null; then
    break
  fi
  sleep 2
done

echo "=== Cribl Stream install complete ==="
echo "  UI:      http://<cribl_public_ip>:9000  (admin / admin)"
echo "  Source:  elastic-in on :9200"
echo "  Dest:    elastic-out → http://${ELASTIC_PRIVATE}:9200"
