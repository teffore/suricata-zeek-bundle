#!/bin/bash
# install-elastic-agent.sh — installs Elastic Agent 8.x on the sensor
# after standalone.sh has put Suricata + Zeek in place.
#
# Usage: install-elastic-agent.sh <CRIBL_PRIVATE_IP>
#
# Runs Elastic Agent in standalone mode (no Fleet server needed). Config
# is rendered from elastic-agent.yml.tmpl which lives alongside this
# script; the workflow scp's both files into /tmp before invoking.

set -e
export DEBIAN_FRONTEND=noninteractive

CRIBL_PRIVATE="${1:?Usage: $0 <CRIBL_PRIVATE_IP>}"
TEMPLATE="${2:-/tmp/elastic-agent.yml.tmpl}"

# Pin to a recent GA of Elastic Agent 8.x. Bumping is intentional — doing
# so in a PR makes the version change reviewable and keeps CI reproducible.
# Latest-at-time-of-write: 8.15.3 (Oct 2024).
EA_VERSION="8.15.3"

echo "=== Elastic Agent install (standalone mode, v${EA_VERSION}) ==="

# ---------- Download ----------
cd /tmp
EA_TARBALL="elastic-agent-${EA_VERSION}-linux-x86_64.tar.gz"
EA_URL="https://artifacts.elastic.co/downloads/beats/elastic-agent/${EA_TARBALL}"

if [ ! -f "$EA_TARBALL" ]; then
  curl -fsSL "$EA_URL" -o "$EA_TARBALL"
fi

rm -rf "elastic-agent-${EA_VERSION}-linux-x86_64"
tar -xzf "$EA_TARBALL"
cd "elastic-agent-${EA_VERSION}-linux-x86_64"

# ---------- Render the standalone config ----------
# envsubst replaces ${CRIBL_PRIVATE} while leaving everything else alone.
# The template uses no other ${...} tokens so this is safe.
apt-get install -y -qq gettext-base
export CRIBL_PRIVATE
envsubst '$CRIBL_PRIVATE' < "$TEMPLATE" > /tmp/elastic-agent.yml

# Spot-check the rendered output (template now uses Beats protocol on
# port 5044, not the earlier http://...:9200 Elasticsearch-output form).
if ! grep -q "${CRIBL_PRIVATE}:5044" /tmp/elastic-agent.yml; then
  echo "FAIL: CRIBL_PRIVATE substitution didn't take effect" >&2
  cat /tmp/elastic-agent.yml >&2
  exit 1
fi

# ---------- Install as a systemd service ----------
# `elastic-agent install` copies the binary to /opt/Elastic/Agent and
# wires up the systemd unit. -f = non-interactive. --non-interactive
# suppresses the Fleet enrollment prompt.
./elastic-agent install \
  --non-interactive \
  --force \
  --unprivileged=false \
  -c /tmp/elastic-agent.yml

# ---------- Wait for it to start shipping ----------
# elastic-agent service reports its state via `status`. We gate on
# "Healthy" which means it parsed the config and its inputs are up.
for i in $(seq 1 30); do
  STATUS=$(elastic-agent status 2>/dev/null | head -5 || true)
  if echo "$STATUS" | grep -q "Healthy"; then
    echo "  elastic-agent healthy"
    break
  fi
  sleep 2
done

# Sanity: the agent needs read permission on Suricata + Zeek logs.
# Both live under /var/log/suricata and /opt/zeek/logs/current with
# restrictive perms by default; opening read so the agent user can
# follow them.
chmod -R a+rX /var/log/suricata 2>/dev/null || true
chmod -R a+rX /opt/zeek/logs/current 2>/dev/null || true

echo "=== Elastic Agent install complete ==="
elastic-agent status 2>&1 | head -20 || true
