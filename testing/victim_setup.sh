#!/bin/bash
# victim_setup.sh — installs victim services for the detection CI lab.
# Runs ON the victim instance (not the runner).
#
# Layers:
#   - nginx :80                  — baseline web target for generic probes
#   - sshd  :22                  — target for SSH brute-force probes
#   - Vulhub Log4Shell :8983     — Solr + Log4j 2.14 (CVE-2021-44228)
#   - Vulhub Spring4Shell :8080  — Tomcat + Spring (CVE-2022-22965)
#
# Vulhub gives the existing CVE-pattern probes a real vulnerable listener
# to hit, which unlocks Zeek's files.log / http.log / detect-webapps signal
# that a bare nginx 404 page can't produce.

set -e

export DEBIAN_FRONTEND=noninteractive

echo "=== [victim_setup] base packages ==="
sudo apt-get update -qq
sudo apt-get install -y -qq nginx openssh-server ca-certificates curl git iproute2

echo "=== [victim_setup] nginx on :80 (always 200 ok) ==="
sudo tee /etc/nginx/sites-available/default > /dev/null <<'CONF'
server {
    listen 80 default_server;
    server_name _;
    location / { return 200 "ok\n"; add_header Content-Type text/plain; }
}
CONF
sudo systemctl restart nginx
sudo systemctl enable --now ssh

echo "=== [victim_setup] docker + compose ==="
# docker.io from Ubuntu universe is fine for a disposable CI target; we don't
# need the bleeding-edge docker-ce channel. docker-compose-v2 gives us the
# modern `docker compose` subcommand that vulhub's YAML expects.
sudo apt-get install -y -qq docker.io docker-compose-v2
sudo systemctl enable --now docker
# Let the ubuntu user invoke docker without sudo (we'll still sudo here for
# clarity, but this avoids surprises if someone shells in to debug).
sudo usermod -aG docker ubuntu || true

echo "=== [victim_setup] cloning vulhub (sparse) ==="
sudo mkdir -p /opt/vulhub
if [ ! -d /opt/vulhub/.git ]; then
  sudo git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/vulhub/vulhub.git /opt/vulhub
  sudo git -C /opt/vulhub sparse-checkout set \
    log4j/CVE-2021-44228 \
    spring/CVE-2022-22965
else
  sudo git -C /opt/vulhub fetch --depth 1 origin master && \
    sudo git -C /opt/vulhub reset --hard origin/master || true
fi

echo "=== [victim_setup] starting vulhub stacks ==="
# Build+start each in the background; Log4Shell's Solr image is ~500 MB,
# Spring4Shell's Tomcat is ~400 MB. First-run pull is the long pole
# (~60-90s total). Containers themselves boot in ~10s once pulled.
for d in log4j/CVE-2021-44228 spring/CVE-2022-22965; do
  if [ -f "/opt/vulhub/$d/docker-compose.yml" ]; then
    echo "--- up: $d ---"
    (cd "/opt/vulhub/$d" && sudo docker compose up -d) \
      || echo "WARN: $d failed to start — CI will continue but this scenario's signal is degraded"
  else
    echo "WARN: /opt/vulhub/$d/docker-compose.yml missing; sparse-checkout may have failed"
  fi
done

echo "=== [victim_setup] waiting for vulnerable listeners ==="
# Up to 120s per port; vulhub images sometimes need that long on a cold pull.
for port in 8080 8983; do
  printf "  :%s " "$port"
  for i in $(seq 1 60); do
    if ss -tln | grep -q ":${port} "; then
      echo "listening"
      break
    fi
    printf "."
    sleep 2
  done
  if ! ss -tln | grep -q ":${port} "; then
    echo " not listening after 120s (continuing anyway)"
  fi
done

echo "=== [victim_setup] final listener summary ==="
ss -tln | grep -E ':(22|80|8080|8983) ' || true
echo ""
echo "=== [victim_setup] docker ps ==="
sudo docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}' || true
