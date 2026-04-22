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

echo "=== [victim_setup] samba on :139/:445 (deliberately misconfigured share) ==="
# Needed so attacker-side SMB / DCE-RPC probes reach tree-connect and
# named-pipe open, which is where our lateral-movement rules
# (9001001-9001021) match. The share is guest-writable on purpose — this
# is a detection lab, not a hardened target.
sudo apt-get install -y -qq samba
sudo tee /etc/samba/smb.conf > /dev/null <<'SMBCONF'
[global]
   workgroup = LAB
   security = user
   map to guest = Bad User
   guest account = nobody
   log level = 0
   disable netbios = no
   server min protocol = NT1
   server max protocol = SMB3

[lab]
   path = /tmp/smbshare
   browsable = yes
   writable = yes
   guest ok = yes
   read only = no
   create mask = 0666
   directory mask = 0777
SMBCONF
sudo mkdir -p /tmp/smbshare && sudo chmod 777 /tmp/smbshare
sudo systemctl restart smbd nmbd || true
sudo systemctl enable --now smbd nmbd || true

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

# ---------- TIER2 listeners: fill gaps that used to RST probe traffic ----------
# Every probe below used to fail because nothing was listening on the target
# port; adding these surfaces completes the detection loop for Suricata +
# Zeek. Each service is deliberately permissive (anonymous / default
# community / guest-writable) — this is a detection lab, not a hardened
# target.
#
#   vsftpd :21       — T1078.001 anonymous FTP login (probe_catalog ftp-anonymous-login)
#   snmpd  :161/udp  — T1602 SNMP community walk (probe_catalog snmp-community-walk)
#   rsync  :873      — T1105 rsync push/pull exfil (TIER2 ART atomics)
#   nginx  :8443 TLS — T1571 HTTPS-on-non-standard-port, TLS cert probes

echo "=== [victim_setup] vsftpd on :21 (anonymous login) ==="
sudo apt-get install -y -qq vsftpd
sudo tee /etc/vsftpd.conf > /dev/null <<'VSFTPD'
listen=YES
listen_ipv6=NO
anonymous_enable=YES
local_enable=NO
write_enable=NO
xferlog_enable=YES
xferlog_std_format=YES
secure_chroot_dir=/var/run/vsftpd/empty
pam_service_name=vsftpd
ftpd_banner=Welcome to the lab FTP service
VSFTPD
sudo mkdir -p /srv/ftp && echo "lab ftp readme" | sudo tee /srv/ftp/README >/dev/null
sudo systemctl restart vsftpd
sudo systemctl enable vsftpd

echo "=== [victim_setup] snmpd on :161/udp (community=public) ==="
sudo apt-get install -y -qq snmpd snmp
sudo tee /etc/snmp/snmpd.conf > /dev/null <<'SNMPD'
agentAddress udp:0.0.0.0:161
rocommunity public default
sysLocation lab
sysContact lab@lab
SNMPD
sudo systemctl restart snmpd
sudo systemctl enable snmpd

echo "=== [victim_setup] rsync daemon on :873 (anonymous [public] module) ==="
sudo apt-get install -y -qq rsync
sudo tee /etc/rsyncd.conf > /dev/null <<'RSYNCD'
uid = nobody
gid = nogroup
use chroot = yes
max connections = 10
pid file = /var/run/rsyncd.pid
log file = /var/log/rsyncd.log

[public]
   path = /srv/rsync
   comment = public anonymous share
   read only = true
   list = yes
RSYNCD
sudo mkdir -p /srv/rsync && echo "lab rsync readme" | sudo tee /srv/rsync/README >/dev/null
# Ubuntu 22.04 ships rsync.service but gates it on RSYNC_ENABLE=true
if grep -q '^RSYNC_ENABLE=' /etc/default/rsync 2>/dev/null; then
  sudo sed -i 's/^RSYNC_ENABLE=.*/RSYNC_ENABLE=true/' /etc/default/rsync
else
  echo "RSYNC_ENABLE=true" | sudo tee -a /etc/default/rsync >/dev/null
fi
sudo systemctl restart rsync || sudo systemctl restart rsyncd || true
sudo systemctl enable rsync  || sudo systemctl enable rsyncd  || true

echo "=== [victim_setup] nginx TLS on :8443 (self-signed cert) ==="
sudo mkdir -p /etc/nginx/ssl
if [ ! -f /etc/nginx/ssl/lab.crt ]; then
  sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/lab.key -out /etc/nginx/ssl/lab.crt \
    -subj "/C=US/ST=Lab/L=Lab/O=Lab/CN=victim.lab" 2>/dev/null
fi
sudo tee /etc/nginx/sites-available/tls8443 > /dev/null <<'TLSCONF'
server {
    listen 8443 ssl default_server;
    server_name _;
    ssl_certificate     /etc/nginx/ssl/lab.crt;
    ssl_certificate_key /etc/nginx/ssl/lab.key;
    location / { return 200 "tls-ok\n"; add_header Content-Type text/plain; }
}
TLSCONF
sudo ln -sf /etc/nginx/sites-available/tls8443 /etc/nginx/sites-enabled/tls8443
sudo nginx -t && sudo systemctl reload nginx

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

echo "=== [victim_setup] DVWA on :8081 (realistic web surface) ==="
# Gives gobuster/ffuf/feroxbuster/nikto a real directory tree + PHP forms to
# enumerate, versus nginx's single-endpoint "ok". vulnerables/web-dvwa ships
# MySQL bundled so no sidecar needed.
if ! sudo docker ps --format '{{.Names}}' | grep -q '^dvwa$'; then
  sudo docker run -d --restart unless-stopped \
    --name dvwa -p 8081:80 vulnerables/web-dvwa >/dev/null 2>&1 \
    || sudo docker start dvwa || true
fi

echo "=== [victim_setup] waiting for vulnerable listeners ==="
# Up to 120s per port; vulhub images sometimes need that long on a cold pull.
for port in 8080 8081 8983; do
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
ss -tlnu | grep -E ':(21|22|80|139|161|445|873|8080|8081|8443|8983) ' || true
echo ""
echo "=== [victim_setup] docker ps ==="
sudo docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}' || true
