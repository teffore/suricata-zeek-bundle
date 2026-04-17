# Suricata + Zeek Sensor Bundle

Standalone installer for the Suricata 8 + Zeek 8 sensor stack with custom rules.
Extracted from the CDK lab in this repo; strips the AWS-specific bits (S3 rules
fetch, VPC Traffic Mirroring wiring) so it runs on any existing Ubuntu 22.04 host.

## Contents

| File | Purpose |
|---|---|
| `standalone.sh` | Single-file installer — Suricata, Zeek, custom rules, intel feeds, crons, logrotate, systemd units |
| `testing/` | Kali attacker tooling + full attack battery + alert-summary script |

## Requirements

- Ubuntu 22.04 (Jammy)
- Root / sudo
- Outbound internet to: `launchpad.net` (OISF PPA), `download.opensuse.org`
  (Zeek OBS), `urlhaus.abuse.ch` + `feodotracker.abuse.ch` (intel feeds)
- A NIC receiving the traffic you want to inspect (SPAN port, tap, VXLAN
  mirror, or promiscuous capture on a bridged interface)

## Install

```bash
curl -LO https://github.com/teffore/suricata-zeek-bundle/releases/latest/download/standalone.sh
sudo bash standalone.sh
```

### Flags

- `--iface <name>` — capture interface (default: first non-loopback NIC)
- `--force` — proceed even if Suricata/Zeek are already installed
  (existing config is backed up to `/etc/suricata.bak.<ts>/` and
  `/opt/zeek-etc.bak.<ts>/` before anything is overwritten)
- `--preserve-config` — keep existing YAML; only refresh rules and intel

### Prior installs

If Suricata or Zeek is already present, `standalone.sh` exits with code 3 and
prints the detected versions. Re-run with `--force` to back up and upgrade,
or `--preserve-config` to keep your tuning and only update rules.

## Post-install checks

No verification script is bundled. Quick manual checks:

```bash
systemctl is-active suricata
/opt/zeek/bin/zeekctl status
sudo -u suricata suricata -T
tail -f /var/log/suricata/eve.json
```

## What the installer configures

### Suricata

Installs Suricata from the **OISF stable PPA** (Ubuntu 22.04 ships 6.0.x, which
is EOL; PPA tracks 8.0.x — required for HTTP/2, QUIC/HTTP/3, and JA4).

Rule sources enabled via `suricata-update`:
- ET Open (default)
- `tgreen/hunting`
- `ptresearch/attackdetection`
- `sslbl/ssl-fp-blacklist`
- `sslbl/ja3-fingerprints`
- `etnetera/aggressive`
- Bundled custom rules (SIDs 9000001–9001021)

Tunings applied to `/etc/suricata/suricata.yaml`:

| Setting | Value | Why |
|---|---|---|
| `HOME_NET` | `[10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]` | Full RFC 1918 space |
| `default-rule-path` | `/var/lib/suricata/rules` | Where `suricata-update` writes |
| `community-id` | `true` | Standard flow hash for SIEM correlation with Zeek |
| `ja3-fingerprints` | `yes` | TLS client fingerprints (identifies malware C2 under TLS) |
| `metadata` in alerts | `yes` | Adds CVE / product / description to alert output |
| `mpm-algo` / `spm-algo` | `hs` (Hyperscan) | Faster pattern matching on 49k+ rule sets |
| `stream.async-oneside` | `true` | Handle asymmetric flows (e.g. SPAN/mirror sessions) |
| `max-pending-packets` | `10000` | Avoid drops under burst (OISF recommendation) |
| `anomaly` logging | enabled | Catches protocol violations signatures miss |
| Runtime user | `suricata` (non-root) | Drops privileges after startup |

Operational bits installed:
- **Daily rule updates** via `/etc/cron.d/suricata-update` (03:00 UTC) with
  live reload via `suricatasc` socket (no restart needed)
- **Logrotate** `/etc/logrotate.d/suricata` — 7 days, compressed, SIGHUP to
  reopen files (avoids full 49k-rule reload on rotation)
- **systemd drop-in** at `/etc/systemd/system/suricata.service.d/user.conf`
  pinning non-root execution

### Zeek

Installs **Zeek 8.0.x** from the openSUSE OBS `security:zeek` repo (Ubuntu
ships older Zeek). Coexists with Suricata on the same NIC: Suricata via
`af-packet`, Zeek via libpcap.

Configured in `/opt/zeek/etc/`:
- `node.cfg` — standalone deployment, capture on primary interface
- `networks.cfg` — full RFC 1918 as `Site::local_nets`

Loaded in `local.zeek`:
- `policy/protocols/conn/community-id-logging` — adds community-id to `conn.log` for Suricata↔Zeek correlation
- `protocols/ssh/detect-bruteforcing` (threshold lowered to 5 guesses)
- `protocols/ftp/detect-bruteforcing`
- `protocols/http/detect-webapps`
- `frameworks/files/detect-MHR` — Team Cymru malware hash registry lookups
- `frameworks/intel/seen`
- `misc/stats` — 60-second engine stats to `stats.log`

**Intel Framework** (`/opt/zeek/intel/`):
- `build-intel.sh` assembles `intel.dat` from:
  - **abuse.ch URLhaus** — malware delivery domains
  - **abuse.ch Feodo Tracker** — botnet C2 IPs
- Refreshed daily at 04:30 via `/etc/cron.d/zeek-intel`
- Hits appear in `intel.log` with source attribution

**Operational:**
- `zeekctl cron` daily at 04:00 (rotation + crash recovery checks)
- Logrotate: `/opt/zeek/logs/*/*.log`, 7 days compressed

### Custom rules

~130 signatures in the `9000000` SID range, embedded directly in `standalone.sh`
and appended to `/var/lib/suricata/rules/suricata.rules` after `suricata-update`
so they survive rule refreshes. Coverage:

- **Traffic mirror validation** (SSH, TCP SYN scan canaries)
- **DNS tunneling** — long subdomain labels, entropy patterns (iodine, dnscat2)
- **URL evasion** — double/triple encoding, Unicode bypass, CRLF injection
- **Cloud metadata** — IMDSv1/v2, AWS credential-format exfil, GCP/Azure IMDS
- **Web shells** — c99, r57, WSO, China Chopper, JSP cmd
- **Injection** — SQLi, XSS, XXE, SSTI, LFI, NoSQL
- **AD / Kerberos / LDAP** — anonymous bind, NTLM, Kerberoasting, DCSync
- **Supply chain** — npm postinstall, PyPI setup.py, GitHub token exfil, typosquat
- **C2 frameworks** — Havoc, Brute Ratel, Mythic, Poshc2, DNS beaconing, DoH
- **Container / K8s** — Docker socket, nsenter namespace escape, K8s API
- **API abuse** — key brute force, suspicious user-agents
- **SaaS exfil** — telegra.ph, Pastebin, transfer.sh, ngrok, serveo
- **Lateral movement** — SMB tree connects to ADMIN$/C$/IPC$, PsExec, svcctl, winreg, samr

## Testing & validation (Kali attacker)

The sensor was developed against a reproducible lab: a Kali attacker box
driving scripted attacks at a victim host while traffic is mirrored to the
Suricata/Zeek sensor. The `testing/` directory bundles those scripts so you
can drive the same test suite against any target you control.

### Contents

| Script | Purpose |
|---|---|
| `testing/kali_setup.sh` | Installs Kali attacker tooling: `nmap`, `hydra`, `nikto`, `hping3`, `dnsutils`, `smbclient`, `impacket-scripts`, `python3-impacket` |
| `testing/run_attacks.sh <victim_ip>` | Runs the full attack battery (see categories below) |
| `testing/verify_alerts.sh` | Runs on the sensor; summarizes alerts, Zeek notices, VXLAN decap evidence, decoder stats |

### Attack coverage

`run_attacks.sh` exercises **18 categories** with ~200+ individual probes:

**Reconnaissance**
- ICMP ping sweep, Nmap SYN scan (top 100), service/version detection, OS
  detection, vulnerability scripts (`--script vuln`), CVE detection (`vulners`)

**Web application attacks**
- SQL injection (union, auth bypass), directory traversal (plain + URL-encoded),
  XSS (script + event-handler), Shellshock, suspicious user-agents (sqlmap,
  nikto, DirBuster), sensitive file probes (`.env`, `/phpmyadmin/`, `server-status`)

**CVE exploit simulations (2021–2025)**
- Log4Shell (CVE-2021-44228), Spring4Shell (2022-22965), Confluence OGNL
  (2023-22527), MOVEit SQLi (2023-34362), Apache path traversal
  (2021-41773/42013), Citrix NetScaler (2023-3519), FortiOS SSLVPN (2018-13379),
  vCenter (2021-21972), ProxyShell (2021-34473), Palo Alto PAN-OS (2024-3400),
  CUPS IPP (2024-47176), Ivanti Connect Secure (2025-0282), Cleo LexiCom /
  Cl0p (2024-55956), PHP-CGI (2024-4577), Check Point (2024-24919), ActiveMQ
  (2023-46604), React Server Components (2025-55182)

**Brute force & credential attacks**
- SSH (hydra + per-user failed logins), FTP, SMB, Telnet, RDP, LDAP anonymous bind

**DNS abuse**
- Long-subdomain tunneling (iodine/dnscat2 patterns), TXT record exfil,
  suspicious TLDs, zone transfer attempts, high-rate random-subdomain floods

**Cloud / metadata attacks**
- IMDSv1 exploitation, IMDSv2 token requests, IMDS bypass variants (decimal,
  octal, IPv6), credential + user-data theft, ECS/Lambda/EKS metadata abuse,
  Docker socket patterns, S3 bucket enumeration via DNS, AKIA credential-format
  exfil, AWS CLI/SDK user-agents from unusual sources, Capital One attack chain

**C2 framework patterns**
- Cobalt Strike beacon URIs, Meterpreter defaults, PowerShell Empire, Sliver,
  Mythic, ransomware callbacks (Conti, LockBit, REvil), crypto mining (XMRig,
  Stratum)

**Evasion techniques**
- IP fragmentation, double/triple URL encoding, case randomization,
  Unicode/full-width bypass, chunked encoding abuse, oversized headers,
  SNI/Host mismatch, HTTP request smuggling (CL.TE), CRLF injection,
  TCP segmentation, header-case variation, nested encoding

**Malware indicators**
- EICAR test string (POST + URL), PowerShell download cradles, phishing kit
  paths, double-extension file probes, base64 shellcode in POST bodies

**Negative controls**
- Legitimate browser GETs, API calls, search queries, form submissions, asset
  requests, well-known DNS lookups, standard TLS handshakes — these should
  **not** fire alerts (tuning-drift canaries)

### Running the suite

On the attacker host:
```bash
sudo ./testing/kali_setup.sh           # one-time install
./testing/run_attacks.sh <victim_ip>   # ~5–10 min
```

On the sensor host:
```bash
sudo ./testing/verify_alerts.sh
```

`verify_alerts.sh` prints:
- Suricata service status and interface/VXLAN diagnostics
- `fast.log` tail (last 50 alerts)
- Top 30 alert signatures by volume (written in full to `/tmp/sig-breakdown.txt`)
- Alert categories breakdown
- Event-type totals from `eve.json`
- Decoder stats
- Zeek summary: log line counts, notices fired, tunnel.log (VXLAN decap evidence),
  top inner-flow conversations from `conn.log`

Exit code: 0 if ≥3 alerts observed, 1 otherwise — suitable for CI gates.

### Expected detection

In the reference lab (AWS VPC Traffic Mirroring → sensor), a single
`run_attacks.sh` pass produces several hundred Suricata alerts across ~40–60
distinct signature IDs, plus Zeek notices for SSH/FTP brute force, detected
web apps, and any intel-framework hits against URLhaus/Feodo. The HTML
iteration reports in the source CDK repo (`reports/iteration-*.html`,
`reports/attack-vs-detection-*.html`) document how coverage evolved across
8 tuning iterations.

## Logs

- Install log: `/var/log/suricata-setup.log`
- Suricata: `/var/log/suricata/{eve.json,fast.log,suricata.log}`
- Zeek: `/opt/zeek/logs/current/*.log`

## Uninstall / rollback

No uninstaller is bundled. To roll back after `--force`:

```bash
sudo systemctl stop suricata
sudo /opt/zeek/bin/zeekctl stop
sudo rm -rf /etc/suricata && sudo mv /etc/suricata.bak.<ts> /etc/suricata
sudo rm -rf /opt/zeek/etc && sudo mv /opt/zeek-etc.bak.<ts> /opt/zeek/etc
sudo apt-get remove --purge suricata zeek-8.0
```
