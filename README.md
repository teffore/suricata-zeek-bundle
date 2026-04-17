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
  (Zeek OBS), `urlhaus.abuse.ch` + `feodotracker.abuse.ch` (intel feeds),
  `github.com` (zkg third-party Zeek packages)
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

Quick manual checks:

```bash
systemctl is-active suricata
sudo systemctl is-active zeek           # new in this bundle (zeek.service)
sudo /opt/zeek/bin/zeekctl status
sudo -u suricata suricata -T
tail -f /var/log/suricata/eve.json
```

For a full summary — service state, interface / VXLAN diagnostics, top alert
signatures, category breakdown, decoder stats, and Zeek notice / tunnel /
conn.log summaries — use the bundled [`testing/verify_alerts.sh`](testing/verify_alerts.sh)
(exit 0 if ≥3 alerts fired, 1 otherwise; suitable for CI gates).

## What the installer configures

### Suricata

Installs Suricata from the **OISF stable PPA** (Ubuntu 22.04 ships 6.0.x, which
is EOL; PPA tracks 8.0.x — required for HTTP/2, QUIC/HTTP/3, and JA4).

Rule sources enabled via `suricata-update` (catalog refreshed first so feed
renames are picked up — silences 12+ "Source index does not exist" warnings):

| Source | What it contributes | Reference |
|---|---|---|
| ET Open (default) | Community ETI signatures — base coverage | [rules.emergingthreats.net](https://rules.emergingthreats.net/open/) |
| `tgreen/hunting` | Travis Green's CVE-era exploit hunting pack | [github.com/travisbgreen/hunting-rules](https://github.com/travisbgreen/hunting-rules) |
| `etnetera/aggressive` | High-FP / high-signal aggressive ruleset | [etnetera.cz](https://security.etnetera.cz/feeds/) |
| `abuse.ch/sslbl-ja3` | JA3 client fingerprints of known malware families | [sslbl.abuse.ch/ja3-fingerprints/](https://sslbl.abuse.ch/ja3-fingerprints/) |
| Bundled custom rules | ~130 signatures in the 9000000 SID range (see below) | in-repo |

Removed vs. earlier revisions: `ptresearch/attackdetection` (obsolete upstream),
`abuse.ch/sslbl-blacklist` (IP list retired 2025-01-03 by abuse.ch).

A `/etc/suricata/disable.conf` mutes one high-volume noise signature
(`SURICATA HTTP Response excessive header repetition`) which was producing
~67% of alert volume with zero detection value.

Tunings applied to `/etc/suricata/suricata.yaml`:

| Setting | Value | Why | Reference |
|---|---|---|---|
| `HOME_NET` | `[10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]` | Full RFC 1918 — treats all private-IP flows as internal | [HOME_NET best practice](https://forum.suricata.io/t/home-net-and-multiple-interfaces-plus-deployment-best-practices/374) |
| `default-rule-path` | `/var/lib/suricata/rules` | Where `suricata-update` writes rule sets | [suricata-update docs](https://suricata-update.readthedocs.io/) |
| `community-id` | `true` | Standard flow hash — correlates the same flow across Suricata, Zeek, and any SIEM | [community-id-spec](https://github.com/corelight/community-id-spec) |
| `ja3-fingerprints` | `yes` | TLS client fingerprints — identify malware C2 behind encryption | [sslbl.abuse.ch/ja3](https://sslbl.abuse.ch/ja3-fingerprints/) |
| **`ja4-fingerprints`** | `yes` | JA4 supersedes JA3 as the 2026 standard; JA3 widely evaded by modern malware | [FoxIO JA4 spec](https://github.com/FoxIO-LLC/ja4) |
| **`hassh`** | `yes` | SSH client fingerprint — cheap, high-signal for lateral-movement detection | [salesforce/hassh](https://github.com/salesforce/hassh) |
| `metadata` in alerts | `yes` | Adds CVE / product / description / ATT&CK tags to eve.json alert output | [ET metadata](https://www.proofpoint.com/us/blog/threat-insight/emerging-threats-updates-improve-metadata-including-mitre-attck-tags) |
| `mpm-algo` / `spm-algo` | `hs` (Hyperscan) | Faster multi-pattern matching on 75k+ rule sets | [Suricata Hyperscan docs](https://docs.suricata.io/en/latest/performance/hyperscan.html) |
| `stream.async-oneside` | `true` | Handle asymmetric flows (AWS Traffic Mirror / SPAN sessions deliver directions separately) | [Suricata tuning](https://docs.suricata.io/en/latest/performance/tuning-considerations.html) |
| `max-pending-packets` | `5000` (<4 vCPU) / `10000` (4+ vCPU) | Picked at install time from `nproc`. OISF docs recommend 10000+ for 8+ core hosts; below that, RAM overhead outweighs queue-depth benefit | [Suricata tuning](https://docs.suricata.io/en/suricata-7.0.12/performance/tuning-considerations.html) |
| `anomaly` logging | enabled | Catches protocol violations that signature rules miss (TCP flag anomalies, protocol mismatch) | [eve-output anomaly](https://docs.suricata.io/en/suricata-8.0.0/output/eve/eve-json-output.html) |
| Runtime user | `suricata` (non-root) | Drops privileges after startup via systemd drop-in; limits blast radius of any Suricata CVE | [Suricata drop-privs docs](https://docs.suricata.io/en/suricata-7.0.11/configuration/dropping-privileges.html) |
| Pre-8 purge | automatic | Detects pre-v8 Suricata + purges before install so stale pidfiles from the 7.0 LTS PPA don't break the 8.x systemd unit | bundle-specific |

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

Log output format: **JSON** (one object per line, `_path` field identifies the
log source). Switched from Zeek's default TSV so Filebeat, Elastic, Splunk,
Loki, and any other SIEM can ingest natively without custom parsers.
`zeek-cut` only reads TSV, so any downstream tool using it needs to move to
`jq` / native JSON parsing.

Field names are **native Zeek** (`id.orig_h`, `id.resp_h`, `ssl.server_name`,
etc.) — no ECS rewrite is done at source. When off-box shipping to Elastic
is added later, Corelight publishes Elasticsearch ingest pipelines
([`corelight/ecs-mapping`](https://github.com/corelight/ecs-mapping) +
[`corelight/ecs-templates`](https://github.com/corelight/ecs-templates))
that apply the ECS transform server-side at ingest — that's the right
place for it, not at the Zeek writer.

Loaded in `local.zeek`:

| `@load` | What it does | Why / Reference |
|---|---|---|
| `policy/tuning/json-logs` | Switches every log from TSV to JSON | [Book of Zeek: log formats](https://docs.zeek.org/en/master/log-formats.html) |
| `policy/protocols/conn/community-id-logging` | Adds `community_id` hash to `conn.log` | Correlates flows with Suricata eve.json / [community-id-spec](https://github.com/corelight/community-id-spec) |
| `protocols/ssh/detect-bruteforcing` | Notices on SSH password brute force (threshold **15**) | Default is 30; 15 catches hydra bursts without tripping on ordinary DevOps automation |
| `protocols/ftp/detect-bruteforcing` | Notices on FTP password brute force | [Book of Zeek: FTP](https://docs.zeek.org/en/lts/scripts/policy/protocols/ftp/detect-bruteforcing.zeek.html) |
| `protocols/http/detect-webapps` | Identifies web apps from HTTP traffic, logs to `software.log` | [policy/protocols/http/detect-webapps](https://docs.zeek.org/en/lts/scripts/policy/protocols/http/detect-webapps.zeek.html) |
| `frameworks/files/detect-MHR` | Team Cymru MalHash Registry lookups against file hashes | [policy/frameworks/files/detect-MHR](https://docs.zeek.org/en/lts/scripts/policy/frameworks/files/detect-MHR.zeek.html) |
| `frameworks/files/hash-all-files` | Enables SHA256 on every file (default is MD5/SHA1 only) — prerequisite for most file-hash intel | [policy/frameworks/files/hash-all-files](https://docs.zeek.org/en/lts/scripts/policy/frameworks/files/hash-all-files.zeek.html) |
| `frameworks/intel/seen` | Matches seen indicators (hosts, URLs, hashes) against the intel framework | [Intel framework docs](https://docs.zeek.org/en/lts/frameworks/intel.html) |
| `policy/frameworks/intel/do_notice` | Promotes intel hits to notices (visible in `notice.log`) for rows with `meta.do_notice=T` | [policy/frameworks/intel/do_notice](https://docs.zeek.org/en/lts/scripts/policy/frameworks/intel/do_notice.zeek.html) |
| `policy/misc/capture-loss` | Emits `capture_loss.log` every 15 min + `CaptureLoss::Too_Much_Loss` notices — primary signal that the mirror is delivering | [policy/misc/capture-loss](https://docs.zeek.org/en/lts/scripts/policy/misc/capture-loss.zeek.html) |
| `policy/protocols/ssl/validate-certs` | X.509 chain validation; flags expired / self-signed / bad-chain certs in `ssl.log` | [ssl/validate-certs](https://docs.zeek.org/en/lts/scripts/policy/protocols/ssl/validate-certs.zeek.html) |
| `policy/protocols/ssl/log-hostcerts-only` | Cuts `x509.log` volume ~10× by dropping intermediate/root cert rows | [ssl/log-hostcerts-only](https://docs.zeek.org/en/master/scripts/policy/protocols/ssl/log-hostcerts-only.zeek.html) |
| `policy/protocols/ssl/expiring-certs` | Notices for certs expiring within 30 days — cert hygiene | [ssl/expiring-certs](https://docs.zeek.org/en/lts/scripts/policy/protocols/ssl/validate-certs.zeek.html) |
| `policy/protocols/conn/known-hosts` | Tracks first-seen hosts in the VPC — anomaly baseline | [known logs](https://docs.zeek.org/en/current/logs/known-and-software.html) |
| `policy/protocols/conn/known-services` | Tracks first-seen (host, port, proto) tuples — new-service alerting basis | same |
| `policy/frameworks/analyzer/detect-protocols` | Logs services running on non-standard ports (shells on 443, HTTP on 22, etc.) | [frameworks/analyzer/detect-protocols](https://docs.zeek.org/en/lts/scripts/policy/frameworks/analyzer/detect-protocols.zeek.html) |
| `misc/stats` | 60-second engine stats to `stats.log` — rate / memory / queue telemetry | [policy/misc/stats](https://docs.zeek.org/en/lts/scripts/policy/misc/stats.zeek.html) |

**Third-party packages installed via `zkg` at deploy time** (fetched from
GitHub, auto-loaded via `/opt/zeek/share/zeek/site/packages/__load__.zeek`):

| Package | What it adds | Why / Reference |
|---|---|---|
| `zeek/foxio/ja4` | JA4+ family — **JA4S** (TLS server), **JA4H** (HTTP), **JA4SSH**, **JA4T/JA4L** (TCP/latency), **JA4D** (DHCP) across `ssl.log`, `http.log`, `ssh.log`, plus new `ja4ssh.log` and `ja4d.log` | Completes the fingerprint family; Suricata 8's native JA4 only ships the client-TLS variant due to patent policy / [github.com/FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4) |
| `mitre-attack/bzar` | `ATTACK::*` notices tagged with MITRE ATT&CK technique IDs (T1021.002, T1047, T1003.006, …) when SMB / DCE-RPC / NTLM / Kerberos events match mapped patterns | Direct ATT&CK classification of Windows lateral-movement traffic; maintained by MITRE / [github.com/mitre-attack/bzar](https://github.com/mitre-attack/bzar) |
| `corelight/zeek-long-connections` | Interim `conn.log` rows for flows that are still open (default every 60s) rather than only writing on flow-close | Makes C2 beacons, reverse shells, and data-exfil tunnels visible in real-time queries / [github.com/corelight/zeek-long-connections](https://github.com/corelight/zeek-long-connections) |

**Intel Framework** (`/opt/zeek/intel/`):
- `build-intel.sh` assembles `intel.dat` from:
  - **abuse.ch URLhaus** — malware delivery domains
  - **abuse.ch Feodo Tracker** — botnet C2 IPs
- Refreshed daily at 04:30 via `/etc/cron.d/zeek-intel`
- Hits appear in `intel.log` with source attribution

**Operational:**
- `zeekctl cron` daily at 04:00 (rotation + crash recovery checks)
- Logrotate: `/opt/zeek/logs/*/*.log`, 7 days compressed
- **`zeek.service` systemd unit** — Zeek auto-starts on boot via a oneshot
  wrapper around `zeekctl start/stop`. Replaces the prior cron-only lifecycle,
  which left Zeek in `crashed` state on reboot until 04:00 UTC.

### Custom rules

~130 signatures in the `9000000` SID range, embedded directly in `standalone.sh`
and appended to `/var/lib/suricata/rules/suricata.rules` after `suricata-update`
so they survive rule refreshes.

The install-time append filters out **SID 9000002** (`TEST - SSH connection
to HOME_NET`) — in single-ENI mirror-target mode the sensor sees its own
management SSH traffic, which would trip that canary rule. The full rule
still exists in the custom-rules source on disk, so you can manually re-add
it if you want the canary in a dual-ENI setup.

Coverage:

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
| `testing/attacker_setup.sh` | Installs the attacker toolkit on a plain Ubuntu 22.04 box: `nmap`, `hydra`, `nikto`, `hping3`, `dnsutils`, `smbclient`, `xxd`, `curl`, `python3-impacket` (provides the `impacket-*` commands). Installs each package independently so one missing universe package doesn't roll back the whole batch. |
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
sudo ./testing/attacker_setup.sh       # one-time install
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

## Continuous integration

Two GitHub Actions workflows validate the bundle end-to-end. Both use OIDC
federation to AWS (no long-lived access keys), provision ephemeral EC2
instances, and tear everything down on completion — see
[`.github/AWS_SETUP.md`](.github/AWS_SETUP.md) for the one-time IAM role setup.

| Workflow | Trigger | What it does |
|---|---|---|
| [`validate-standalone.yml`](.github/workflows/validate-standalone.yml) | Push / PR touching `standalone.sh` | Spins up one t3.medium Ubuntu 22.04, runs `standalone.sh --force`, asserts Suricata + Zeek are on 8.x and configs validate |
| [`validate-detections.yml`](.github/workflows/validate-detections.yml) | `workflow_dispatch` (manual) | Spins up **three** t3.medium instances (sensor / victim / attacker), wires an **AWS VPC Traffic Mirror** session (VXLAN/4789) from victim ENI → sensor primary ENI, installs the bundle, runs [`testing/run_attacks.sh`](testing/run_attacks.sh) from the attacker, gates on [`testing/verify_alerts.sh`](testing/verify_alerts.sh), uploads the resulting `sig-breakdown.txt` + `fast.log` + Zeek logs as artifacts, and tears down in reverse order. ~$0.05 / 8-minute run. |

The detection workflow verifies that every link in the chain is actually
working end-to-end — install succeeds, mirror delivers packets, attacks
produce alerts, both Suricata and Zeek log them.

## Logs

- Install log: `/var/log/suricata-setup.log`
- Suricata: `/var/log/suricata/{eve.json,fast.log,suricata.log}`
- Zeek: `/opt/zeek/logs/current/*.log` (JSON format, one object per line)

## Uninstall / rollback

No uninstaller is bundled. To roll back after `--force`:

```bash
sudo systemctl stop suricata
sudo /opt/zeek/bin/zeekctl stop
sudo rm -rf /etc/suricata && sudo mv /etc/suricata.bak.<ts> /etc/suricata
sudo rm -rf /opt/zeek/etc && sudo mv /opt/zeek-etc.bak.<ts> /opt/zeek/etc
sudo apt-get remove --purge suricata zeek-8.0
```
