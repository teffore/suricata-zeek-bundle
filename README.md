# Suricata + Zeek Sensor Bundle

Standalone installer for the Suricata 8 + Zeek 8 sensor stack with custom rules.
Extracted from the CDK lab in this repo; strips the AWS-specific bits (S3 rules
fetch, VPC Traffic Mirroring wiring) so it runs on any existing Ubuntu 22.04 host.

## Contents

| File | Purpose |
|---|---|
| `install.sh` | Wrapper: detects prior installs, backs up config, runs both setup scripts |
| `suricata_setup.sh` | Installs Suricata 8.x from the OISF PPA, applies tuning |
| `zeek_setup.sh` | Installs Zeek 8.x from the OBS repo, intel feeds, zeekctl cron |
| `custom.rules` | ~70 custom Suricata signatures (SIDs 9000001–9000612) |
| `verify.sh` | Post-install health + canary-alert check |

## Requirements

- Ubuntu 22.04 (Jammy)
- Root / sudo
- Outbound internet to: `launchpad.net` (OISF PPA), `download.opensuse.org`
  (Zeek OBS), `urlhaus.abuse.ch` + `feodotracker.abuse.ch` (intel feeds)
- A NIC receiving the traffic you want to inspect (SPAN port, tap, VXLAN
  mirror, or promiscuous capture on a bridged interface)

## Install

```bash
tar -xzf suricata-zeek-bundle.tar.gz
cd suricata-zeek-bundle
sudo ./install.sh
```

### Flags

- `--iface <name>` — capture interface (default: first non-loopback NIC)
- `--force` — proceed even if Suricata/Zeek are already installed
  (existing config is backed up to `/etc/suricata.bak.<ts>/` and
  `/opt/zeek-etc.bak.<ts>/` before anything is overwritten)
- `--preserve-config` — keep existing YAML; only refresh rules and intel

### Prior installs

If Suricata or Zeek is already present, `install.sh` exits with code 3 and
prints the detected versions. Re-run with `--force` to back up and upgrade,
or `--preserve-config` to keep your tuning and only update rules.

## Verify

```bash
sudo ./verify.sh
```

Exits 0 on success. Checks: services up, versions 8.x, configs parse, custom
rules loaded, live capture producing fresh `eve.json`, and a canary alert
(SID 9000002) fires end-to-end.

The canary fails on hosts that aren't receiving mirrored traffic — expected
if you haven't wired up a SPAN/tap yet. All other checks should still pass.

## What the setup scripts configure

### Suricata (`suricata_setup.sh`)

Installs Suricata from the **OISF stable PPA** (Ubuntu 22.04 ships 6.0.x, which
is EOL; PPA tracks 8.0.x — required for HTTP/2, QUIC/HTTP/3, and JA4).

Rule sources enabled via `suricata-update`:
- ET Open (default)
- `tgreen/hunting`
- `ptresearch/attackdetection`
- `sslbl/ssl-fp-blacklist`
- `sslbl/ja3-fingerprints`
- `etnetera/aggressive`
- `custom.rules` (bundled — SIDs 9000001–9000612)

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

### Zeek (`zeek_setup.sh`)

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

### Custom rules (`custom.rules`)

~70 signatures in the `9000000` SID range:
- **Traffic mirror validation** (SSH, TCP SYN scan canaries)
- **DNS tunneling detection** — long subdomain labels, entropy patterns
  targeting iodine / dnscat2
- **Policy violations** — cleartext protocols, credential patterns in
  POST bodies (AKIA, password fields)
- **C2 heuristics** — large ICMP payloads, beacon patterns

Appended to `/var/lib/suricata/rules/suricata.rules` after `suricata-update`
so they survive rule refreshes.

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
