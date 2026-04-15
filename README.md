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
