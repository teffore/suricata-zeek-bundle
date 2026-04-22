# purple-agent

Autonomous purple-team probe runner for the Suricata+Zeek lab. Drops you a
3-box lab (attacker / victim / sensor) and runs Claude as an agent that
iterates through a curated probe pool (or improvises, with `--pool-free`),
observes the sensor, and writes a self-contained HTML report with an inline
ledger-vs-sensor accuracy audit — the script-version of what you did
interactively with me during wave 1 and wave 2.

Inspired by Tech Raj's HackTheBox-pentest-agent pattern (custom system
prompt + autonomous Claude + final walkthrough report) but scoped to
**defensive evaluation on your own authorized lab**, not external
pentesting.

## What it does

For each iteration:

1. **Baseline** sensor — snapshot `eve.json` line count, Zeek `weird.log` line
   count, and sensor epoch time (one `ssh` per baseline, so all three are tight)
2. **Probe** — SSH to attacker, run a bash probe against the victim IP
3. **Check** — SSH to sensor, diff new Suricata SIDs + Zeek notices + weird events
4. **Classify** — call `record_finding` with verdict:
   - `DETECTED` — a relevant Suricata SID fired (or a material Zeek notice / intel hit)
   - `UNDETECTED` — probe reached the wire but no rule matched (rule-engineering target)
   - `ERROR` — probe failed to run (tool missing, connection refused)
   - `FP` — a SID fired but is unrelated to the probe technique (false positive)

**Pushback loop.** If the agent stops before reaching `--max-attacks` (text-only
turn, hit budget, or just said COMPLETE early), the orchestrator pushes it back
with a continuation prompt up to a fixed retry cap. The run only ends when the
ledger reaches the requested count or the cap is hit.

**End-of-run Zeek sweep.** After the agent finishes, a 3-minute wait + final
sensor query catches SumStats-delayed notices (Scan::Port_Scan,
SSH::Password_Guessing, etc.) that Zeek emits on a timer rather than inline.
Findings are merged into the report as a "Zeek Sensor Sweep" section. Skip
with `--no-sweep`.

**Inline accuracy audit.** Every report now ends with a deterministic
cross-check that pulls Suricata alerts + Zeek notices straight from the sensor
and compares them to what the agent claimed in the ledger. Overclaim counts
(claimed SIDs that never actually fired) appear at the bottom of every report.

At run end the script writes:

- `reports/report-<ts>.html` — self-contained HTML report (auto-opens in browser)
- `reports/findings-<ts>.jsonl` — raw per-probe JSONL trace
- `reports/sweep-<ts>.json` — sensor sweep results
- `reports/accuracy-<ts>.json` — accuracy audit sidecar
- `reports/navigator-layer-<ts>.json` — MITRE ATT&CK Navigator layer

## Hard safety constraints (enforced via system prompt + tool allowlist)

- Only tools: `Bash`, `Read`, `record_finding`. No `Write`, no `Edit`, no MCP-shell-over-SSH.
- System prompt explicitly bans `rm`, `shutdown`, `iptables`, `aws ec2 terminate-*`, git ops, wiki edits.
- SSH restricted (by prompt) to the 2 declared hosts. No third-party IPs.
- `permission_mode=bypassPermissions` is set so it doesn't prompt, but the
  allowlist + prompt rules do the actual constraint.

## Prerequisites

- **Claude Code subscription** — you're running `claude` CLI interactively
  already. The Python SDK inherits that OAuth token. Run `claude` once to
  confirm you're logged in.
- **Python 3.10+** (uv works too: `uv python install 3.14`).
- **AWS CLI + jq** on PATH, creds configured (`aws sts get-caller-identity` works).
- **SSH + `ssh-keygen`** on PATH (Git Bash on Windows is fine).

## Lab provisioning

The agent needs the 3-box topology (attacker / victim / sensor + VPC traffic
mirror) running. Two scripts in this folder do that end-to-end:

```bash
./lab-up.sh          # ~3-4 min, writes .lab-state + .lab-key, prints cheat sheet
./lab-down.sh        # reads .lab-state, deletes in reverse order
```

Under the hood this mirrors the exact provisioning `validate-detections.yml`
CI does (same 3× t3.medium + dual traffic-mirror session pattern), but keeps
the lab running until you explicitly tear it down.

Cost: ~$0.13/hr while up. One lab at a time — `lab-up.sh` refuses to start if
`.lab-state` exists. If state is lost but AWS still holds resources, recover
via `./lab-down.sh --force` (discovers by the `PurpleLabRunTag` EC2 tag).

At the end of `lab-up.sh`, the cheat sheet prints a ready-to-run
`purple_agent.py` invocation with the live IPs filled in — copy-paste to
start the agent.

## Install

```bash
cd purple-agent
python -m venv .venv
# Windows Git Bash:
source .venv/Scripts/activate
# Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
```

## Run

With a lab already up (same shape as `validate-detections.yml` uses):

```bash
python purple_agent.py \
  --attacker-ip 34.231.243.255 \
  --sensor-ip   98.92.118.21 \
  --victim-ip   172.31.78.152 \
  --key         .lab-key \
  --budget      30 \
  --max-attacks 10
```

Output streams a one-line preview per LLM turn to stdout. Report auto-opens
when the run finishes.

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `--budget N` | 30 | Max LLM turns before the agent has to wrap up. |
| `--max-attacks N` | unset | Cap the ledger at N probes. Pushback loop keeps the agent going until this is hit. |
| `--pool-free` | off | Agent improvises attacks ATT&CK-style instead of reading `probes.yaml`. Useful for exploring novel coverage gaps. |
| `--focus "phrase"` | none | Appended to the system prompt. Example: `--focus "prioritize AD lateral movement / Kerberos / SMB"`. |
| `--no-sweep` | off | Skip the 3-minute post-run sensor sweep (SumStats-delayed notices). |

## Customizing the probe pool

`probes.yaml` ships with ~80 probes curated from the wave-1 and wave-2
research (CVE-2024 signatures, modern C2, SaaS/LLM SNIs, supply-chain,
cryptominer-live, Zeek-specific signals). Each entry has an
`expected_verdict` hint the agent uses to classify.

Add your own by appending a new block with the same schema:

```yaml
- name: my-new-probe
  category: cve-2026
  mitre: T1190
  rationale: "One-line why"
  expected_sids: []
  expected_verdict: UNDETECTED
  already_in_catalog: false
  command: |
    curl -sS --max-time 5 "http://{{VICTIM_IP}}/new-path" >/dev/null
```

Use `{{VICTIM_IP}}` in commands — the agent substitutes it from the
`--victim-ip` CLI arg.

## Troubleshooting

- **`claude-agent-sdk not installed`** — `pip install -r requirements.txt`.
- **Agent claims it can't SSH** — verify `ssh -i <key> ubuntu@<host> echo ok`
  works from your shell first. The SDK just shells out to `ssh`.
- **Auth errors from the SDK** — run `claude` once interactively. The SDK
  picks up the OAuth token from the CLI's config. Alternatively, set
  `ANTHROPIC_API_KEY` if you have a paid API key.
- **Zero findings** — check `reports/findings-<ts>.jsonl` (empty file
  means the agent never called `record_finding`). Re-read the agent's
  stdout preview for what it was doing instead.

## What it does NOT do (by design)

- Does **not** commit code or touch `run_attacks.sh` / `probe_catalog.json`.
  Catalog decisions are yours — read the report, hand-add detected scenarios
  that are worth adding to CI.
- Does **not** refresh the wiki.
- Does **not** run the full CI battery (`run_attacks.sh`). That's the CI
  workflow's job; this agent does one-probe-at-a-time exploration.
- Does **not** tear down the lab. Your `lab-up.sh` / ad-hoc provisioning
  owns that.
