# Agent Orange

Deterministic runner for atomic red team attacks against the shared
Suricata+Zeek lab. Sibling to `purple-agent/`, not a replacement — both
coexist and can be compared side by side.

## Philosophy

- **Deterministic mechanics.** Runner, harvest, attribution, and
  verdict are pure / near-pure functions. Same inputs → same outputs.
- **LLM only at the end.** After the deterministic pipeline writes the
  ledger, a single Anthropic SDK call reads it and produces narrative,
  per-attack commentary, remediation suggestions, and drift comparison
  vs. the prior run. The LLM never changes verdicts.
- **Attack-first vocabulary.** "Attack" everywhere in code and reports,
  not "probe."

## Installing

```bash
pip install -r agent-orange/requirements.txt
```

Dependencies: `PyYAML` (catalog parsing), `claude-agent-sdk`
(end-of-run narrative). Both are pinned permissively in
`requirements.txt`. The narrative step goes through your Claude Code
subscription auth -- no separate Anthropic API key needed.

## Running

```bash
# Auto-sources purple-agent/.lab-state (if lab-up.sh has run). Prefers
# VICTIM_PRIVATE (VPC) over the public VICTIM_IP automatically.
./agent-orange/run.sh

# Explicit args (no .lab-state needed)
./agent-orange/run.sh \
  --attacker-ip A.B.C.D --sensor-ip E.F.G.H \
  --victim-ip 10.0.1.5  --key path/to/.lab-key

# Run a subset by name or by MITRE technique
./agent-orange/run.sh --only art-masscan-syn-burst,art-tor-bootstrap
./agent-orange/run.sh --only-mitre T1046,T1090.003

# Skip the Anthropic narrative (faster, no API key needed)
./agent-orange/run.sh --no-llm

# Suppress auto-opening the HTML report in a browser
./agent-orange/run.sh --no-open
```

The narrative step uses `claude-agent-sdk`, which authenticates via
your Claude Code subscription (same path purple-agent uses). If the
`claude` CLI works on your machine, the narrative step will too. Use
`--no-llm` to skip it entirely; the ledger + report still render,
just without the LLM-generated prose sections.

## What it produces

Every run emits three artifacts under
`agent-orange/runs/<run_id>/`:

| File | Purpose |
|---|---|
| `ledger.json` | Structured source of truth. Every verdict, every attributed alert/notice, ruleset snapshot + drift, LLM narrative. Machine-readable. |
| `report.html` | Self-contained HTML (no external assets). Auto-opens in the default browser unless `--no-open` or `PURPLE_AGENT_NO_OPEN=1`. |
| `report.md` | Terminal / git / wiki-friendly rendering of the same content. |

Plus `runs/index.json` — an ordered list of every run's summary,
used for drift comparison.

## What it does (pipeline)

```
1. Load attacks.yaml, apply --only / --only-mitre filters.
2. SSH to sensor: capture baseline line counts for eve.json + the
   core Zeek logs (notice, weird, intel, conn).
3. SSH to sensor: snapshot enabled Suricata SIDs.
4. For each attack (strictly sequential):
     - substitute {{VICTIM_IP}} in command + target
     - record probe_start_ts
     - SSH to attacker, execute the attack command
     - record probe_end_ts, classify RAN/FAILED
5. SSH to sensor ONCE: harvest everything — eve.json forward from
   baseline, all Zeek protocol logs (http, ssh, ssl, dns, ftp, smtp,
   files, software, snmp, x509, tunnel, dce_rpc, smb_*, kerberos)
   plus diagnostic pair (loaded_scripts, stats).
6. Attribute evidence to each attack by time window + destination
   match. Classify verdict by pure set operations.
7. Load prior run's ledger (if runs/index.json has one) for drift
   comparison.
8. LLM narrative call: one Anthropic SDK request with the ledger +
   prior run. Skip if --no-llm. Falls back gracefully on failure.
9. Render JSON + HTML + MD. Update runs/index.json. Open HTML.
```

Three SSH calls to sensor total (baseline, ruleset snapshot, harvest).
**Zero during the attack loop.** Attribution happens entirely after
the run — no per-attack sensor queries, so Zeek's bucket-flush
behavior can't cause false UNDETECTED results.

## Verdicts

| Verdict | Condition |
|---|---|
| `DETECTED_EXPECTED` | Every `expected_sid` and `expected_zeek_notice` fired with correct attribution |
| `DETECTED_PARTIAL` | Some but not all expected signals fired |
| `DETECTED_UNEXPECTED` | No expected signal fired, but another SID or Zeek notice did (attributable) |
| `UNDETECTED` | Nothing attributable fired |
| `FAILED` | Attack command itself failed (SSH error, timeout, tool missing) — emitted by runner, not the classifier |

**`OBSERVED` is not a verdict.** Protocol-log evidence (User-Agent in
`software.log`, auth failure in `ftp.log`, SNI in `ssl.log`) is
captured and reported alongside the verdict, but never inflates the
detection count.

## Comparing with purple-agent

Run both agents against the same lab with the same probe / attack set
and compare the resulting verdicts. Where they agree, trust grows.
Where they disagree, investigate — often Agent Orange is right because
its attribution window is wider and doesn't race Zeek's flush cycle.

## Tests

```bash
cd agent-orange
pytest -q
```

Suite is fixture-driven; no lab required. 200+ cases covering catalog
validation, attribution boundary math, verdict set operations, SSH
harvest parsing, runner status classification, ruleset drift math,
ledger helpers, JSON/HTML/Markdown rendering, narrative LLM
integration (with fake client), and cross-module integration.

## Known limitations

- **Hourly Zeek log rotation.** A run that crosses the `:00`
  boundary reads baseline line counts against a freshly rotated log
  and can miss pre-rotation events. Stay within one hour until
  rotation detection lands.
- **IP-range attribution.** Attacks targeting a pool of destination
  IPs (e.g., Tor DA IPs) without SNI context are not fully attributed
  under the current model — SNI-based attribution still works for
  most TLS events. Known follow-up.
- **LLM narrative needs the `claude` CLI available + network.** Use
  `--no-llm` if you only need the deterministic ledger.
