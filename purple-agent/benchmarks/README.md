# Speed-Test Harness — 10-probe ART benchmark

Reproducible wall-clock benchmark for the purple-agent. Run the same 10
probes the same way every time so optimizations can be measured instead
of guessed at.

## Why this exists

A typical run today is ~15 min for 15 probes (~60s/probe). Before we
optimize, we need a "before" number. This harness pins the probe set and
emits a comparable JSON so any change (SSH multiplexing, prompt caching,
parallel probes, etc.) can be measured against the same yardstick.

## The 10 probes (pinned)

`probes-perf10.yaml` contains a frozen copy of 10 ART probes spanning 10
distinct MITRE techniques. Order is intentional:

| # | Probe | Technique | Surface |
|---|-------|-----------|---------|
| 1 | art-masscan-syn-burst | T1046 | Suricata stream/flow |
| 2 | art-gobuster-dvwa-dir-enum | T1595.003 | HTTP UA + 404 burst |
| 3 | art-wget-post-https-exfil | T1048.002 | TLS JA3 + SNI |
| 4 | art-icmpdoor-c2 | T1095 | Zeek weird / ICMP |
| 5 | art-socat-tls-reverse-shell | T1059.004 | TLS JA3 reverse shell |
| 6 | art-cloudflared-tunnel | T1572 | SNI + ephemeral cert |
| 7 | art-rclone-s3-sni | T1567.002 | UA + SaaS SNI |
| 8 | art-hydra-ftp-brute | T1110.001 | FTP auth failure burst |
| 9 | art-slowhttptest-slowloris | T1499.002 | Long-lived HTTP conns |
| 10 | art-tor-bootstrap | T1090.003 | Tor DA SNI + ET intel |

Keep this list frozen once a baseline is captured. If the main
`probes.yaml` evolves, that's fine — the benchmark stays stable because
it reads from this local copy.

## How to run

```bash
# With the lab up (lab-up.sh has written .lab-state):
./benchmarks/speedtest.sh

# Or pass IPs/key explicitly:
./benchmarks/speedtest.sh \
  --attacker-ip A.B.C.D \
  --sensor-ip   E.F.G.H \
  --victim-ip   10.0.1.5 \
  --key         .lab-key
```

The script invokes `purple_agent.py` with:

- `--probe-pool benchmarks/probes-perf10.yaml`
- `--max-attacks 10 --budget 30 --no-sweep`
- A `--focus` directive instructing the LLM to run the probes in the
  order listed, exactly once each.

On exit it runs `summarize.py` which writes
`benchmarks/results/benchmark-<ts>.json` and prints a one-screen summary.

## What gets measured

From the `ts` field in `reports/findings-<ts>.jsonl`, per-probe duration
= `ts[N+1] - ts[N]` (last probe uses wall-clock end). This bundles SSH,
LLM, and probe-exec time — it's enough to spot "which probe got slower"
and "did the total drop" run over run. A future follow-up can add active
phase-level instrumentation inside `purple_agent.py`.

Output JSON schema (trimmed):

```json
{
  "run_id": "20260423T120000Z",
  "total_seconds": 890,
  "probes_expected": 10,
  "probes_run": 10,
  "order_honored": true,
  "expected_order": ["art-masscan-syn-burst", ...],
  "actual_order":   ["art-masscan-syn-burst", ...],
  "per_probe": [
    {"order": 1, "actual": "art-masscan-syn-burst",
     "inferred_duration_s": 42.1, "verdict": "DETECTED", ...}
  ],
  "detection_summary": {"detected": 6, "undetected": 4, "coverage_pct": 60.0},
  "accuracy": {"overclaim_count": 0, "structural_issues_count": 0, ...}
}
```

## Capturing a baseline

After the first clean run (all 10 probes ran, `order_honored == true`):

```bash
cp benchmarks/results/benchmark-<ts>.json benchmarks/baseline.json
git add benchmarks/baseline.json && git commit -m "benchmark: capture baseline"
```

Now `baseline.json` is the "before" number. Compare any future run
against it:

```bash
python -c "
import json, sys
a = json.load(open('benchmarks/baseline.json'))
b = json.load(open(sys.argv[1]))
print(f'baseline: {a[\"total_seconds\"]}s  new: {b[\"total_seconds\"]}s')
print(f'delta:    {b[\"total_seconds\"] - a[\"total_seconds\"]:+d}s')
" benchmarks/results/benchmark-<newts>.json
```

## Determinism — caveats

Probe order is not enforced by code today — the LLM is told to follow
the pool order via `--focus`. If `order_honored` reports `false` across
multiple runs, the benchmark isn't comparable and two follow-ups become
relevant:

1. Re-run to confirm it's not a one-off.
2. Add a `--deterministic-order` CLI flag to `purple_agent.py` that
   injects sequential probe picking directly in the kickoff prompt.

Variance under ~10-15% is expected (LLM sampling, network jitter).
Larger variance is a signal to investigate before declaring a win.

## Tests

Pure-function coverage of `summarize.py` lives in
`tests/test_benchmarks_summarize.py`. Run:

```bash
cd purple-agent && pytest tests/test_benchmarks_summarize.py -q
```

No lab or agent run needed — these are fixture-driven.
