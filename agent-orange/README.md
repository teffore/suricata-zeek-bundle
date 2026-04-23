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
  not "probe." Tightens the scope: this is for atomic red team
  simulations.

See the design spec in the plan file (and the git history of PRs
against `agent-orange/`) for the full rationale.

## Current status

**Foundation only.** This PR lands:

- `attacks.yaml` — 23 atomic red team attacks, ported from
  `purple-agent/probes.yaml` into a stricter schema.
- `agent_orange_pkg/catalog.py` — YAML loader + schema validator.
- `agent_orange_pkg/attribution.py` — pure time-window + dest-match
  filters.
- `agent_orange_pkg/verdict.py` — pure tiered classifier.
- `tests/` — pytest coverage of the three modules (plus a sanity test
  that the real `attacks.yaml` parses cleanly).

Nothing runs end-to-end yet. Upcoming PRs:

1. `harvest.py` (batch sensor query), `runner.py` (sequential SSH),
   `ruleset.py` (snapshot + drift).
2. `render.py` (JSON/HTML/MD), `narrative.py` (Anthropic SDK call),
   `run.py` + `run.sh` (wire it all up).

## Schema

```yaml
attacks:
  - name: art-masscan-syn-burst     # required, unique
    mitre: T1046                    # required
    source: atomic-red-team         # required, always this string
    art_test: "T1046 (masscan)"     # required
    rationale: "short why"          # required
    target:                         # required
      type: victim                  # victim | sni | external
      value: "{{VICTIM_IP}}"        # victim IP placeholder, SNI, or external host
    expected_sids: []               # required, int list (empty = expected UNDETECTED)
    expected_zeek_notices: []       # required, string list
    expected_verdict: UNDETECTED    # required, DETECTED_EXPECTED | UNDETECTED
    timeout: 30                     # optional, default 45
    command: |                      # required
      timeout 20 sudo masscan ...
```

Any entry missing a required field is rejected at load time with a
clear message. Duplicate names are rejected. `source` must be exactly
`"atomic-red-team"`.

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

## Tests

```bash
cd agent-orange
pytest -q
```

Pure-function coverage; no lab required.
