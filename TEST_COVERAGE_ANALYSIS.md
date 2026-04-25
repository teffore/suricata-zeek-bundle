# Test coverage analysis & proposed improvements

## What's tested today

The Python package `agent-orange/agent_orange_pkg/` is well-covered by 366
pytest cases (361 pass, 5 skip). Running `pytest --cov` against it produces:

```
agent_orange_pkg/__init__.py        100%
agent_orange_pkg/attribution.py      99%
agent_orange_pkg/catalog.py          90%
agent_orange_pkg/harvest.py          95%
agent_orange_pkg/ledger.py          100%
agent_orange_pkg/narrative.py        89%
agent_orange_pkg/render.py           85%
agent_orange_pkg/ruleset.py          93%
agent_orange_pkg/runner.py          100%
agent_orange_pkg/verdict.py         100%
TOTAL (package only)                 91%
```

`tests/test_integration.py` exercises the catalog → runner → harvest →
attribution → verdict pipeline jointly with fakes for SSH.

## Where the coverage gaps are

### 1. `agent-orange/run.py` — 0% covered (0 / 206 statements)

This is the entry point that wires the entire pipeline together, and it has
**no tests at all**. The package modules it composes are well-tested, but the
composition itself is not. Untested logic includes:

- `filter_attacks` (`run.py:149`) — the `--only` / `--only-mitre` filter logic.
- `build_ledger` (`run.py:167`) — the function that produces every artifact
  the rest of the system consumes. It owns the FAILED-attack exclusion
  rule, the cross-stream `flow_owners` precomputation (a regression-prone
  area called out by the inline comments), and the
  Zeek-intel-as-notice merge.
- `load_prior_ledger` / `_stub_prior_ledger` (`run.py:295`, `326`) — silent
  fallback paths used for drift comparison. The `except Exception: return None`
  at line 407 is marked `pragma: no cover` and means the stub builder can fail
  without anyone noticing.
- `update_runs_index` (`run.py:411`) — JSON index appender; behavior on
  non-list / corrupt index is untested.
- `parse_args` (`run.py:436`) — argparse plumbing; no test asserts the flags
  it advertises.
- `main` (`run.py:462`) — orchestration, including the
  `last_probe_end + DEFAULT_GRACE_SECONDS + 1.0` flush-wait, the empty-`attacks`
  early-return-2, and the `--no-llm` branch.

**Proposal:** add `tests/test_run.py` covering at minimum:
- `filter_attacks` with empty / unknown / mixed name+mitre filters.
- `build_ledger` end-to-end with a synthetic `SensorHarvest` containing
  alerts AND notices on a shared `community_id`, asserting that
  attribution does not split that flow's evidence (the
  whois-tunnel/icmpdoor-c2 regression noted at `run.py:215`).
- `load_prior_ledger` against missing / malformed / valid `runs/index.json`.
- `update_runs_index` round-trip with no existing file, valid file,
  corrupted file.
- `main` smoke test with all SSH/LLM dependencies injected via monkeypatch
  (`build_sensor_runner`, `build_attacker_runner`, `generate_narrative`,
  `webbrowser.open`) and a fake `attacks.yaml`, asserting exit code 0,
  artifact files written, `--no-llm` honored.

### 2. Custom Zeek scripts — entirely untested

`zeek/site/purple-ras-intel.zeek`, `purple-ssh-asymmetry.zeek`, and
`purple-ua-diversity.zeek` have **no automated test of any kind**, and worse,
none of the notice types they emit (`Remote_Access_Software_SNI`,
`SSH_Bulk_Exfil_Candidate`, `UA_Diversity_Spike`) appears in
`testing/probe_catalog.json` or `agent-orange/attacks.yaml` as an
`expected_zeek_notice`. They are silent passengers — broken scripts would not
fail the detection workflow.

**Proposal:**
- Add `btest`-style trace-driven tests under `zeek/tests/`. For each script:
  feed a small pcap (or scripted event) and assert the expected notice fires
  with the right `$identifier` / suppression. Run via
  `zeek -r trace.pcap zeek/site/purple-ssh-asymmetry.zeek` in a CI step and
  grep `notice.log`.
- Wire each notice type into a scenario in `probe_catalog.json` and an attack
  in `attacks.yaml` so the live detection workflow asserts on them.

### 3. Pytest is never run in CI

Three workflows live under `.github/workflows/`
(`validate-detections.yml`, `validate-shipping.yml`,
`validate-standalone.yml`) and none of them invoke pytest, ruff, mypy,
shellcheck, or actionlint. The 360+ Python tests only protect a developer
who remembers to run them locally.

**Proposal:** add a fast `validate-unit.yml` (no AWS, no OIDC) that:
- Sets up Python 3.11.
- Installs `agent-orange/requirements.txt` + pytest + pytest-cov.
- Runs `pytest agent-orange/tests --cov=agent_orange_pkg --cov-fail-under=85`.
- Runs `shellcheck` over `*.sh`.
- Runs `actionlint` over `.github/workflows/*.yml`.

This gates every PR for ~30 seconds at zero AWS cost, and the cloud workflows
stop being the only signal.

### 4. Shell scripts (≈3,500 lines) have no tests

`standalone.sh` (1,383 LoC), `testing/run_attacks.sh` (1,267),
`testing/verify_alerts.sh` (244), `lab-up.sh` (324), `lab-down.sh` (110),
`testing/attacker_setup.sh` (252), `testing/victim_setup.sh` (218), and the
four `testing/shipping/*.sh` scripts have **no static or unit test
coverage** — not even shellcheck.

`verify_alerts.sh` is particularly load-bearing: it owns the coverage gate
that gates the detections workflow, and its `jq` join (lines 168–195) is
the most fragile piece of logic in the whole repo. A typo in the join keys
silently produces 100% miss.

**Proposal:**
- **shellcheck** every `*.sh` in CI (catches unquoted vars, missing
  fallthrough, etc).
- **bats**-style tests for the join logic in `verify_alerts.sh`: feed a
  fixture `eve.json` + `notice.log` + `probe_catalog.json` and assert
  `coverage.json` matches the expected per-scenario PASS/MISS list.
- Extract pure helper functions out of `standalone.sh`
  (`detect_iface`, `extract_custom_rules`, `wait_for_apt_lock`,
  `apt_update_noninteractive`) into a sourceable `lib/` file so they can
  be unit-tested via bats.

### 5. Catalog drift between probe_catalog.json and attacks.yaml

Both `testing/probe_catalog.json` and `agent-orange/attacks.yaml` declare
`expected_suricata_sids` for overlapping scenarios, but **no test asserts
they agree**. They can drift silently — a SID renamed in `standalone.sh`'s
custom rules might be updated in only one of the two catalogs and the run
would still pass on the other path.

**Proposal:** add a parametrized test that:
1. Loads both catalogs and the `9000xxx` SIDs declared by
   `standalone.sh`'s `extract_custom_rules` block.
2. Asserts each `expected_suricata_sids` SID actually exists in
   `standalone.sh`'s rule SID set.
3. For each attack name that appears in both catalogs, asserts the SID
   sets are equal (or one is documented to be a strict subset).

### 6. Smaller gaps inside the agent-orange package

Worth filling, in priority order:

- **`render.py` — fallback rendering paths (lines 547–568, 813–833).** The
  "no narrative available, but evidence exists" branch is reached by both
  the markdown and HTML renderers and is currently untested. A user runs
  with `--no-llm` exactly when the LLM is broken; the renderer must not
  also be broken in that path.
- **`render.py` — stdout summary tail (lines 813–831, 837–844, 850–851,
  858–859, 930).** Easy to add: assert specific substrings in the output of
  `render_stdout_summary` for ledgers with mixed verdicts, no narrative,
  drift present/absent.
- **`narrative.py` — `_extract_json_object` edges.** No test for "no `{`
  at all", "unbalanced braces", "JSON inside a string with escaped quotes
  containing `}`". The brace-counter is hand-rolled and is the kind of code
  fuzzing finds bugs in fast.
- **`catalog.py` — `_parse_target` (lines 205, 208, 246, 249–253).**
  Target-not-mapping, target-missing-fields, and the `_parse_int_list` /
  `_parse_str_list` rejection edges have no test.
- **`harvest.py` — `_resolve_dest_ip` for `software.log` non-string,
  `files.log` empty `rx_hosts` (lines 251–254).** Already comments call out
  past reviewer catches; lock those down.
- **`ruleset.py` — `parse_sids` freeform-fallback `ValueError` paths
  (lines 119–120, 125–126).** Low-effort, exercises the regex branch.

### 7. SSH runner wrappers (`run.py:73–142`)

`build_sensor_runner`, `build_attacker_runner`, and `_ssh_base` are pure
subprocess wrappers but contain real logic: timeout-to-rc translation,
`StrictHostKeyChecking=no`, `BatchMode=yes`. None of it is tested.

**Proposal:** monkeypatch `subprocess.run` and assert the constructed
argv list, plus that a `subprocess.TimeoutExpired` is converted to
`(stdout, stderr, non-zero rc)` rather than propagating.

---

## Recommended order of work

1. **Wire pytest into CI** (highest ROI, ~30 min). Without this, every
   improvement below is invisible to PRs.
2. **Add `tests/test_run.py`** covering `build_ledger`, `filter_attacks`,
   `load_prior_ledger`, `update_runs_index`, and a fully-mocked `main`.
3. **Catalog-consistency test** — small, prevents an entire class of
   silent regressions across `attacks.yaml` ↔ `probe_catalog.json` ↔
   `standalone.sh` rule SIDs.
4. **shellcheck + actionlint** in CI.
5. **Zeek script tests** (`btest` or pcap-driven), plus folding their
   notice types into the existing detection catalogs so the live workflow
   asserts on them.
6. **bats tests for `verify_alerts.sh`**, focused on the `jq` join.
7. Fill the remaining `render.py` / `narrative.py` / `catalog.py` /
   `harvest.py` branch gaps to push package coverage from 91% → 97%+.
