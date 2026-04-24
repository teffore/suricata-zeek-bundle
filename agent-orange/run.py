#!/usr/bin/env python3
"""run.py -- Agent Orange entry point.

Wires together the deterministic pipeline (catalog -> runner -> harvest
-> attribution -> verdict) and the end-of-run narrative layer (LLM),
producing the three output artifacts (JSON / HTML / MD) under
agent-orange/runs/<run_id>/.

Invocation is via run.sh which auto-sources .lab-state; direct use:

    python run.py \\
        --attacker-ip A --sensor-ip S --victim-ip V --key path/to/key \\
        [--only art-masscan-syn-burst,art-tor-bootstrap] \\
        [--only-mitre T1046,T1090.003] \\
        [--no-llm] \\
        [--attacks-yaml path/to/attacks.yaml]

Behavior:
  - sensor + attacker contacted via ssh (subprocess; no paramiko dep)
  - attacks run strictly sequentially
  - three sensor SSH calls total: baseline + ruleset snapshot at start,
    harvest at end. Zero during the attack loop, so Zeek flush timing
    can't race the verdict.
  - drift computed vs. most recent prior run if runs/index.json exists
  - LLM narrative unless --no-llm; failure falls back gracefully
  - auto-opens the HTML report unless AGENT_ORANGE_NO_OPEN=1 in env
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent_orange_pkg import __version__ as AO_VERSION
from agent_orange_pkg.attribution import AttackWindow, attribute_all
from agent_orange_pkg.catalog import Attack, load_attacks_yaml
from agent_orange_pkg.harvest import (
    SensorHarvest, capture_baseline, harvest,
)
from agent_orange_pkg.ledger import (
    AttackLedgerEntry, Narrative, RunLedger,
)
from agent_orange_pkg.narrative import generate_narrative
from agent_orange_pkg.render import (
    render_stdout_summary, write_html, write_json, write_markdown,
)
from agent_orange_pkg.ruleset import (
    RulesetDrift, RulesetSnapshot, compute_drift, snapshot_ruleset,
)
from agent_orange_pkg.runner import AttackResult, run_attack
from agent_orange_pkg.verdict import classify


SCRIPT_DIR = Path(__file__).parent.resolve()
DEFAULT_ATTACKS_YAML = SCRIPT_DIR / "attacks.yaml"
RUNS_DIR = SCRIPT_DIR / "runs"


# ---------------------------------------------------------------------------
#  SSH runners (real)
# ---------------------------------------------------------------------------

def build_sensor_runner(sensor_ip: str, key: str):
    """Return an ssh_runner callable that targets the sensor box (ubuntu@).

    Signature: (command: str) -> (stdout, stderr, rc). Matches the
    harvest.SshRunner protocol exactly.

    SSH-transport failures (timeout, connection refused, missing key)
    are converted to a non-zero rc + populated stderr so callers'
    HarvestError / RulesetError branches surface a readable message
    instead of an uncaught subprocess exception mid-run.
    """
    base = _ssh_base(key, "ubuntu", sensor_ip)

    def runner(command: str) -> tuple[str, str, int]:
        try:
            result = subprocess.run(
                base + [command],
                capture_output=True, text=True, timeout=300,
            )
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired as exc:
            return (exc.stdout or "", f"ssh timeout after 300s: {exc}", 124)
        except OSError as exc:
            return ("", f"ssh transport error: {exc}", 255)
    return runner


def build_attacker_runner(attacker_ip: str, key: str):
    """Return an attacker_runner callable for runner.run_attacks.

    Signature: (command: str, timeout: int) -> AttackResult.
    """
    base = _ssh_base(key, "kali", attacker_ip)

    def runner(command: str, timeout: int) -> AttackResult:
        try:
            result = subprocess.run(
                base + [command],
                capture_output=True, text=True, timeout=timeout,
            )
            return AttackResult(
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.returncode,
            )
        except subprocess.TimeoutExpired as exc:
            return AttackResult(
                stdout=exc.stdout or "",
                stderr=exc.stderr or "",
                exit_code=124,
                timed_out=True,
            )
        except OSError as exc:
            return AttackResult(
                stdout="", stderr=str(exc), exit_code=-1,
                ssh_error=str(exc),
            )
    return runner


def _ssh_base(key: str, user: str, host: str) -> list[str]:
    return [
        "ssh",
        "-i", key,
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10",
        "-o", "BatchMode=yes",
        f"{user}@{host}",
    ]


# ---------------------------------------------------------------------------
#  Attack filtering
# ---------------------------------------------------------------------------

def filter_attacks(
    attacks: list[Attack],
    only_names: set[str] | None,
    only_mitre: set[str] | None,
) -> list[Attack]:
    """Apply optional --only / --only-mitre filters in place-preserving order."""
    out = attacks
    if only_names:
        out = [a for a in out if a.name in only_names]
    if only_mitre:
        out = [a for a in out if a.mitre in only_mitre]
    return out


# ---------------------------------------------------------------------------
#  Run assembly
# ---------------------------------------------------------------------------

def build_ledger(
    *,
    run_id: str,
    started_at: float,
    victim_ip: str,
    sensor_host: str,
    attacker_host: str,
    attacks: list[Attack],
    runs,  # list[AttackRun] -- imported for types only
    harvest_result: SensorHarvest,
    ruleset_snapshot: RulesetSnapshot,
    ruleset_drift: RulesetDrift | None,
    narrative: Narrative,
    attacks_yaml_path: str,
) -> RunLedger:
    """Attribute + classify every attack, package into a RunLedger.

    Pure-ish: no I/O, assembles the ledger from already-collected data.
    """
    entries: list[AttackLedgerEntry] = []

    protocol_logs_by_name = harvest_result.zeek_protocol_logs

    # Build one AttackWindow per RAN attack. FAILED attacks are excluded
    # from attribution: they produced no traffic, so any events landing
    # in their original time slot belong to a temporally-adjacent RAN
    # attack (attribute_all's first-match sort will assign them there).
    windows = [
        AttackWindow(
            name=attack.name,
            start_ts=run.probe_start_ts,
            end_ts=run.probe_end_ts,
            target_type=run.target.type,
            target_value=run.target.value,
        )
        for attack, run in zip(attacks, runs)
        if run.status != "FAILED"
    ]

    # Exclusive attribution across the whole run: each event is assigned
    # to at most one attack (first-match by start_ts + target). Prevents
    # the "same SID attributed to 8 attacks" bleed when many attacks all
    # target the same victim IP.
    alerts_by_attack = attribute_all(harvest_result.suricata_alerts, windows)
    notices_by_attack = attribute_all(harvest_result.zeek_notices, windows)
    # Intel hits are Zeek-side detection signals equivalent to notices.
    intel_by_attack = attribute_all(harvest_result.zeek_intel, windows)
    observed_by_log = {
        logname: attribute_all(events, windows)
        for logname, events in protocol_logs_by_name.items()
    }

    for attack, run in zip(attacks, runs):
        if run.status == "FAILED":
            entries.append(AttackLedgerEntry(
                attack=attack, run=run, verdict="FAILED",
                attributed_alerts=(), attributed_notices=(),
                observed_evidence={},
            ))
            continue

        alerts = tuple(alerts_by_attack.get(attack.name, []))
        notices = tuple(notices_by_attack.get(attack.name, []))
        intel = tuple(intel_by_attack.get(attack.name, []))
        notices = notices + intel

        observed: dict[str, tuple[dict[str, Any], ...]] = {}
        for logname, by_attack in observed_by_log.items():
            filtered = tuple(by_attack.get(attack.name, []))
            if filtered:
                observed[logname] = filtered

        verdict = classify(
            alerts=list(alerts),
            notices=list(notices),
            expected_sids=attack.expected_sids,
            expected_zeek_notices=attack.expected_zeek_notices,
        )
        entries.append(AttackLedgerEntry(
            attack=attack, run=run, verdict=verdict,
            attributed_alerts=alerts, attributed_notices=notices,
            observed_evidence=observed,
        ))

    ended_at = datetime.now(timezone.utc).timestamp()
    return RunLedger(
        run_id=run_id,
        started_at=started_at,
        ended_at=ended_at,
        victim_ip=victim_ip,
        sensor_host=sensor_host,
        attacker_host=attacker_host,
        attacks=tuple(entries),
        ruleset_snapshot=ruleset_snapshot,
        ruleset_drift=ruleset_drift,
        zeek_loaded_scripts=harvest_result.zeek_loaded_scripts,
        zeek_stats=harvest_result.zeek_stats,
        narrative=narrative,
        agent_orange_version=AO_VERSION,
        attacks_yaml_path=attacks_yaml_path,
    )


# ---------------------------------------------------------------------------
#  Runs index (for drift comparison)
# ---------------------------------------------------------------------------

def load_prior_ledger(runs_dir: Path) -> RunLedger | None:
    """Return the most recent prior run's ledger, or None if none exist.

    Loads from runs/<ts>/ledger.json. Returns None on parse failure
    rather than raising -- drift is nice-to-have, not load-bearing.
    """
    index_path = runs_dir / "index.json"
    if not index_path.exists():
        return None
    try:
        entries = json.loads(index_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(entries, list) or not entries:
        return None
    latest = entries[-1]
    ledger_path = runs_dir / latest.get("run_id", "") / "ledger.json"
    if not ledger_path.exists():
        return None
    # We intentionally do NOT re-hydrate the full RunLedger (dataclass
    # round-trip would be fragile). For drift purposes, narrative only
    # needs verdict_counts and per-attack verdicts, which we read from
    # the JSON directly. Return a stub RunLedger with only those fields
    # meaningfully populated.
    try:
        raw = json.loads(ledger_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    return _stub_prior_ledger(raw)


def _stub_prior_ledger(raw: dict[str, Any]) -> RunLedger | None:
    """Build a best-effort RunLedger stub from a raw ledger.json.

    Only the fields narrative.py reads are populated correctly (run_id,
    attacks[].attack.name, attacks[].verdict, ruleset_snapshot
    enabled_sid count). Everything else is a placeholder. The stub is
    never rendered, only consumed by narrative.py for drift comparison.
    """
    try:
        attacks_raw = raw.get("attacks") or []
        # Building a full AttackLedgerEntry stub is painful; instead we
        # pass compact_prior_verdicts dict via a lightweight shim.
        # Import types late to avoid circularity.
        from agent_orange_pkg.catalog import Attack, Target
        from agent_orange_pkg.runner import AttackRun

        stub_entries: list[AttackLedgerEntry] = []
        for a in attacks_raw:
            attack_meta = a.get("attack") or {}
            run_meta = a.get("run") or {}
            stub_entries.append(AttackLedgerEntry(
                attack=Attack(
                    name=attack_meta.get("name", "<unknown>"),
                    mitre=attack_meta.get("mitre", ""),
                    source=attack_meta.get("source", "atomic-red-team"),
                    art_test=attack_meta.get("art_test", ""),
                    rationale=attack_meta.get("rationale", ""),
                    target=Target(
                        type=(attack_meta.get("target") or {}).get("type", "victim"),
                        value=(attack_meta.get("target") or {}).get("value", ""),
                    ),
                    expected_sids=tuple(attack_meta.get("expected_sids", ())),
                    expected_zeek_notices=tuple(
                        attack_meta.get("expected_zeek_notices", ())
                    ),
                    expected_verdict=attack_meta.get("expected_verdict", "UNDETECTED"),
                    command=attack_meta.get("command", ""),
                    timeout=attack_meta.get("timeout", 45),
                ),
                run=AttackRun(
                    attack_name=attack_meta.get("name", "<unknown>"),
                    mitre=attack_meta.get("mitre", ""),
                    art_test=attack_meta.get("art_test", ""),
                    target=Target(type="victim", value=""),
                    substituted_command="",
                    probe_start_ts=0.0, probe_end_ts=0.0,
                    status=run_meta.get("status", "RAN"),
                    exit_code=run_meta.get("exit_code"),
                    stdout="", stderr="", error="", timed_out=False,
                ),
                verdict=a.get("verdict", "UNDETECTED"),
                attributed_alerts=(), attributed_notices=(), observed_evidence={},
            ))

        from agent_orange_pkg.ruleset import RulesetSnapshot
        snap_raw = raw.get("ruleset_snapshot") or {}
        snap = RulesetSnapshot(
            enabled_sids=frozenset(snap_raw.get("enabled_sids") or ()),
            hash=snap_raw.get("hash", ""),
            captured_at=snap_raw.get("captured_at", 0.0),
        )
        return RunLedger(
            run_id=raw.get("run_id", ""),
            started_at=raw.get("started_at", 0.0),
            ended_at=raw.get("ended_at", 0.0),
            victim_ip=raw.get("victim_ip", ""),
            sensor_host=raw.get("sensor_host", ""),
            attacker_host=raw.get("attacker_host", ""),
            attacks=tuple(stub_entries),
            ruleset_snapshot=snap,
            ruleset_drift=None,
            zeek_loaded_scripts="",
            zeek_stats="",
            narrative=Narrative(
                available=False, exec_summary="", per_attack_commentary={},
                remediation_suggestions={}, drift_commentary="",
                generated_at=0.0, model="", error="prior run stub",
            ),
            agent_orange_version=raw.get("agent_orange_version", ""),
            attacks_yaml_path=raw.get("attacks_yaml_path", ""),
        )
    except Exception:  # pragma: no cover
        return None


def update_runs_index(runs_dir: Path, ledger: RunLedger) -> None:
    """Append this run to runs/index.json (ordered, oldest first)."""
    index_path = runs_dir / "index.json"
    entries: list[dict[str, Any]] = []
    if index_path.exists():
        try:
            entries = json.loads(index_path.read_text(encoding="utf-8"))
            if not isinstance(entries, list):
                entries = []
        except json.JSONDecodeError:
            entries = []
    entries.append({
        "run_id": ledger.run_id,
        "started_at": ledger.started_at,
        "total_seconds": ledger.total_seconds(),
        "coverage_pct": ledger.coverage_pct(),
        "verdict_counts": ledger.verdict_counts(),
    })
    index_path.write_text(json.dumps(entries, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
#  CLI
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Agent Orange -- deterministic ART runner.",
    )
    p.add_argument("--attacker-ip", required=True)
    p.add_argument("--sensor-ip", required=True)
    p.add_argument("--victim-ip", required=True,
                   help="Victim PRIVATE IP (VPC). Public IPs fail attribution.")
    p.add_argument("--key", required=True, help="SSH private key path")
    p.add_argument("--only", default="",
                   help="Comma-separated attack names to run; others skipped")
    p.add_argument("--only-mitre", default="",
                   help="Comma-separated MITRE technique IDs (e.g. T1046,T1090)")
    p.add_argument("--no-llm", action="store_true",
                   help="Skip the Anthropic narrative call")
    p.add_argument("--attacks-yaml", default=str(DEFAULT_ATTACKS_YAML),
                   help="Path to attacks.yaml catalog")
    p.add_argument("--no-open", action="store_true",
                   help="Don't auto-open the HTML report in a browser")
    return p.parse_args(argv)


# ---------------------------------------------------------------------------
#  main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    started_at = datetime.now(timezone.utc).timestamp()

    print(f"[agent-orange] run {run_id} starting")
    print(f"[agent-orange]   attacker {args.attacker_ip}")
    print(f"[agent-orange]   sensor   {args.sensor_ip}")
    print(f"[agent-orange]   victim   {args.victim_ip}")

    attacks = load_attacks_yaml(Path(args.attacks_yaml))
    only_names = set(
        n.strip() for n in args.only.split(",") if n.strip()
    ) or None
    only_mitre = set(
        m.strip() for m in args.only_mitre.split(",") if m.strip()
    ) or None
    attacks = filter_attacks(attacks, only_names, only_mitre)
    if not attacks:
        print("[agent-orange] no attacks selected after filters; nothing to do")
        return 2

    print(f"[agent-orange] running {len(attacks)} attack(s)")

    sensor_ssh = build_sensor_runner(args.sensor_ip, args.key)
    attacker_ssh = build_attacker_runner(args.attacker_ip, args.key)

    print("[agent-orange] capturing sensor baseline...")
    baseline = capture_baseline(sensor_ssh)

    print("[agent-orange] snapshotting Suricata ruleset...")
    ruleset_snap = snapshot_ruleset(sensor_ssh)
    print(
        f"[agent-orange]   {len(ruleset_snap.enabled_sids)} enabled SIDs "
        f"(hash {ruleset_snap.hash[:12]}...)"
    )

    # Sequential attack loop with per-attack progress.
    runs = []
    for i, attack in enumerate(attacks, start=1):
        print(f"[agent-orange] [{i}/{len(attacks)}] {attack.name} ...", flush=True)
        one = run_attack(attack, args.victim_ip, attacker_ssh)
        duration = int(one.probe_end_ts - one.probe_start_ts)
        print(
            f"[agent-orange] [{i}/{len(attacks)}] {attack.name} -> "
            f"{one.status} ({duration}s)"
        )
        runs.append(one)

    print("[agent-orange] harvesting sensor logs...")
    harvest_result = harvest(sensor_ssh, baseline, run_start_ts=started_at)

    prior_ledger = load_prior_ledger(RUNS_DIR)
    drift = compute_drift(ruleset_snap, prior_ledger.ruleset_snapshot) \
        if prior_ledger else None

    # Build an un-narrated ledger first so narrative.py can read it.
    un_narrated = build_ledger(
        run_id=run_id, started_at=started_at,
        victim_ip=args.victim_ip,
        sensor_host=args.sensor_ip, attacker_host=args.attacker_ip,
        attacks=attacks, runs=runs, harvest_result=harvest_result,
        ruleset_snapshot=ruleset_snap, ruleset_drift=drift,
        narrative=Narrative(
            available=False, exec_summary="",
            per_attack_commentary={}, remediation_suggestions={},
            drift_commentary="", generated_at=0.0, model="",
            error="not yet generated",
        ),
        attacks_yaml_path=args.attacks_yaml,
    )

    if args.no_llm:
        print("[agent-orange] --no-llm: skipping narrative generation")
        narrative = Narrative(
            available=False, exec_summary="",
            per_attack_commentary={}, remediation_suggestions={},
            drift_commentary="", generated_at=0.0, model="",
            error="--no-llm flag set",
        )
    else:
        print("[agent-orange] generating LLM narrative...")
        narrative = generate_narrative(un_narrated, prior_ledger)
        if not narrative.available:
            print(
                f"[agent-orange] narrative unavailable: {narrative.error}"
            )

    final_ledger = build_ledger(
        run_id=run_id, started_at=started_at,
        victim_ip=args.victim_ip,
        sensor_host=args.sensor_ip, attacker_host=args.attacker_ip,
        attacks=attacks, runs=runs, harvest_result=harvest_result,
        ruleset_snapshot=ruleset_snap, ruleset_drift=drift,
        narrative=narrative,
        attacks_yaml_path=args.attacks_yaml,
    )

    run_dir = RUNS_DIR / run_id
    write_json(final_ledger, run_dir / "ledger.json")
    write_markdown(final_ledger, run_dir / "report.md")
    write_html(final_ledger, run_dir / "report.html")
    update_runs_index(RUNS_DIR, final_ledger)

    print()
    print(render_stdout_summary(final_ledger))
    print()
    print(f"[agent-orange] artifacts: {run_dir}")

    if not args.no_open and os.environ.get("AGENT_ORANGE_NO_OPEN") != "1":
        try:
            webbrowser.open((run_dir / "report.html").as_uri())
        except Exception:  # pragma: no cover
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
