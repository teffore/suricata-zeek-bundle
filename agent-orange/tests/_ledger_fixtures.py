"""Shared test fixtures for building RunLedger instances.

Not named `conftest.py` because these are helpers, not pytest fixtures,
and we want them importable from any test module by name.
"""

from __future__ import annotations

from agent_orange_pkg.catalog import Attack, Target
from agent_orange_pkg.ledger import (
    AttackLedgerEntry, Narrative, RunLedger,
)
from agent_orange_pkg.ruleset import RulesetDrift, RulesetSnapshot
from agent_orange_pkg.runner import AttackRun


def make_attack(
    name: str = "art-sample",
    mitre: str = "T1046",
    expected_sids: tuple[int, ...] = (),
    expected_verdict: str = "UNDETECTED",
) -> Attack:
    return Attack(
        name=name, mitre=mitre, source="atomic-red-team",
        art_test=f"{name} test", rationale="r",
        target=Target(type="victim", value="{{VICTIM_IP}}"),
        expected_sids=expected_sids,
        expected_zeek_notices=(),
        expected_verdict=expected_verdict,
        command=f"echo {name}",
        timeout=5,
    )


def make_run(
    attack: Attack,
    *,
    status: str = "RAN",
    start: float = 100.0,
    end: float = 110.0,
) -> AttackRun:
    return AttackRun(
        attack_name=attack.name, mitre=attack.mitre, art_test=attack.art_test,
        target=Target(type="victim", value="172.31.76.116"),
        substituted_command=attack.command.replace("{{VICTIM_IP}}", "172.31.76.116"),
        probe_start_ts=start, probe_end_ts=end,
        status=status, exit_code=0 if status == "RAN" else 127,
        stdout="", stderr="",
        error="" if status == "RAN" else "non-zero exit",
        timed_out=False,
    )


def make_entry(
    attack: Attack,
    verdict: str = "UNDETECTED",
    alerts=(),
    notices=(),
    observed=None,
    *,
    status: str = "RAN",
    start: float = 100.0,
    end: float = 110.0,
) -> AttackLedgerEntry:
    return AttackLedgerEntry(
        attack=attack,
        run=make_run(attack, status=status, start=start, end=end),
        verdict=verdict,
        attributed_alerts=tuple(alerts),
        attributed_notices=tuple(notices),
        observed_evidence=observed or {},
    )


def make_narrative(available: bool = True, **overrides) -> Narrative:
    defaults = dict(
        available=available,
        exec_summary="1 attack ran; 0 detected; 0 FAILED.",
        per_attack_commentary={},
        remediation_suggestions={},
        drift_commentary="",
        generated_at=1000.0,
        model="test-model",
        error="",
    )
    defaults.update(overrides)
    if not available:
        # Force an unavailable-shape narrative.
        defaults = dict(
            available=False, exec_summary="",
            per_attack_commentary={}, remediation_suggestions={},
            drift_commentary="", generated_at=0.0, model="",
            error=overrides.get("error", "test unavailable"),
        )
    return Narrative(**defaults)


def make_ledger(
    *,
    run_id: str = "20260423T200000Z",
    entries: list[AttackLedgerEntry] | None = None,
    snapshot_sids: frozenset[int] = frozenset({2001219, 9000003}),
    drift: RulesetDrift | None = None,
    narrative: Narrative | None = None,
    started_at: float = 100.0,
    ended_at: float = 200.0,
) -> RunLedger:
    if entries is None:
        entries = [make_entry(make_attack())]
    if narrative is None:
        narrative = make_narrative()
    snap = RulesetSnapshot(
        enabled_sids=snapshot_sids,
        hash="deadbeef" * 8,
        captured_at=started_at,
    )
    return RunLedger(
        run_id=run_id,
        started_at=started_at,
        ended_at=ended_at,
        victim_ip="172.31.76.116",
        sensor_host="10.0.0.5",
        attacker_host="10.0.0.6",
        attacks=tuple(entries),
        ruleset_snapshot=snap,
        ruleset_drift=drift,
        zeek_loaded_scripts="",
        zeek_stats="",
        narrative=narrative,
        agent_orange_version="0.1.0",
        attacks_yaml_path="agent-orange/attacks.yaml",
    )
