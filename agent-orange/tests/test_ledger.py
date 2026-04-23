"""Unit tests for agent_orange_pkg.ledger."""

from __future__ import annotations

from agent_orange_pkg.ledger import Narrative, RunLedger
from agent_orange_pkg.ruleset import RulesetDrift
from tests._ledger_fixtures import (
    make_attack, make_entry, make_ledger, make_narrative,
)


class TestVerdictCounts:
    def test_counts_by_verdict(self):
        ledger = make_ledger(entries=[
            make_entry(make_attack("a"), verdict="DETECTED_EXPECTED"),
            make_entry(make_attack("b"), verdict="DETECTED_PARTIAL"),
            make_entry(make_attack("c"), verdict="UNDETECTED"),
            make_entry(make_attack("d"), verdict="UNDETECTED"),
            make_entry(make_attack("e"), verdict="FAILED"),
        ])
        assert ledger.verdict_counts() == {
            "DETECTED_EXPECTED": 1,
            "DETECTED_PARTIAL": 1,
            "UNDETECTED": 2,
            "FAILED": 1,
        }


class TestDetectedCount:
    def test_all_detected_tiers_count(self):
        ledger = make_ledger(entries=[
            make_entry(make_attack("a"), verdict="DETECTED_EXPECTED"),
            make_entry(make_attack("b"), verdict="DETECTED_PARTIAL"),
            make_entry(make_attack("c"), verdict="DETECTED_UNEXPECTED"),
            make_entry(make_attack("d"), verdict="UNDETECTED"),
            make_entry(make_attack("e"), verdict="FAILED"),
        ])
        assert ledger.detected_count() == 3  # three DETECTED_* verdicts

    def test_no_detections(self):
        ledger = make_ledger(entries=[
            make_entry(make_attack("a"), verdict="UNDETECTED"),
            make_entry(make_attack("b"), verdict="FAILED"),
        ])
        assert ledger.detected_count() == 0


class TestCoveragePct:
    def test_coverage_computation(self):
        ledger = make_ledger(entries=[
            make_entry(make_attack("a"), verdict="DETECTED_EXPECTED"),
            make_entry(make_attack("b"), verdict="UNDETECTED"),
            make_entry(make_attack("c"), verdict="UNDETECTED"),
            make_entry(make_attack("d"), verdict="UNDETECTED"),
        ])
        assert ledger.coverage_pct() == 25.0

    def test_empty_ledger_zero_coverage(self):
        ledger = make_ledger(entries=[])
        assert ledger.coverage_pct() == 0.0


class TestTotalSeconds:
    def test_elapsed_int(self):
        ledger = make_ledger(started_at=100.0, ended_at=450.7)
        assert ledger.total_seconds() == 350

    def test_negative_clamped_to_zero(self):
        # Clock skew shouldn't produce negative totals.
        ledger = make_ledger(started_at=200.0, ended_at=100.0)
        assert ledger.total_seconds() == 0


class TestNarrativeShapes:
    def test_available_narrative_round_trips(self):
        n = make_narrative(
            available=True,
            exec_summary="hello world",
            per_attack_commentary={"a": "nope"},
            remediation_suggestions={"a": "alert ..."},
            drift_commentary="no prior",
        )
        assert n.available is True
        assert n.exec_summary == "hello world"
        assert n.per_attack_commentary == {"a": "nope"}

    def test_unavailable_narrative_has_error(self):
        n = make_narrative(available=False, error="api key missing")
        assert n.available is False
        assert n.error == "api key missing"
        assert n.exec_summary == ""
        assert n.per_attack_commentary == {}
