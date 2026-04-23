"""ledger.py -- the canonical run artifact.

Agent Orange produces exactly one RunLedger per invocation. The ledger
ties together everything the deterministic pipeline and the narrative
layer generated: per-attack verdicts with attributed evidence, the
ruleset snapshot, drift vs. prior, and the LLM narrative when present.
render.py turns a RunLedger into JSON/HTML/MD. narrative.py reads a
partial RunLedger (no narrative attached yet) + the prior run's ledger
to produce a Narrative that is then folded in.

All dataclasses are frozen -- the ledger is a record, not a mutable
accumulator. Callers build an intermediate dict during orchestration
and freeze into a RunLedger once at the end.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_orange_pkg.catalog import Attack
from agent_orange_pkg.ruleset import RulesetDrift, RulesetSnapshot
from agent_orange_pkg.runner import AttackRun


@dataclass(frozen=True)
class AttackLedgerEntry:
    """Everything known about one attack after the deterministic pipeline.

    - attack: the catalog entry (immutable; still carries raw
      {{VICTIM_IP}} placeholders for provenance).
    - run: the runner's record (substituted target + command + timings).
    - verdict: one of the VERDICT_* constants from verdict.py.
    - attributed_alerts / attributed_notices: evidence that passed
      time-window + dest-match filtering against this attack. Used to
      derive the verdict; referenced in reports.
    - observed_evidence: protocol-log events (software.log UA, ftp.log
      auth failures, ssl.log SNI hits) that attribute to this attack
      but do NOT affect the verdict. The "observed" sidebar.
    """
    attack: Attack
    run: AttackRun
    verdict: str
    attributed_alerts: tuple[dict[str, Any], ...]
    attributed_notices: tuple[dict[str, Any], ...]
    observed_evidence: dict[str, tuple[dict[str, Any], ...]]


@dataclass(frozen=True)
class Narrative:
    """LLM-generated narrative metadata for a run.

    Written once at end-of-run by narrative.py. Purely descriptive --
    the underlying verdicts and evidence are authoritative; narrative
    is for humans reading the report.

    When --no-llm is passed or the LLM call fails, a Narrative with
    `available=False` is produced so the render layer can show
    "narrative unavailable, raw data below" instead of a crash.
    """
    available: bool
    exec_summary: str
    per_attack_commentary: dict[str, str]       # attack_name -> prose
    remediation_suggestions: dict[str, str]     # attack_name -> snippet
    drift_commentary: str
    generated_at: float                         # epoch seconds; 0.0 if unavailable
    model: str                                  # model id used; "" if unavailable
    error: str                                  # populated when available=False


@dataclass(frozen=True)
class RunLedger:
    """Complete artifact of one Agent Orange run."""
    run_id: str                                 # "YYYYMMDDTHHMMSSZ"
    started_at: float                           # epoch seconds
    ended_at: float                             # epoch seconds
    victim_ip: str
    sensor_host: str
    attacker_host: str
    attacks: tuple[AttackLedgerEntry, ...]
    ruleset_snapshot: RulesetSnapshot
    ruleset_drift: RulesetDrift | None          # None when no prior run
    zeek_loaded_scripts: str                    # raw text, diagnostic
    zeek_stats: str                             # raw text, diagnostic
    narrative: Narrative                        # always present; may be .available=False

    # Metadata fields populated by orchestration:
    agent_orange_version: str
    attacks_yaml_path: str

    def total_seconds(self) -> int:
        return max(0, int(self.ended_at - self.started_at))

    def verdict_counts(self) -> dict[str, int]:
        """Group attacks by verdict for quick summary."""
        out: dict[str, int] = {}
        for entry in self.attacks:
            out[entry.verdict] = out.get(entry.verdict, 0) + 1
        return out

    def detected_count(self) -> int:
        """Any DETECTED_* verdict counts as a detection (not just EXPECTED)."""
        return sum(
            1 for e in self.attacks if e.verdict.startswith("DETECTED")
        )

    def coverage_pct(self) -> float:
        total = len(self.attacks)
        return round(100.0 * self.detected_count() / total, 1) if total else 0.0
