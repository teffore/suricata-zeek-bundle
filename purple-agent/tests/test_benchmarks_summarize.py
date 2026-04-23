"""Unit tests for benchmarks/summarize.py.

Covers the pure helper functions that parse ledgers, infer per-probe
durations, and compute order-honored / detection summaries. These tests
don't need a live sensor or a real agent run -- they drive summary logic
off fixture strings, so regressions in duration math or order-checking
get caught without standing the lab up.

Run:
    cd purple-agent && pytest tests/test_benchmarks_summarize.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# summarize.py lives in benchmarks/ as a script, not a package. Add it to
# sys.path so we can import the pure functions directly.
_BENCH_DIR = Path(__file__).resolve().parent.parent / "benchmarks"
if str(_BENCH_DIR) not in sys.path:
    sys.path.insert(0, str(_BENCH_DIR))

import summarize  # type: ignore  # noqa: E402


# ============================================================================
#  parse_iso_ts
# ============================================================================

class TestParseIsoTs:
    def test_parses_utc_z(self):
        assert summarize.parse_iso_ts("2026-04-23T12:00:00Z") == pytest.approx(
            1776945600, abs=1
        )

    def test_parses_offset(self):
        a = summarize.parse_iso_ts("2026-04-23T12:00:00+00:00")
        b = summarize.parse_iso_ts("2026-04-23T12:00:00Z")
        assert a == b

    def test_returns_zero_on_garbage(self):
        assert summarize.parse_iso_ts("not-a-timestamp") == 0.0

    def test_returns_zero_on_empty(self):
        assert summarize.parse_iso_ts("") == 0.0


# ============================================================================
#  load_pool_probe_names
# ============================================================================

class TestLoadPoolProbeNames:
    def test_reads_names_in_order(self, tmp_path: Path):
        pool = tmp_path / "pool.yaml"
        pool.write_text(
            "probes:\n"
            "  - name: art-first\n"
            "    mitre: T1046\n"
            "  - name: art-second\n"
            "    mitre: T1595\n"
            "  - name: art-third\n"
            "    mitre: T1048\n",
            encoding="utf-8",
        )
        assert summarize.load_pool_probe_names(pool) == [
            "art-first", "art-second", "art-third",
        ]

    def test_empty_pool_returns_empty(self, tmp_path: Path):
        pool = tmp_path / "empty.yaml"
        pool.write_text("probes: []\n", encoding="utf-8")
        assert summarize.load_pool_probe_names(pool) == []


# ============================================================================
#  load_ledger
# ============================================================================

class TestLoadLedger:
    def test_reads_jsonl(self, tmp_path: Path):
        p = tmp_path / "findings.jsonl"
        p.write_text(
            '{"probe":"art-one","verdict":"DETECTED","ts":"2026-04-23T12:00:00Z"}\n'
            '{"probe":"art-two","verdict":"UNDETECTED","ts":"2026-04-23T12:01:00Z"}\n',
            encoding="utf-8",
        )
        ledger = summarize.load_ledger(p)
        assert len(ledger) == 2
        assert ledger[0]["probe"] == "art-one"
        assert ledger[1]["verdict"] == "UNDETECTED"

    def test_skips_blank_and_bad_lines(self, tmp_path: Path):
        p = tmp_path / "noisy.jsonl"
        p.write_text(
            '{"probe":"art-one","ts":"2026-04-23T12:00:00Z"}\n'
            "\n"
            "not json at all\n"
            '{"probe":"art-two","ts":"2026-04-23T12:01:00Z"}\n',
            encoding="utf-8",
        )
        ledger = summarize.load_ledger(p)
        assert [e["probe"] for e in ledger] == ["art-one", "art-two"]


# ============================================================================
#  find_latest_by_ts + extract_ts_from_path
# ============================================================================

class TestLatestByTs:
    def test_picks_newest_by_lex_sort(self, tmp_path: Path):
        for name in [
            "findings-20260420T100000Z.jsonl",
            "findings-20260423T115959Z.jsonl",
            "findings-20260422T090000Z.jsonl",
        ]:
            (tmp_path / name).write_text("{}\n", encoding="utf-8")
        got = summarize.find_latest_by_ts(tmp_path, "findings", "jsonl")
        assert got is not None
        assert got.name == "findings-20260423T115959Z.jsonl"

    def test_returns_none_when_missing(self, tmp_path: Path):
        assert summarize.find_latest_by_ts(tmp_path, "findings", "jsonl") is None

    def test_extract_ts_from_path(self, tmp_path: Path):
        p = tmp_path / "findings-20260423T115959Z.jsonl"
        p.write_text("", encoding="utf-8")
        assert summarize.extract_ts_from_path(p, "findings") == "20260423T115959Z"


# ============================================================================
#  compute_per_probe
# ============================================================================

class TestComputePerProbe:
    def test_inferred_durations_chain_forward(self):
        ledger = [
            {"probe": "a", "ts": "2026-04-23T12:00:00Z", "verdict": "DETECTED",  "confidence": "high"},
            {"probe": "b", "ts": "2026-04-23T12:00:30Z", "verdict": "UNDETECTED","confidence": "none"},
            {"probe": "c", "ts": "2026-04-23T12:02:00Z", "verdict": "DETECTED",  "confidence": "partial"},
        ]
        end_epoch = summarize.parse_iso_ts("2026-04-23T12:03:00Z")
        rows = summarize.compute_per_probe(ledger, ["a", "b", "c"], end_epoch)

        assert [r["order"] for r in rows] == [1, 2, 3]
        assert rows[0]["inferred_duration_s"] == pytest.approx(30.0, abs=0.5)
        assert rows[1]["inferred_duration_s"] == pytest.approx(90.0, abs=0.5)
        # last probe uses end_epoch as upper bound
        assert rows[2]["inferred_duration_s"] == pytest.approx(60.0, abs=0.5)

    def test_marks_expected_vs_actual_mismatch(self):
        ledger = [
            {"probe": "b", "ts": "2026-04-23T12:00:00Z"},
            {"probe": "a", "ts": "2026-04-23T12:00:10Z"},
        ]
        end_epoch = summarize.parse_iso_ts("2026-04-23T12:00:20Z")
        rows = summarize.compute_per_probe(ledger, ["a", "b"], end_epoch)
        assert rows[0]["expected"] == "a"
        assert rows[0]["actual"] == "b"
        assert rows[1]["expected"] == "b"
        assert rows[1]["actual"] == "a"

    def test_duration_is_never_negative(self):
        # If the agent ever wrote an out-of-order ts, the duration must floor
        # at 0 instead of going negative — otherwise comparisons get noisy.
        ledger = [
            {"probe": "a", "ts": "2026-04-23T12:05:00Z"},
            {"probe": "b", "ts": "2026-04-23T12:02:00Z"},  # earlier than prior
        ]
        end_epoch = summarize.parse_iso_ts("2026-04-23T12:06:00Z")
        rows = summarize.compute_per_probe(ledger, ["a", "b"], end_epoch)
        assert rows[0]["inferred_duration_s"] >= 0
        assert rows[1]["inferred_duration_s"] >= 0


# ============================================================================
#  compute_order_honored
# ============================================================================

class TestOrderHonored:
    def test_exact_match_is_true(self):
        assert summarize.compute_order_honored(["a", "b", "c"], ["a", "b", "c"]) is True

    def test_reorder_is_false(self):
        assert summarize.compute_order_honored(["b", "a", "c"], ["a", "b", "c"]) is False

    def test_missing_probe_is_false(self):
        assert summarize.compute_order_honored(["a", "b"], ["a", "b", "c"]) is False

    def test_extra_probe_is_false(self):
        assert summarize.compute_order_honored(["a", "b", "c", "d"], ["a", "b", "c"]) is False


# ============================================================================
#  summarize_detection
# ============================================================================

class TestSummarizeDetection:
    def test_counts_detected_and_undetected(self):
        ledger = [
            {"verdict": "DETECTED"},
            {"verdict": "DETECTED_UNEXPECTED"},
            {"verdict": "UNDETECTED"},
            {"verdict": "UNDETECTED"},
            {"verdict": "ERROR"},
        ]
        out = summarize.summarize_detection(ledger)
        assert out["total"] == 5
        assert out["detected"] == 2
        assert out["undetected"] == 2
        assert out["other"] == 1
        assert out["coverage_pct"] == 40.0

    def test_empty_ledger_is_zero_coverage(self):
        out = summarize.summarize_detection([])
        assert out["total"] == 0
        assert out["coverage_pct"] == 0.0


# ============================================================================
#  build_summary (integration of pure pieces)
# ============================================================================

class TestBuildSummary:
    def test_full_clean_run(self):
        ledger = [
            {"probe": "a", "verdict": "DETECTED",   "confidence": "high",    "ts": "2026-04-23T12:00:00Z"},
            {"probe": "b", "verdict": "UNDETECTED", "confidence": "none",    "ts": "2026-04-23T12:00:45Z"},
        ]
        audit = {
            "overclaim_count": 1,
            "structural_issues": ["dup-name: a"],
            "sensor_alerts_in_window": 7,
            "sensor_notices_in_window": 3,
        }
        summary = summarize.build_summary(
            run_id="20260423T120000Z",
            start_iso="2026-04-23T12:00:00Z",
            end_iso="2026-04-23T12:01:00Z",
            start_epoch=summarize.parse_iso_ts("2026-04-23T12:00:00Z"),
            end_epoch=summarize.parse_iso_ts("2026-04-23T12:01:00Z"),
            expected_order=["a", "b"],
            ledger=ledger,
            audit=audit,
        )
        assert summary["run_id"] == "20260423T120000Z"
        assert summary["probes_expected"] == 2
        assert summary["probes_run"] == 2
        assert summary["order_honored"] is True
        assert summary["total_seconds"] == 60
        assert summary["detection_summary"]["coverage_pct"] == 50.0
        assert summary["accuracy"]["overclaim_count"] == 1
        assert summary["accuracy"]["structural_issues_count"] == 1
        assert summary["accuracy"]["sensor_alerts_in_window"] == 7

    def test_missing_audit_defaults_to_zeros(self):
        summary = summarize.build_summary(
            run_id="20260423T120000Z",
            start_iso="2026-04-23T12:00:00Z",
            end_iso="2026-04-23T12:01:00Z",
            start_epoch=0.0,
            end_epoch=60.0,
            expected_order=["a"],
            ledger=[{"probe": "a", "verdict": "DETECTED", "ts": "2026-04-23T12:00:00Z"}],
            audit=None,
        )
        assert summary["accuracy"]["overclaim_count"] == 0
        assert summary["accuracy"]["structural_issues_count"] == 0

    def test_output_shape_is_json_serializable(self):
        summary = summarize.build_summary(
            run_id="r1", start_iso="s", end_iso="e",
            start_epoch=0.0, end_epoch=1.0,
            expected_order=["a"],
            ledger=[{"probe": "a", "verdict": "DETECTED", "ts": "2026-04-23T12:00:00Z"}],
            audit=None,
        )
        # Round-trip ensures no non-serializable values sneak in.
        json.dumps(summary)
