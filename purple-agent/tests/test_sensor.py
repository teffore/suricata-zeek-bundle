"""Unit tests for purple_agent_pkg.sensor.

Covers the sensor-log parser, timestamp normalizer, and ledger audit. The
point of the extraction is that these trust-model guarantees -- ±60s causal
window, run_start floor, DETECTED-with-no-evidence guard, duplicate-probe
detection -- are locked down by tests that DON'T require claude-agent-sdk,
AWS, or a live sensor.

Run:
    pip install pytest
    pytest purple-agent/tests/test_sensor.py
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from purple_agent_pkg.sensor import (
    compute_audit,
    normalize_suricata_ts,
    parse_sectioned_jq_stream,
)


# ============================================================================
#  parse_sectioned_jq_stream
# ============================================================================

class TestParseSectionedJqStream:
    def test_audit_style_two_sections(self):
        raw = (
            "=== ALERTS ===\n"
            '{"ts":"2026-04-21T23:58:37+0000","sid":2001,"sig":"a"}\n'
            '{"ts":"2026-04-21T23:59:10+0000","sid":2002,"sig":"b"}\n'
            "=== NOTICES ===\n"
            '{"ts":"1745280000","note":"Scan::Port_Scan"}\n'
        )
        out = parse_sectioned_jq_stream(
            raw, {"=== ALERTS ===": "alerts", "=== NOTICES ===": "notices"}
        )
        assert len(out["alerts"]) == 2
        assert out["alerts"][0]["sid"] == 2001
        assert len(out["notices"]) == 1
        assert out["notices"][0]["note"] == "Scan::Port_Scan"

    def test_sweep_style_notices_and_intel(self):
        raw = (
            "=== NOTICES ===\n"
            '{"ts":"1745280000","note":"Weird::TLS"}\n'
            "=== INTEL ===\n"
            '{"indicator":"1.2.3.4","sources":["abuse.ch"]}\n'
        )
        out = parse_sectioned_jq_stream(
            raw, {"=== NOTICES ===": "notices", "=== INTEL ===": "intel"}
        )
        assert len(out["notices"]) == 1
        assert len(out["intel"]) == 1
        assert out["intel"][0]["indicator"] == "1.2.3.4"

    def test_empty_section_still_returns_key(self):
        raw = "=== ALERTS ===\n=== NOTICES ===\n"
        out = parse_sectioned_jq_stream(
            raw, {"=== ALERTS ===": "alerts", "=== NOTICES ===": "notices"}
        )
        assert out == {"alerts": [], "notices": []}

    def test_malformed_json_line_is_silently_skipped(self):
        # Simulates jq emitting a truncated line mid-rotation.
        raw = (
            "=== ALERTS ===\n"
            '{"sid":123}\n'
            "{not valid json}\n"
            '{"sid":456}\n'
        )
        out = parse_sectioned_jq_stream(raw, {"=== ALERTS ===": "alerts"})
        assert [a["sid"] for a in out["alerts"]] == [123, 456]

    def test_content_before_first_banner_is_dropped(self):
        raw = (
            '{"orphan":true}\n'
            "=== ALERTS ===\n"
            '{"sid":1}\n'
        )
        out = parse_sectioned_jq_stream(raw, {"=== ALERTS ===": "alerts"})
        assert len(out["alerts"]) == 1
        assert out["alerts"][0]["sid"] == 1

    def test_whitespace_around_banner_still_matches(self):
        raw = (
            "   === ALERTS ===   \n"
            '{"sid":7}\n'
        )
        out = parse_sectioned_jq_stream(raw, {"=== ALERTS ===": "alerts"})
        assert len(out["alerts"]) == 1

    def test_empty_raw_input(self):
        out = parse_sectioned_jq_stream(
            "", {"=== ALERTS ===": "alerts", "=== NOTICES ===": "notices"}
        )
        assert out == {"alerts": [], "notices": []}


# ============================================================================
#  normalize_suricata_ts
# ============================================================================

class TestNormalizeSuricataTs:
    def test_compact_tz_offset(self):
        # Suricata's native format.
        out = normalize_suricata_ts("2026-04-21T23:58:37.123456+0000")
        # 2026-04-21 23:58:37 UTC is a fixed epoch.
        expected = datetime(2026, 4, 21, 23, 58, 37, 123456, tzinfo=timezone.utc).timestamp()
        assert out == pytest.approx(expected)

    def test_colon_tz_offset(self):
        out = normalize_suricata_ts("2026-04-21T23:58:37.123456+00:00")
        expected = datetime(2026, 4, 21, 23, 58, 37, 123456, tzinfo=timezone.utc).timestamp()
        assert out == pytest.approx(expected)

    def test_zulu_shorthand(self):
        out = normalize_suricata_ts("2026-04-21T23:58:37Z")
        expected = datetime(2026, 4, 21, 23, 58, 37, tzinfo=timezone.utc).timestamp()
        assert out == pytest.approx(expected)

    def test_non_utc_compact_offset(self):
        # A -05:00 offset should land 5 hours LATER in epoch than the same
        # wall-clock time in UTC.
        eastern = normalize_suricata_ts("2026-04-21T18:58:37-0500")
        utc = normalize_suricata_ts("2026-04-21T23:58:37+0000")
        assert eastern == pytest.approx(utc)

    def test_empty_string_returns_zero(self):
        assert normalize_suricata_ts("") == 0.0

    def test_none_returns_zero(self):
        assert normalize_suricata_ts(None) == 0.0

    def test_non_string_returns_zero(self):
        assert normalize_suricata_ts(12345) == 0.0

    def test_garbage_string_returns_zero(self):
        assert normalize_suricata_ts("not a timestamp") == 0.0

    def test_naive_timestamp_parses(self):
        # No tz -- fromisoformat accepts; timestamp() interprets as local.
        # We just check it doesn't blow up and returns a positive float.
        out = normalize_suricata_ts("2026-04-21T23:58:37")
        assert out > 0


# ============================================================================
#  compute_audit
# ============================================================================

RUN_START = datetime(2026, 4, 21, 23, 0, 0, tzinfo=timezone.utc).timestamp()


def _probe_ts(minute: int, second: int = 0) -> str:
    """Helper: build a probe ts string at 23:MM:SS on run-start day."""
    return f"2026-04-21T23:{minute:02d}:{second:02d}+00:00"


def _alert_ts(minute: int, second: int = 0) -> str:
    """Helper: Suricata-style compact-tz alert ts on run-start day."""
    return f"2026-04-21T23:{minute:02d}:{second:02d}.000000+0000"


class TestComputeAuditCausalAttribution:
    def test_alert_within_window_verifies_claim(self):
        ledger = [
            {"probe": "p1", "ts": _probe_ts(10, 0), "verdict": "DETECTED",
             "fired_sids": [2001]},
        ]
        alerts = [{"sid": 2001, "ts": _alert_ts(10, 30)}]  # +30s
        out = compute_audit(alerts, [], ledger, RUN_START, 3600)
        assert out["probe_audits"][0]["verified_sids"] == [2001]
        assert out["probe_audits"][0]["unverified_sids"] == []
        assert out["overclaim_count"] == 0

    def test_alert_outside_window_does_not_verify(self):
        ledger = [
            {"probe": "p1", "ts": _probe_ts(10, 0), "verdict": "DETECTED",
             "fired_sids": [2001]},
        ]
        # 2 minutes away -- outside ±60s.
        alerts = [{"sid": 2001, "ts": _alert_ts(12, 0)}]
        out = compute_audit(alerts, [], ledger, RUN_START, 3600)
        assert out["probe_audits"][0]["verified_sids"] == []
        assert out["probe_audits"][0]["unverified_sids"] == [2001]
        assert out["overclaim_count"] == 1

    def test_alert_before_run_start_is_excluded(self):
        # The classic "historical alert falsely verifies" trap. run_start
        # is 23:00 UTC; this alert is at 22:00 UTC (before the run).
        ledger = [
            {"probe": "p1", "ts": _probe_ts(0, 30), "verdict": "DETECTED",
             "fired_sids": [2001]},
        ]
        alerts = [{"sid": 2001, "ts": "2026-04-21T22:00:10+0000"}]
        out = compute_audit(alerts, [], ledger, RUN_START, 3600)
        assert out["probe_audits"][0]["verified_sids"] == []
        assert out["probe_audits"][0]["unverified_sids"] == [2001]

    def test_multiple_firings_any_match_verifies(self):
        ledger = [
            {"probe": "p1", "ts": _probe_ts(10, 0), "verdict": "DETECTED",
             "fired_sids": [2001]},
        ]
        alerts = [
            {"sid": 2001, "ts": _alert_ts(5, 0)},   # out of window
            {"sid": 2001, "ts": _alert_ts(10, 30)},  # in window
        ]
        out = compute_audit(alerts, [], ledger, RUN_START, 3600)
        assert 2001 in out["probe_audits"][0]["verified_sids"]


class TestComputeAuditStructuralIssues:
    def test_detected_with_no_evidence_is_flagged(self):
        ledger = [
            {"probe": "p1", "ts": _probe_ts(10, 0), "verdict": "DETECTED",
             "fired_sids": [], "zeek_notices": [], "zeek_signals": ""},
        ]
        out = compute_audit([], [], ledger, RUN_START, 3600)
        issues = out["structural_issues"]
        assert any("DETECTED with no evidence" in i["issue"] for i in issues)

    def test_detected_with_sid_is_not_flagged(self):
        ledger = [
            {"probe": "p1", "ts": _probe_ts(10, 0), "verdict": "DETECTED",
             "fired_sids": [2001], "zeek_notices": [], "zeek_signals": ""},
        ]
        out = compute_audit([], [], ledger, RUN_START, 3600)
        assert not any("DETECTED with no evidence" in i["issue"]
                       for i in out["structural_issues"])

    def test_detected_with_zeek_notice_is_not_flagged(self):
        ledger = [
            {"probe": "p1", "ts": _probe_ts(10, 0), "verdict": "DETECTED",
             "fired_sids": [], "zeek_notices": ["Scan::Port_Scan"],
             "zeek_signals": ""},
        ]
        out = compute_audit([], [], ledger, RUN_START, 3600)
        assert not any("DETECTED with no evidence" in i["issue"]
                       for i in out["structural_issues"])

    def test_detected_with_empty_zeek_signals_marker_still_flagged(self):
        # "empty" / "none" / whitespace are all treated as no-evidence.
        for marker in ("empty", "EMPTY", "none", "  ", ""):
            ledger = [
                {"probe": f"p_{marker.strip() or 'blank'}", "ts": _probe_ts(10, 0),
                 "verdict": "DETECTED", "fired_sids": [], "zeek_notices": [],
                 "zeek_signals": marker},
            ]
            out = compute_audit([], [], ledger, RUN_START, 3600)
            assert any("DETECTED with no evidence" in i["issue"]
                       for i in out["structural_issues"]), (
                f"marker {marker!r} should flag no-evidence"
            )

    def test_missing_probe_name_is_flagged(self):
        ledger = [
            {"probe": "", "ts": _probe_ts(10, 0), "verdict": "DETECTED",
             "fired_sids": [2001]},
        ]
        out = compute_audit([], [], ledger, RUN_START, 3600)
        assert any(i["issue"] == "missing probe_name" for i in out["structural_issues"])
        # Entries without a probe name don't contribute an audit row.
        assert out["probe_audits"] == []

    def test_duplicate_probe_name_is_flagged(self):
        ledger = [
            {"probe": "p1", "ts": _probe_ts(10, 0), "verdict": "UNDETECTED"},
            {"probe": "p1", "ts": _probe_ts(15, 0), "verdict": "DETECTED",
             "fired_sids": [2001]},
        ]
        out = compute_audit([], [], ledger, RUN_START, 3600)
        dupe_issues = [i for i in out["structural_issues"]
                       if i["issue"] == "duplicate probe name"]
        assert len(dupe_issues) == 1
        assert dupe_issues[0]["probe"] == "p1"


class TestComputeAuditAggregates:
    def test_total_probes_and_verdict_distribution(self):
        ledger = [
            {"probe": "p1", "ts": _probe_ts(10), "verdict": "DETECTED",
             "fired_sids": [2001]},
            {"probe": "p2", "ts": _probe_ts(11), "verdict": "UNDETECTED"},
            {"probe": "p3", "ts": _probe_ts(12), "verdict": "UNDETECTED"},
            {"probe": "p4", "ts": _probe_ts(13), "verdict": "FAILED"},
        ]
        out = compute_audit([], [], ledger, RUN_START, 3600)
        assert out["total_probes"] == 4
        assert out["verdict_distribution"] == {
            "DETECTED": 1, "UNDETECTED": 2, "FAILED": 1,
        }

    def test_sensor_counts_match_input(self):
        alerts = [
            {"sid": 2001, "ts": _alert_ts(10)},
            {"sid": 2001, "ts": _alert_ts(11)},
            {"sid": 2002, "ts": _alert_ts(12)},
        ]
        notices = [{"note": "x"}, {"note": "y"}]
        out = compute_audit(alerts, notices, [], RUN_START, 3600)
        assert out["sensor_alerts_in_window"] == 3
        assert out["sensor_unique_sids"] == 2
        assert out["sensor_notices_in_window"] == 2

    def test_empty_ledger_produces_empty_audit(self):
        out = compute_audit([], [], [], RUN_START, 3600)
        assert out["total_probes"] == 0
        assert out["verdict_distribution"] == {}
        assert out["probe_audits"] == []
        assert out["overclaim_count"] == 0
        assert out["structural_issues"] == []

    def test_returned_shape_has_all_expected_keys(self):
        # Contract guard -- the HTML report reads these keys by name.
        out = compute_audit([], [], [], RUN_START, 3600)
        for key in (
            "run_start_epoch",
            "window_sec",
            "total_probes",
            "verdict_distribution",
            "sensor_alerts_in_window",
            "sensor_unique_sids",
            "sensor_notices_in_window",
            "structural_issues",
            "overclaim_count",
            "probe_audits",
        ):
            assert key in out, f"missing key: {key}"


class TestComputeAuditTimestampRobustness:
    def test_audit_handles_mixed_tz_formats_in_ledger_and_alerts(self):
        # Alerts use compact +0000 (Suricata's native), ledger entries use
        # colon +00:00 (from datetime.isoformat() in record_finding). Both
        # must resolve to the same epoch or the window match fails.
        ledger = [
            {"probe": "p_zulu", "ts": "2026-04-21T23:10:00Z",
             "verdict": "DETECTED", "fired_sids": [2001]},
            {"probe": "p_colon", "ts": "2026-04-21T23:15:00+00:00",
             "verdict": "DETECTED", "fired_sids": [2002]},
        ]
        alerts = [
            {"sid": 2001, "ts": "2026-04-21T23:10:05.000000+0000"},  # +5s
            {"sid": 2002, "ts": "2026-04-21T23:15:20.000000+0000"},  # +20s
        ]
        out = compute_audit(alerts, [], ledger, RUN_START, 3600)
        for audit_row in out["probe_audits"]:
            assert audit_row["unverified_sids"] == [], (
                f"{audit_row['probe']} should verify across mixed tz formats: "
                f"{audit_row}"
            )

    def test_ledger_entry_with_unparseable_ts_yields_no_verifications(self):
        ledger = [
            {"probe": "p1", "ts": "not a ts", "verdict": "DETECTED",
             "fired_sids": [2001]},
        ]
        alerts = [{"sid": 2001, "ts": _alert_ts(10)}]
        out = compute_audit(alerts, [], ledger, RUN_START, 3600)
        # With probe_ts == 0, no SIDs go into verified or unverified; the
        # overclaim counter only trips on non-empty unverified list, so it
        # stays at 0.
        assert out["probe_audits"][0]["verified_sids"] == []
        assert out["probe_audits"][0]["unverified_sids"] == []
        assert out["overclaim_count"] == 0

    def test_alert_with_unparseable_ts_is_silently_dropped(self):
        ledger = [
            {"probe": "p1", "ts": _probe_ts(10), "verdict": "DETECTED",
             "fired_sids": [2001]},
        ]
        alerts = [
            {"sid": 2001, "ts": "junk"},
            {"sid": 2001, "ts": _alert_ts(10, 20)},  # good one within window
        ]
        out = compute_audit(alerts, [], ledger, RUN_START, 3600)
        assert 2001 in out["probe_audits"][0]["verified_sids"]
