"""Unit tests for agent_orange_pkg.harvest.

Covers timestamp parsing, event normalization, sectioned output parsing,
and the capture_baseline / harvest public API with a fake ssh_runner
so the tests don't touch a real sensor.
"""

from __future__ import annotations

import json
from typing import Callable

import pytest

from agent_orange_pkg.harvest import (
    BASELINE_LOGS, PROTOCOL_LOGS, DIAGNOSTIC_LOGS,
    HarvestError, SensorBaseline, SensorHarvest,
    build_baseline_command, build_harvest_command,
    capture_baseline, harvest,
    parse_sections, parse_suricata_ts, parse_zeek_ts,
    _normalize_suricata_alert, _normalize_zeek_notice,
)


# ---------------------------------------------------------------------------
#  Timestamp parsing
# ---------------------------------------------------------------------------

class TestParseSuricataTs:
    def test_utc_z_format(self):
        # 2026-04-23T15:43:46.000000+0000 == 1776959026
        assert parse_suricata_ts("2026-04-23T15:43:46.000000+0000") == pytest.approx(
            1776959026, abs=1
        )

    def test_no_microseconds(self):
        assert parse_suricata_ts("2026-04-23T15:43:46+0000") == pytest.approx(
            1776959026, abs=1
        )

    def test_already_colon_offset(self):
        # Python fromisoformat-compatible
        assert parse_suricata_ts("2026-04-23T15:43:46.000000+00:00") == pytest.approx(
            1776959026, abs=1
        )

    def test_garbage_returns_none(self):
        assert parse_suricata_ts("not-a-ts") is None
        assert parse_suricata_ts("") is None
        assert parse_suricata_ts(None) is None
        assert parse_suricata_ts(12345) is None


class TestParseZeekTs:
    def test_numeric_float(self):
        assert parse_zeek_ts(1776959026.123) == 1776959026.123

    def test_string_float(self):
        assert parse_zeek_ts("1776959026.123") == pytest.approx(1776959026.123)

    def test_int(self):
        assert parse_zeek_ts(1776959026) == 1776959026.0

    def test_bool_rejected(self):
        # isinstance(True, int) is True in Python; must explicitly reject
        assert parse_zeek_ts(True) is None
        assert parse_zeek_ts(False) is None

    def test_bad_string_returns_none(self):
        assert parse_zeek_ts("not-a-number") is None

    def test_none_returns_none(self):
        assert parse_zeek_ts(None) is None


# ---------------------------------------------------------------------------
#  Event normalization
# ---------------------------------------------------------------------------

class TestNormalizeSuricataAlert:
    def test_happy_path(self):
        raw = {
            "event_type": "alert",
            "timestamp": "2026-04-23T15:43:46.000000+0000",
            "src_ip": "10.0.0.5",
            "dest_ip": "172.31.76.116",
            "dest_port": 80,
            "proto": "TCP",
            "alert": {
                "signature_id": 2031502,
                "signature": "ET EXPLOIT /.env HTTP Request",
                "category": "Web Application Attack",
                "severity": 2,
            },
            "http": {"hostname": "victim.local"},
        }
        ev = _normalize_suricata_alert(raw)
        assert ev is not None
        assert ev["sid"] == 2031502
        assert ev["dest_ip"] == "172.31.76.116"
        assert ev["sni"] == "victim.local"  # falls back to http.hostname
        assert ev["ts"] == pytest.approx(1776959026, abs=1)

    def test_non_alert_rejected(self):
        raw = {"event_type": "flow", "timestamp": "2026-04-23T15:43:46+0000"}
        assert _normalize_suricata_alert(raw) is None

    def test_missing_ts_rejected(self):
        raw = {"event_type": "alert", "alert": {"signature_id": 1}}
        assert _normalize_suricata_alert(raw) is None

    def test_tls_sni_preferred(self):
        raw = {
            "event_type": "alert",
            "timestamp": "2026-04-23T15:43:46+0000",
            "dest_ip": "1.1.1.1",
            "tls": {"sni": "trycloudflare.com"},
            "http": {"hostname": "something.else"},
            "alert": {"signature_id": 9999},
        }
        ev = _normalize_suricata_alert(raw)
        assert ev["sni"] == "trycloudflare.com"  # tls wins over http

    def test_string_sid_coerced_to_int(self):
        raw = {
            "event_type": "alert",
            "timestamp": "2026-04-23T15:43:46+0000",
            "dest_ip": "1.1.1.1",
            "alert": {"signature_id": "2031502"},
        }
        ev = _normalize_suricata_alert(raw)
        assert ev["sid"] == 2031502


class TestNormalizeZeekNotice:
    def test_happy_path(self):
        raw = {
            "ts": "1776959026.5",
            "id.orig_h": "10.0.0.5",
            "id.resp_h": "172.31.76.116",
            "note": "Scan::Port_Scan",
            "msg": "10.0.0.5 scanned 8 ports",
            "server_name": "example.com",
        }
        ev = _normalize_zeek_notice(raw)
        assert ev is not None
        assert ev["ts"] == pytest.approx(1776959026.5)
        assert ev["dest_ip"] == "172.31.76.116"
        assert ev["sni"] == "example.com"
        assert ev["note"] == "Scan::Port_Scan"
        assert ev["src"] == "10.0.0.5"

    def test_dst_field_fallback(self):
        # Some Zeek versions use "dst" instead of id.resp_h
        raw = {"ts": "1.0", "dst": "8.8.8.8", "note": "Tor::Connection"}
        ev = _normalize_zeek_notice(raw)
        assert ev["dest_ip"] == "8.8.8.8"

    def test_missing_ts_rejected(self):
        assert _normalize_zeek_notice({"note": "anything"}) is None


# ---------------------------------------------------------------------------
#  Sectioned output parser
# ---------------------------------------------------------------------------

class TestParseSections:
    def test_two_sections(self):
        raw = (
            "=== SECTION_A ===\n"
            "line1\n"
            "line2\n"
            "=== SECTION_B ===\n"
            "line3\n"
        )
        out = parse_sections(raw)
        assert out == {"SECTION_A": ["line1", "line2"], "SECTION_B": ["line3"]}

    def test_empty_section(self):
        out = parse_sections("=== EMPTY ===\n")
        assert out == {"EMPTY": []}

    def test_leading_garbage_before_first_section_ignored(self):
        raw = "junk line\nmore junk\n=== SECTION ===\nreal\n"
        assert parse_sections(raw) == {"SECTION": ["real"]}

    def test_blank_lines_dropped(self):
        raw = "=== SECTION ===\nline\n\n\nline2\n"
        assert parse_sections(raw) == {"SECTION": ["line", "line2"]}

    def test_header_must_have_three_equals_each_side(self):
        raw = "== NOT_A_SECTION ==\nhello\n=== REAL ===\nworld\n"
        out = parse_sections(raw)
        assert "NOT_A_SECTION" not in out
        assert out["REAL"] == ["world"]

    def test_json_payload_matching_section_pattern_is_a_header(self):
        # Known theoretical edge case: if a log value were literally a line
        # that started `=== ` and ended ` ===`, parse_sections would treat
        # it as a section header. No real sensor produces such lines today,
        # but this test documents the behavior so future hardening (e.g.
        # switching to a unique marker) has a canary. If this assertion
        # ever surprises someone, that's the moment to strengthen the
        # marker contract.
        raw = "=== HEADER ===\nreal content\n=== UNLIKELY INNER ===\nleaked\n"
        out = parse_sections(raw)
        # The "UNLIKELY INNER" line becomes its own section, swallowing
        # the following line. This is the current behavior, not a goal.
        assert "HEADER" in out
        assert "UNLIKELY INNER" in out


# ---------------------------------------------------------------------------
#  Command builders
# ---------------------------------------------------------------------------

class TestCommandBuilders:
    def test_baseline_command_is_a_string_with_all_five_logs(self):
        cmd = build_baseline_command()
        for log_token in ("eve.json", "notice.log", "weird.log", "intel.log", "conn.log"):
            assert log_token in cmd

    def test_harvest_command_includes_baselined_logs(self):
        baseline = SensorBaseline(
            eve_json_lines=100,
            notice_log_lines=50,
            weird_log_lines=10,
            intel_log_lines=5,
            conn_log_lines=200,
            captured_at=1.0,
        )
        cmd = build_harvest_command(baseline)
        assert "=== EVE_ALERTS ===" in cmd
        assert "tail -n +101" in cmd  # eve baseline + 1
        assert "tail -n +51" in cmd   # notice baseline + 1
        assert "tail -n +201" in cmd  # conn baseline + 1

    def test_harvest_command_includes_protocol_logs(self):
        baseline = SensorBaseline(
            eve_json_lines=0, notice_log_lines=0, weird_log_lines=0,
            intel_log_lines=0, conn_log_lines=0, captured_at=0.0,
        )
        cmd = build_harvest_command(baseline)
        for logname in PROTOCOL_LOGS:
            section_name = f"ZEEK_{logname.replace('.log','').upper()}"
            assert f"=== {section_name} ===" in cmd

    def test_harvest_command_includes_diagnostics(self):
        baseline = SensorBaseline(
            eve_json_lines=0, notice_log_lines=0, weird_log_lines=0,
            intel_log_lines=0, conn_log_lines=0, captured_at=0.0,
        )
        cmd = build_harvest_command(baseline)
        assert "=== ZEEK_LOADED_SCRIPTS ===" in cmd
        assert "=== ZEEK_STATS ===" in cmd


# ---------------------------------------------------------------------------
#  SensorBaseline.line_for
# ---------------------------------------------------------------------------

class TestSensorBaseline:
    def test_line_for_mapping(self):
        b = SensorBaseline(
            eve_json_lines=100, notice_log_lines=50, weird_log_lines=10,
            intel_log_lines=5, conn_log_lines=200, captured_at=0.0,
        )
        assert b.line_for("eve.json") == 100
        assert b.line_for("notice.log") == 50
        assert b.line_for("weird.log") == 10
        assert b.line_for("intel.log") == 5
        assert b.line_for("conn.log") == 200

    def test_line_for_unknown_returns_zero(self):
        b = SensorBaseline(
            eve_json_lines=100, notice_log_lines=50, weird_log_lines=10,
            intel_log_lines=5, conn_log_lines=200, captured_at=0.0,
        )
        assert b.line_for("unknown.log") == 0


# ---------------------------------------------------------------------------
#  capture_baseline + harvest (fake ssh_runner)
# ---------------------------------------------------------------------------

def _fake_runner(stdout: str = "", stderr: str = "", rc: int = 0) -> Callable:
    """Produce a one-shot fake ssh_runner that returns the given triple."""
    def runner(cmd: str) -> tuple[str, str, int]:
        return stdout, stderr, rc
    return runner


def _fake_runner_sequence(responses: list[tuple[str, str, int]]) -> Callable:
    """Fake ssh_runner that returns responses in order across calls."""
    it = iter(responses)

    def runner(cmd: str) -> tuple[str, str, int]:
        try:
            return next(it)
        except StopIteration:  # pragma: no cover
            return "", "", 0
    return runner


class TestCaptureBaseline:
    def test_parses_valid_json(self):
        runner = _fake_runner(
            stdout='{"eve":123,"notice":45,"weird":6,"intel":7,"conn":999}\n',
        )
        b = capture_baseline(runner)
        assert b.eve_json_lines == 123
        assert b.conn_log_lines == 999

    def test_nonzero_rc_raises(self):
        runner = _fake_runner(stderr="permission denied", rc=1)
        with pytest.raises(HarvestError, match="baseline SSH failed"):
            capture_baseline(runner)

    def test_unparseable_stdout_raises(self):
        runner = _fake_runner(stdout="not-json")
        with pytest.raises(HarvestError, match="baseline parse failed"):
            capture_baseline(runner)


class TestHarvest:
    def _baseline(self, **overrides) -> SensorBaseline:
        defaults = dict(
            eve_json_lines=0, notice_log_lines=0, weird_log_lines=0,
            intel_log_lines=0, conn_log_lines=0, captured_at=0.0,
        )
        defaults.update(overrides)
        return SensorBaseline(**defaults)

    def test_parses_suricata_and_zeek_sections(self):
        alert = {
            "event_type": "alert",
            "timestamp": "2026-04-23T15:43:46+0000",
            "dest_ip": "172.31.76.116",
            "alert": {"signature_id": 2031502},
        }
        notice = {
            "ts": "1776959050.0",
            "id.resp_h": "172.31.76.116",
            "note": "Scan::Port_Scan",
        }
        stdout = (
            "=== EVE_ALERTS ===\n"
            f"{json.dumps(alert)}\n"
            "=== ZEEK_NOTICE ===\n"
            f"{json.dumps(notice)}\n"
            "=== ZEEK_WEIRD ===\n"
            "=== ZEEK_INTEL ===\n"
            "=== ZEEK_CONN ===\n"
        )
        for logname in PROTOCOL_LOGS + DIAGNOSTIC_LOGS:
            section_name = f"ZEEK_{logname.replace('.log','').upper()}"
            stdout += f"=== {section_name} ===\n"

        h = harvest(_fake_runner(stdout=stdout), self._baseline(), run_start_ts=0.0)
        assert len(h.suricata_alerts) == 1
        assert h.suricata_alerts[0]["sid"] == 2031502
        assert len(h.zeek_notices) == 1
        assert h.zeek_notices[0]["note"] == "Scan::Port_Scan"

    def test_protocol_log_filtered_by_run_start(self):
        # Two http.log events, one before run_start, one after.
        early = {"ts": "100.0", "id.resp_h": "1.1.1.1", "host": "x.com"}
        late = {"ts": "500.0", "id.resp_h": "1.1.1.1", "host": "y.com"}
        stdout = "=== EVE_ALERTS ===\n=== ZEEK_NOTICE ===\n=== ZEEK_WEIRD ===\n"
        stdout += "=== ZEEK_INTEL ===\n=== ZEEK_CONN ===\n"
        stdout += "=== ZEEK_HTTP ===\n"
        stdout += f"{json.dumps(early)}\n{json.dumps(late)}\n"
        for logname in PROTOCOL_LOGS[1:] + DIAGNOSTIC_LOGS:
            section_name = f"ZEEK_{logname.replace('.log','').upper()}"
            stdout += f"=== {section_name} ===\n"

        h = harvest(_fake_runner(stdout=stdout), self._baseline(), run_start_ts=300.0)
        assert "http.log" in h.zeek_protocol_logs
        assert len(h.zeek_protocol_logs["http.log"]) == 1
        assert h.zeek_protocol_logs["http.log"][0]["ts"] == 500.0

    def test_missing_sections_tolerated(self):
        # Completely empty stdout -> empty SensorHarvest, no crash.
        h = harvest(_fake_runner(stdout=""), self._baseline(), run_start_ts=0.0)
        assert h.suricata_alerts == []
        assert h.zeek_notices == []
        assert h.zeek_protocol_logs == {}

    def test_ssh_failure_raises(self):
        runner = _fake_runner(stderr="connection refused", rc=255)
        with pytest.raises(HarvestError, match="harvest SSH failed"):
            harvest(runner, self._baseline(), run_start_ts=0.0)

    def test_unparseable_lines_skipped(self):
        stdout = (
            "=== EVE_ALERTS ===\n"
            "not-json\n"
            '{"event_type":"alert","timestamp":"2026-04-23T15:43:46+0000",'
            '"dest_ip":"1.1.1.1","alert":{"signature_id":1}}\n'
        )
        h = harvest(_fake_runner(stdout=stdout), self._baseline(), run_start_ts=0.0)
        assert len(h.suricata_alerts) == 1


# ---------------------------------------------------------------------------
#  Module constants sanity
# ---------------------------------------------------------------------------

class TestConstants:
    def test_baseline_logs_are_the_five_growth_logs(self):
        assert set(BASELINE_LOGS) == {
            "eve.json", "notice.log", "weird.log", "intel.log", "conn.log",
        }

    def test_protocol_logs_include_key_detection_surfaces(self):
        for required in ("http.log", "ssl.log", "dns.log", "ftp.log",
                         "smtp.log", "files.log", "software.log",
                         "dce_rpc.log", "kerberos.log"):
            assert required in PROTOCOL_LOGS, f"{required} missing from PROTOCOL_LOGS"

    def test_diagnostic_logs_include_loaded_and_stats(self):
        assert "loaded_scripts.log" in DIAGNOSTIC_LOGS
        assert "stats.log" in DIAGNOSTIC_LOGS
