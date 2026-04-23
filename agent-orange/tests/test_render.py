"""Unit tests for agent_orange_pkg.render."""

from __future__ import annotations

import json
from pathlib import Path

from agent_orange_pkg.render import (
    ledger_to_dict, render_html, render_markdown,
    render_stdout_summary, write_html, write_json, write_markdown,
)
from agent_orange_pkg.ruleset import RulesetDrift
from tests._ledger_fixtures import (
    make_attack, make_entry, make_ledger, make_narrative,
)


class TestFormatVerdictBadge:
    """Maps internal verdict tiers to visible badges.

    Unicode style for HTML/MD, ASCII for stdout. Only DETECTED_EXPECTED
    gets a visible mark; all other DETECTED tiers render as plain
    "DETECTED".
    """

    def test_detected_expected_unicode(self):
        from agent_orange_pkg.render import format_verdict_badge
        assert format_verdict_badge("DETECTED_EXPECTED", "unicode") == "DETECTED \u2713"

    def test_detected_expected_ascii(self):
        from agent_orange_pkg.render import format_verdict_badge
        assert format_verdict_badge("DETECTED_EXPECTED", "ascii") == "DETECTED [x]"

    def test_detected_partial_unicode_same_as_unexpected(self):
        from agent_orange_pkg.render import format_verdict_badge
        assert format_verdict_badge("DETECTED_PARTIAL", "unicode") == "DETECTED"

    def test_detected_partial_ascii(self):
        from agent_orange_pkg.render import format_verdict_badge
        assert format_verdict_badge("DETECTED_PARTIAL", "ascii") == "DETECTED"

    def test_detected_unexpected_unicode(self):
        from agent_orange_pkg.render import format_verdict_badge
        assert format_verdict_badge("DETECTED_UNEXPECTED", "unicode") == "DETECTED"

    def test_detected_unexpected_ascii(self):
        from agent_orange_pkg.render import format_verdict_badge
        assert format_verdict_badge("DETECTED_UNEXPECTED", "ascii") == "DETECTED"

    def test_undetected_unicode(self):
        from agent_orange_pkg.render import format_verdict_badge
        assert format_verdict_badge("UNDETECTED", "unicode") == "UNDETECTED"

    def test_undetected_ascii(self):
        from agent_orange_pkg.render import format_verdict_badge
        assert format_verdict_badge("UNDETECTED", "ascii") == "UNDETECTED"

    def test_failed_unicode(self):
        from agent_orange_pkg.render import format_verdict_badge
        assert format_verdict_badge("FAILED", "unicode") == "FAILED"

    def test_failed_ascii(self):
        from agent_orange_pkg.render import format_verdict_badge
        assert format_verdict_badge("FAILED", "ascii") == "FAILED"

    def test_unknown_tier_defaults_to_tier_name(self):
        # Defensive: if verdict.py ever grows a new tier and render isn't
        # updated in lockstep, fall back to the raw tier name rather than
        # crash. Makes the miss visible without breaking the report.
        from agent_orange_pkg.render import format_verdict_badge
        assert format_verdict_badge("BRAND_NEW_TIER", "unicode") == "BRAND_NEW_TIER"

    def test_unknown_style_defaults_to_unicode(self):
        from agent_orange_pkg.render import format_verdict_badge
        assert format_verdict_badge("DETECTED_EXPECTED", "html5") == "DETECTED \u2713"


class TestFormatSuricataCell:
    """Suricata column: '0 or --' / 'N (sid1, sid2, sid3)' / 'N (sid1, sid2, +K more)'."""

    def test_empty_renders_dash(self):
        from agent_orange_pkg.render import format_suricata_cell
        assert format_suricata_cell([]) == "\u2014"

    def test_none_input_renders_dash(self):
        from agent_orange_pkg.render import format_suricata_cell
        # Defensive: ledger might omit the list on some paths; treat as empty.
        assert format_suricata_cell(None) == "\u2014"

    def test_single_sid(self):
        from agent_orange_pkg.render import format_suricata_cell
        alerts = [{"sid": 2001219}]
        assert format_suricata_cell(alerts) == "1 (2001219)"

    def test_three_sids_at_threshold_no_truncation(self):
        from agent_orange_pkg.render import format_suricata_cell
        alerts = [{"sid": 1}, {"sid": 2}, {"sid": 3}]
        assert format_suricata_cell(alerts) == "3 (1, 2, 3)"

    def test_five_sids_truncate_to_three_plus_more(self):
        from agent_orange_pkg.render import format_suricata_cell
        alerts = [{"sid": 1}, {"sid": 2}, {"sid": 3}, {"sid": 4}, {"sid": 5}]
        assert format_suricata_cell(alerts) == "5 (1, 2, 3, +2 more)"

    def test_duplicate_sids_deduped_in_display(self):
        # Raw alerts can repeat; cell shows unique SIDs, count reflects unique.
        from agent_orange_pkg.render import format_suricata_cell
        alerts = [{"sid": 9000003}, {"sid": 9000003}, {"sid": 9000003}]
        assert format_suricata_cell(alerts) == "1 (9000003)"

    def test_missing_sid_field_skipped(self):
        # Alert without a sid is diagnostic noise; don't count it.
        from agent_orange_pkg.render import format_suricata_cell
        alerts = [{"sid": 2001219}, {"signature": "no sid here"}]
        assert format_suricata_cell(alerts) == "1 (2001219)"

    def test_non_int_sid_skipped(self):
        # Same hygiene as verdict.classify -- stringly-typed sid is harvest bug.
        from agent_orange_pkg.render import format_suricata_cell
        alerts = [{"sid": 2001219}, {"sid": "2002383"}]
        assert format_suricata_cell(alerts) == "1 (2001219)"

    def test_sids_sorted_ascending_for_stable_output(self):
        from agent_orange_pkg.render import format_suricata_cell
        alerts = [{"sid": 9000003}, {"sid": 2001219}]
        assert format_suricata_cell(alerts) == "2 (2001219, 9000003)"


class TestFormatZeekCell:
    """Zeek column: '0 or --' / 'N (NoticeType1, NoticeType2)' / 'N (NoticeType1, NoticeType2, +K more)'.

    Truncation threshold is 2 (not 3 like Suricata) because Zeek notice
    type strings are longer than SIDs.
    """

    def test_empty_renders_dash(self):
        from agent_orange_pkg.render import format_zeek_cell
        assert format_zeek_cell([]) == "\u2014"

    def test_none_input_renders_dash(self):
        from agent_orange_pkg.render import format_zeek_cell
        assert format_zeek_cell(None) == "\u2014"

    def test_single_notice(self):
        from agent_orange_pkg.render import format_zeek_cell
        notices = [{"note": "Scan::Port_Scan"}]
        assert format_zeek_cell(notices) == "1 (Scan::Port_Scan)"

    def test_two_notices_at_threshold_no_truncation(self):
        from agent_orange_pkg.render import format_zeek_cell
        notices = [{"note": "Scan::Port_Scan"}, {"note": "HTTP::SQL_Injection"}]
        assert format_zeek_cell(notices) == "2 (HTTP::SQL_Injection, Scan::Port_Scan)"

    def test_four_notices_truncate_to_two_plus_more(self):
        from agent_orange_pkg.render import format_zeek_cell
        notices = [
            {"note": "A"}, {"note": "B"}, {"note": "C"}, {"note": "D"},
        ]
        assert format_zeek_cell(notices) == "4 (A, B, +2 more)"

    def test_intel_synthesized_note_counts_as_regular_notice(self):
        # harvest.py synthesizes "Intel::<tag>" for Zeek Intel Framework
        # hits so they classify as notices. They should appear in the
        # Zeek cell the same as any other notice.
        from agent_orange_pkg.render import format_zeek_cell
        notices = [{"note": "Intel::DOMAIN"}]
        assert format_zeek_cell(notices) == "1 (Intel::DOMAIN)"

    def test_duplicate_note_types_deduped(self):
        from agent_orange_pkg.render import format_zeek_cell
        notices = [
            {"note": "Scan::Port_Scan"},
            {"note": "Scan::Port_Scan"},
            {"note": "Scan::Port_Scan"},
        ]
        assert format_zeek_cell(notices) == "1 (Scan::Port_Scan)"

    def test_missing_note_field_skipped(self):
        from agent_orange_pkg.render import format_zeek_cell
        notices = [{"note": "Scan::Port_Scan"}, {"msg": "no note here"}]
        assert format_zeek_cell(notices) == "1 (Scan::Port_Scan)"

    def test_empty_note_string_skipped(self):
        from agent_orange_pkg.render import format_zeek_cell
        notices = [{"note": "Scan::Port_Scan"}, {"note": ""}]
        assert format_zeek_cell(notices) == "1 (Scan::Port_Scan)"

    def test_notes_sorted_alphabetically_for_stable_output(self):
        from agent_orange_pkg.render import format_zeek_cell
        notices = [{"note": "Zeta"}, {"note": "Alpha"}]
        assert format_zeek_cell(notices) == "2 (Alpha, Zeta)"


class TestCharacterizeObservedLog:
    """Per-log-type one-liner generator for Evidence block Observed rows.

    For each known log type, extracts a key field; falls back to count
    only for unknown log types. Always returns a line like
    '<logname>.log: N entries (<summary>)' or just '<logname>.log: N entries'.
    """

    def test_empty_events_returns_count_zero_line(self):
        # Defensive -- caller should have filtered out empty; but if not,
        # helper must not crash.
        from agent_orange_pkg.render import _characterize_observed_log
        assert _characterize_observed_log("http.log", []) == "http.log: 0 entries"

    def test_software_log_extracts_user_agents(self):
        from agent_orange_pkg.render import _characterize_observed_log
        events = [
            {"software_type": "HTTP::BROWSER", "unparsed_version": "gobuster/3.8.2"},
            {"software_type": "HTTP::BROWSER", "unparsed_version": "gobuster/3.8.2"},
        ]
        out = _characterize_observed_log("software.log", events)
        assert "software.log: 2 entries" in out
        assert "gobuster/3.8.2" in out

    def test_files_log_extracts_mime_types(self):
        from agent_orange_pkg.render import _characterize_observed_log
        events = [
            {"mime_type": "application/x-dosexec"},
            {"mime_type": "text/html"},
        ]
        out = _characterize_observed_log("files.log", events)
        assert "files.log: 2 entries" in out
        assert "x-dosexec" in out or "text/html" in out

    def test_ssl_log_extracts_sni(self):
        from agent_orange_pkg.render import _characterize_observed_log
        events = [
            {"server_name": "trycloudflare.com"},
            {"server_name": "abc.trycloudflare.com"},
        ]
        out = _characterize_observed_log("ssl.log", events)
        assert "ssl.log: 2 entries" in out
        assert "trycloudflare.com" in out

    def test_ftp_log_counts_auth_failures(self):
        from agent_orange_pkg.render import _characterize_observed_log
        events = [
            {"command": "PASS", "reply_code": 530},
            {"command": "PASS", "reply_code": 530},
            {"command": "USER"},
        ]
        out = _characterize_observed_log("ftp.log", events)
        assert "ftp.log: 3 entries" in out
        assert "2 auth" in out or "530" in out

    def test_dns_log_extracts_queries(self):
        from agent_orange_pkg.render import _characterize_observed_log
        events = [{"query": "evil.example.com"}, {"query": "test.local"}]
        out = _characterize_observed_log("dns.log", events)
        assert "dns.log: 2 entries" in out
        assert "evil.example.com" in out or "test.local" in out

    def test_http_log_extracts_host(self):
        from agent_orange_pkg.render import _characterize_observed_log
        events = [{"host": "victim.local", "uri": "/a"}, {"host": "victim.local", "uri": "/b"}]
        out = _characterize_observed_log("http.log", events)
        assert "http.log: 2 entries" in out
        assert "victim.local" in out

    def test_conn_log_counts_flows(self):
        from agent_orange_pkg.render import _characterize_observed_log
        events = [{"uid": "C1"}, {"uid": "C2"}, {"uid": "C3"}]
        out = _characterize_observed_log("conn.log", events)
        assert "conn.log: 3 entries" in out
        assert "flow" in out.lower()

    def test_unknown_log_falls_back_to_count_only(self):
        from agent_orange_pkg.render import _characterize_observed_log
        events = [{"foo": "bar"}, {"foo": "baz"}]
        assert _characterize_observed_log("mystery.log", events) == "mystery.log: 2 entries"


# ---------------------------------------------------------------------------
#  ledger_to_dict
# ---------------------------------------------------------------------------

class TestLedgerToDict:
    def test_produces_json_serializable_shape(self):
        ledger = make_ledger()
        d = ledger_to_dict(ledger)
        # Round-trips through json without raising.
        json.dumps(d)

    def test_summary_block_matches_helpers(self):
        ledger = make_ledger(entries=[
            make_entry(make_attack("a"), verdict="DETECTED_EXPECTED"),
            make_entry(make_attack("b"), verdict="UNDETECTED"),
        ])
        d = ledger_to_dict(ledger)
        s = d["summary"]
        assert s["total_attacks"] == 2
        assert s["detected"] == 1
        assert s["coverage_pct"] == 50.0
        assert s["verdict_counts"] == {
            "DETECTED_EXPECTED": 1, "UNDETECTED": 1,
        }

    def test_enabled_sids_flattened_to_sorted_list(self):
        ledger = make_ledger(snapshot_sids=frozenset({3, 1, 2}))
        d = ledger_to_dict(ledger)
        assert d["ruleset_snapshot"]["enabled_sids"] == [1, 2, 3]

    def test_drift_sids_sorted(self):
        ledger = make_ledger(drift=RulesetDrift(
            added_sids=frozenset({5, 2}),
            removed_sids=frozenset({9, 7}),
            hash_changed=True,
        ))
        d = ledger_to_dict(ledger)
        assert d["ruleset_drift"]["added_sids"] == [2, 5]
        assert d["ruleset_drift"]["removed_sids"] == [7, 9]


# ---------------------------------------------------------------------------
#  write_json
# ---------------------------------------------------------------------------

class TestWriteJson:
    def test_writes_file(self, tmp_path: Path):
        ledger = make_ledger()
        out = tmp_path / "ledger.json"
        write_json(ledger, out)
        assert out.exists()
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["run_id"] == ledger.run_id
        assert "summary" in data

    def test_creates_parent_dirs(self, tmp_path: Path):
        ledger = make_ledger()
        out = tmp_path / "nested" / "dir" / "ledger.json"
        write_json(ledger, out)
        assert out.exists()


# ---------------------------------------------------------------------------
#  render_markdown
# ---------------------------------------------------------------------------

class TestRenderMarkdown:
    def test_contains_run_id_and_summary(self):
        ledger = make_ledger()
        md = render_markdown(ledger)
        assert ledger.run_id in md
        assert "## Summary" in md

    def test_attack_table_contains_every_attack(self):
        ledger = make_ledger(entries=[
            make_entry(make_attack("art-one"), verdict="DETECTED_EXPECTED"),
            make_entry(make_attack("art-two"), verdict="UNDETECTED"),
        ])
        md = render_markdown(ledger)
        assert "`art-one`" in md
        assert "`art-two`" in md

    def test_unavailable_narrative_renders_notice(self):
        ledger = make_ledger(
            narrative=make_narrative(available=False, error="api key missing"),
        )
        md = render_markdown(ledger)
        assert "LLM narrative unavailable" in md
        assert "api key missing" in md

    def test_available_narrative_includes_exec_summary(self):
        ledger = make_ledger(
            narrative=make_narrative(
                available=True, exec_summary="50% coverage across ART.",
            ),
        )
        md = render_markdown(ledger)
        assert "## Executive summary" in md
        assert "50% coverage across ART." in md


# ---------------------------------------------------------------------------
#  render_html
# ---------------------------------------------------------------------------

class TestRenderHtml:
    def test_is_self_contained_document(self):
        html = render_html(make_ledger())
        assert html.startswith("<!doctype html>")
        assert html.endswith("</body></html>")
        assert "<style>" in html  # CSS inline
        assert "<link" not in html  # no external sheets

    def test_verdict_css_class_present_per_entry(self):
        ledger = make_ledger(entries=[
            make_entry(make_attack("a"), verdict="DETECTED_EXPECTED"),
            make_entry(make_attack("b"), verdict="FAILED"),
        ])
        html = render_html(ledger)
        assert "v-DETECTED_EXPECTED" in html
        assert "v-FAILED" in html

    def test_escapes_attack_name_with_html_special_chars(self):
        # Defensive: if an attack ever has HTML metacharacters in its
        # name (unlikely given snake-case convention, but possible for
        # rationale or commentary) the output must not break.
        attack = make_attack("art-<injection>")
        ledger = make_ledger(entries=[make_entry(attack, verdict="UNDETECTED")])
        html = render_html(ledger)
        assert "art-&lt;injection&gt;" in html
        assert "<injection>" not in html


# ---------------------------------------------------------------------------
#  render_stdout_summary
# ---------------------------------------------------------------------------

class TestRenderStdoutSummary:
    def test_contains_key_stats(self):
        ledger = make_ledger(entries=[
            make_entry(make_attack("a"), verdict="DETECTED_EXPECTED"),
            make_entry(make_attack("b"), verdict="UNDETECTED"),
        ])
        out = render_stdout_summary(ledger)
        assert "agent-orange run:" in out
        assert "attacks    : 2" in out
        assert "coverage   : 50.0%" in out
        assert "a" in out and "b" in out  # per-attack rows


# ---------------------------------------------------------------------------
#  write_markdown / write_html file emission
# ---------------------------------------------------------------------------

class TestFileEmission:
    def test_markdown_file_written(self, tmp_path: Path):
        out = tmp_path / "report.md"
        write_markdown(make_ledger(), out)
        assert out.exists()
        assert out.read_text(encoding="utf-8").startswith("# Agent Orange Run")

    def test_html_file_written(self, tmp_path: Path):
        out = tmp_path / "report.html"
        write_html(make_ledger(), out)
        assert out.exists()
        assert "<!doctype html>" in out.read_text(encoding="utf-8").lower()


# ---------------------------------------------------------------------------
#  Sensor-health section
# ---------------------------------------------------------------------------

class TestCountLoadedScripts:
    """Direct unit tests for the loaded-scripts counter helper.

    Complements the end-to-end TestSensorHealth tests which go through
    render_markdown; unit tests make failure localization faster and
    catch helper-level regressions that wouldn't surface in the
    rendered-string-shape assertions.
    """

    def _count(self, s: str) -> int:
        from agent_orange_pkg.render import _count_loaded_scripts
        return _count_loaded_scripts(s)

    def test_empty_input(self):
        assert self._count("") == 0

    def test_whitespace_only(self):
        assert self._count("\n  \n\t\n") == 0

    def test_json_only(self):
        text = (
            '{"name":"/a.zeek"}\n'
            '{"name":"/b.zeek"}\n'
            '{"name":"/c.zeek"}\n'
        )
        assert self._count(text) == 3

    def test_tsv_only(self):
        text = (
            "site/local.zeek\n"
            "base/main.zeek\n"
            "policy/protocols/ssh/software.zeek\n"
        )
        assert self._count(text) == 3

    def test_only_malformed(self):
        text = (
            "# header comment\n"
            "random prose\n"
            '{"no-name-field":"x"}\n'
            "{not-valid-json\n"
        )
        assert self._count(text) == 0

    def test_crlf_line_endings(self):
        # Windows CRLF occasionally sneaks in via tools that rewrite
        # captured text. splitlines() handles CR/LF/CRLF uniformly;
        # this test locks that in.
        text = '{"name":"/a.zeek"}\r\nsite/local.zeek\r\n'
        assert self._count(text) == 2

    def test_json_with_extra_whitespace_in_value(self):
        # Real Zeek indents nested scripts in the name field via
        # whitespace; leading spaces in the value shouldn't affect
        # the count.
        text = '{"name":"  /opt/zeek/share/zeek/base/bif/const.bif.zeek"}\n'
        assert self._count(text) == 1

    def test_mixed_json_and_tsv_dedup_not_required(self):
        # The counter is a straight tally, not a dedupe. Same script
        # name seen twice = count 2. This is intentional: we're
        # measuring Zeek's output volume, not unique scripts.
        text = (
            '{"name":"/a.zeek"}\n'
            "a.zeek\n"
        )
        assert self._count(text) == 2


class TestSensorHealth:
    def _ledger_with_diagnostics(self, stats_text="", scripts_text=""):
        # Build a ledger with custom zeek_stats / zeek_loaded_scripts.
        from dataclasses import replace
        base = make_ledger()
        return replace(base, zeek_stats=stats_text, zeek_loaded_scripts=scripts_text)

    def test_html_shows_dropped_packets_warning(self):
        from agent_orange_pkg.render import render_html
        stats = "peer=zeek interval=15 pkts_dropped=42 pkts_link=10000\n"
        ledger = self._ledger_with_diagnostics(stats_text=stats)
        html = render_html(ledger)
        assert "Sensor health" in html
        assert "42" in html
        assert "carry an asterisk" in html

    def test_html_zero_drops_shows_clean(self):
        from agent_orange_pkg.render import render_html
        stats = "peer=zeek interval=15 pkts_dropped=0 pkts_link=10000\n"
        ledger = self._ledger_with_diagnostics(stats_text=stats)
        html = render_html(ledger)
        assert "Sensor health" in html
        assert "Packets dropped during run: 0" in html

    def test_html_not_captured_shows_caution(self):
        ledger = self._ledger_with_diagnostics()  # both empty
        from agent_orange_pkg.render import render_html
        html = render_html(ledger)
        assert "not captured" in html
        assert "UNDETECTED verdicts below should be read cautiously" in html

    def test_loaded_scripts_missing_but_stats_present_shows_na(self):
        # Common reality: Zeek rotates loaded_scripts.log to the daily
        # archive at the first hour boundary after zeek_init and never
        # recreates it. Runs after that rotation capture stats.log
        # fine but loaded_scripts.log is empty. Report must NOT say
        # "Zeek scripts loaded: 0" -- that misleadingly implies nothing
        # is loaded when really the log just isn't available to harvest.
        from agent_orange_pkg.render import render_markdown, render_html
        stats = "peer=zeek interval=15 pkts_dropped=0 pkts_link=10000\n"
        ledger = self._ledger_with_diagnostics(
            stats_text=stats, scripts_text="",
        )
        md = render_markdown(ledger)
        html = render_html(ledger)
        # Must not assert a concrete count when the log wasn't captured.
        assert "Zeek scripts loaded: 0" not in md
        assert "Zeek scripts loaded: 0" not in html
        # Must communicate that the log wasn't available.
        assert "n/a" in md or "not available" in md or "not captured" in md
        assert "n/a" in html or "not available" in html or "not captured" in html

    def test_markdown_reports_loaded_script_count(self):
        from agent_orange_pkg.render import render_markdown
        scripts = (
            "site/local.zeek\n"
            "policy/frameworks/intel/seen.zeek\n"
            "base/protocols/http/main.zeek\n"
        )
        ledger = self._ledger_with_diagnostics(scripts_text=scripts)
        md = render_markdown(ledger)
        assert "Zeek scripts loaded: 3" in md

    def test_markdown_reports_loaded_script_count_json_format(self):
        # When Zeek has `policy/tuning/json-logs` loaded (standalone.sh
        # does), loaded_scripts.log contains one JSON object per line
        # like {"name":"/path/script.zeek"} instead of the TSV-style
        # path-only format. Real live-lab output hits this case. The
        # old `^\s*\S+\.(zeek|bro)\s*$` regex matched zero on this input
        # despite the sensor having captured 576 entries.
        from agent_orange_pkg.render import render_markdown
        scripts = (
            '{"name":"/opt/zeek/share/zeek/base/init-bare.zeek"}\n'
            '{"name":"  /opt/zeek/share/zeek/base/bif/const.bif.zeek"}\n'
            '{"name":"/opt/zeek/share/zeek/site/local.zeek"}\n'
        )
        ledger = self._ledger_with_diagnostics(scripts_text=scripts)
        md = render_markdown(ledger)
        assert "Zeek scripts loaded: 3" in md

    def test_json_shaped_garbage_does_not_fall_through_to_tsv(self):
        # A line starting with `{` but not parsing as JSON with a name
        # key should NOT be counted via the TSV fallback -- JSON-shaped
        # lines are exclusively in the JSON path per the docstring.
        # Real Zeek never emits this, but the asymmetry matters for
        # the contract.
        from agent_orange_pkg.render import render_markdown
        scripts = (
            '{not-valid-json.zeek\n'           # must NOT count
            '{"name":"/path/good.zeek"}\n'     # counts via JSON
        )
        ledger = self._ledger_with_diagnostics(scripts_text=scripts)
        md = render_markdown(ledger)
        assert "Zeek scripts loaded: 1" in md

    def test_markdown_tolerates_mixed_and_malformed_lines(self):
        # A real loaded_scripts.log may have preamble lines and stray
        # whitespace. Defensive: malformed lines are skipped, good ones
        # count. Supports both JSON and TSV inputs side by side so a
        # future upstream change doesn't silently regress.
        from agent_orange_pkg.render import render_markdown
        scripts = (
            "# zeek header\n"                                            # skip
            "\n"                                                         # skip
            'garbage not a script\n'                                     # skip
            '{"name":"/path/a.zeek"}\n'                                  # count
            '{"notname":"missing"}\n'                                    # skip (no name key)
            'site/local.zeek\n'                                          # count (tsv fallback)
            '{"name":"/path/b.zeek"}\n'                                  # count
        )
        ledger = self._ledger_with_diagnostics(scripts_text=scripts)
        md = render_markdown(ledger)
        assert "Zeek scripts loaded: 3" in md

    def test_markdown_reports_drops_section(self):
        from agent_orange_pkg.render import render_markdown
        stats = "pkts_dropped=7\npkts_dropped=0\npkts_dropped=100\n"
        ledger = self._ledger_with_diagnostics(stats_text=stats)
        md = render_markdown(ledger)
        # 7 + 0 + 100 = 107 total
        assert "107" in md
