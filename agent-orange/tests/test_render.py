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


class TestRenderEvidenceBlock:
    """Full Evidence subblock: Suricata alerts / Zeek notices / Observed.

    Returns a string with `\\n` line separators (Markdown). HTML rendering
    happens in the HTML wire-up task; this helper emits Markdown form.
    """

    def _entry(self, **overrides):
        from tests._ledger_fixtures import make_attack, make_entry
        defaults = dict(
            attack=make_attack(),
            verdict="DETECTED_UNEXPECTED",
            alerts=(),
            notices=(),
            observed=None,
        )
        defaults.update(overrides)
        # make_entry already returns an AttackLedgerEntry
        return make_entry(**defaults)

    def test_all_three_subsections_present(self):
        from agent_orange_pkg.render import render_evidence_block
        from tests._ledger_fixtures import make_attack, make_entry
        entry = make_entry(
            make_attack("art-example"),
            verdict="DETECTED_EXPECTED",
            alerts=[{"sid": 2001219, "signature": "ET scan"}],
            notices=[{"note": "Scan::Port_Scan", "msg": "detected"}],
            observed={"http.log": ({"host": "victim.local"},)},
        )
        out = render_evidence_block(entry)
        assert "Evidence:" in out
        assert "Suricata alerts (1)" in out
        assert "Zeek notices (1)" in out
        assert "Observed" in out
        assert "2001219" in out
        assert "ET scan" in out
        assert "Scan::Port_Scan" in out
        assert "http.log" in out

    def test_zeek_only_drops_empty_suricata_subsection(self):
        from agent_orange_pkg.render import render_evidence_block
        from tests._ledger_fixtures import make_attack, make_entry
        entry = make_entry(
            make_attack("art-zeek-only"),
            verdict="DETECTED_UNEXPECTED",
            alerts=[],
            notices=[{"note": "Scan::Port_Scan"}],
            observed=None,
        )
        out = render_evidence_block(entry)
        assert "Suricata alerts" not in out
        assert "Zeek notices (1)" in out

    def test_failed_row_entire_block_skipped(self):
        # When all three subsections empty, block header is also dropped.
        from agent_orange_pkg.render import render_evidence_block
        from tests._ledger_fixtures import make_attack, make_entry
        entry = make_entry(
            make_attack("art-failed"),
            verdict="FAILED",
            alerts=[],
            notices=[],
            observed=None,
        )
        out = render_evidence_block(entry)
        assert out == ""

    def test_missing_signature_field_renders_sid_alone(self):
        # No trailing em-dash-quote when signature is absent.
        from agent_orange_pkg.render import render_evidence_block
        from tests._ledger_fixtures import make_attack, make_entry
        entry = make_entry(
            make_attack("art-x"),
            alerts=[{"sid": 9000003}],
            notices=[],
            observed=None,
        )
        out = render_evidence_block(entry)
        assert "SID 9000003" in out
        assert "SID 9000003 \u2014" not in out  # no em-dash-quote
        assert 'SID 9000003 "' not in out

    def test_missing_notice_msg_renders_note_alone(self):
        from agent_orange_pkg.render import render_evidence_block
        from tests._ledger_fixtures import make_attack, make_entry
        entry = make_entry(
            make_attack("art-x"),
            alerts=[],
            notices=[{"note": "HTTP::SQL_Injection"}],
            observed=None,
        )
        out = render_evidence_block(entry)
        assert "HTTP::SQL_Injection" in out
        assert "HTTP::SQL_Injection \u2014" not in out

    def test_observed_only_attack_renders_observed_section(self):
        # OBSERVED is not a verdict -- a probe caught by Zeek protocol
        # logs but zero rules fired is still UNDETECTED. The Evidence
        # block must show the observed section so the gap is visible.
        from agent_orange_pkg.render import render_evidence_block
        from tests._ledger_fixtures import make_attack, make_entry
        entry = make_entry(
            make_attack("art-observed-only"),
            verdict="UNDETECTED",
            alerts=[],
            notices=[],
            observed={"software.log": ({"unparsed_version": "gobuster/3.8.2"},)},
        )
        out = render_evidence_block(entry)
        assert "Observed" in out
        assert "software.log" in out
        assert "gobuster" in out
        assert "Suricata alerts" not in out
        assert "Zeek notices" not in out

    def test_severity_included_when_present(self):
        from agent_orange_pkg.render import render_evidence_block
        from tests._ledger_fixtures import make_attack, make_entry
        entry = make_entry(
            make_attack("art-x"),
            alerts=[{"sid": 2002383, "signature": "ET SCAN Hydra FTP", "severity": 2}],
            notices=[],
            observed=None,
        )
        out = render_evidence_block(entry)
        assert "severity 2" in out


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

    def test_ledger_to_dict_keys_unchanged_across_rerender(self):
        # Guard against anyone adding a new key to ledger_to_dict's output
        # while "just rewiring the renderer". The contract for JSON
        # consumers (future CI gates, diff scripts) is key-stable.
        ledger = make_ledger()
        first = ledger_to_dict(ledger)
        second = ledger_to_dict(ledger)

        def deep_keys(obj, prefix=""):
            found = set()
            if isinstance(obj, dict):
                for k, v in obj.items():
                    path = f"{prefix}.{k}" if prefix else k
                    found.add(path)
                    found |= deep_keys(v, path)
            elif isinstance(obj, list) and obj:
                # Only descend first element; lists of dicts should be
                # key-homogeneous.
                found |= deep_keys(obj[0], f"{prefix}[]")
            return found

        assert deep_keys(first) == deep_keys(second)
        # Spot-check expected top-level keys stayed
        top = set(first.keys())
        assert {
            "run_id", "started_at", "ended_at", "victim_ip", "attacks",
            "ruleset_snapshot", "narrative", "summary",
        } <= top


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

    def test_attack_table_has_suricata_and_zeek_columns(self):
        # Main-table column header must be split.
        ledger = make_ledger(entries=[
            make_entry(make_attack("art-one"), verdict="DETECTED_EXPECTED"),
            make_entry(make_attack("art-two"), verdict="UNDETECTED"),
        ])
        md = render_markdown(ledger)
        assert "`art-one`" in md
        assert "`art-two`" in md
        assert "Suricata" in md
        assert "Zeek" in md
        assert "Fired SIDs" not in md  # old column name must be gone

    def test_verdict_badge_used_not_raw_tier(self):
        # The visible verdict must use the badge, never the raw tier.
        ledger = make_ledger(entries=[
            make_entry(make_attack("a"), verdict="DETECTED_EXPECTED"),
            make_entry(make_attack("b"), verdict="DETECTED_UNEXPECTED"),
            make_entry(make_attack("c"), verdict="UNDETECTED"),
        ])
        md = render_markdown(ledger)
        # Exact-match gets the checkmark
        assert "DETECTED \u2713" in md
        # UNEXPECTED renders as plain DETECTED, NOT the raw tier name
        assert "DETECTED_UNEXPECTED" not in md
        assert "UNDETECTED" in md

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

    def test_evidence_block_appears_for_attacks_with_evidence(self):
        # Per-attack analysis section must include the new Evidence block.
        ledger = make_ledger(entries=[
            make_entry(
                make_attack("art-fires"),
                verdict="DETECTED_UNEXPECTED",
                alerts=[{"sid": 2001219, "signature": "ET scan"}],
                notices=[{"note": "Scan::Port_Scan"}],
            ),
        ])
        md = render_markdown(ledger)
        assert "Evidence:" in md
        assert "Suricata alerts (1)" in md
        assert "2001219" in md
        assert "Scan::Port_Scan" in md

    def test_failed_attack_omits_evidence_block_entirely(self):
        ledger = make_ledger(entries=[
            make_entry(
                make_attack("art-failed"),
                verdict="FAILED",
                status="FAILED",
                alerts=[],
                notices=[],
            ),
        ])
        md = render_markdown(ledger)
        # Evidence header must NOT appear under a FAILED attack with no data
        attack_section_start = md.find("art-failed")
        if attack_section_start != -1:
            # Only look in that attack's section (up to next ### or end)
            after = md[attack_section_start:]
            assert "Evidence:" not in after[:500]


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

    def test_css_classes_still_keyed_off_internal_tier(self):
        # HTML classes are stable even though visible text changes.
        ledger = make_ledger(entries=[
            make_entry(make_attack("a"), verdict="DETECTED_EXPECTED"),
            make_entry(make_attack("b"), verdict="FAILED"),
        ])
        html = render_html(ledger)
        assert "v-DETECTED_EXPECTED" in html
        assert "v-FAILED" in html

    def test_verdict_visible_text_uses_badge_not_raw_tier(self):
        ledger = make_ledger(entries=[
            make_entry(make_attack("a"), verdict="DETECTED_EXPECTED"),
            make_entry(make_attack("b"), verdict="DETECTED_UNEXPECTED"),
        ])
        html = render_html(ledger)
        # The span's displayed text uses the badge
        assert ">DETECTED \u2713<" in html
        assert ">DETECTED<" in html
        # The UNEXPECTED word never appears in visible prose. CSS class
        # names (v-DETECTED_UNEXPECTED) are allowed -- they're inside
        # attribute values OR inside <style>...</style> where they're
        # selectors, not displayed text.
        import re
        body_only = re.sub(
            r"<style>.*?</style>", "", html, flags=re.DOTALL,
        )
        assert re.search(r">[^<]*UNEXPECTED[^<]*<", body_only) is None

    def test_attack_table_has_suricata_and_zeek_columns(self):
        ledger = make_ledger(entries=[
            make_entry(make_attack("art-one"), verdict="DETECTED_EXPECTED"),
        ])
        html = render_html(ledger)
        assert "<th>Suricata</th>" in html
        assert "<th>Zeek</th>" in html
        assert "<th>Fired SIDs</th>" not in html

    def test_escapes_attack_name_with_html_special_chars(self):
        attack = make_attack("art-<injection>")
        ledger = make_ledger(entries=[make_entry(attack, verdict="UNDETECTED")])
        html = render_html(ledger)
        assert "art-&lt;injection&gt;" in html
        assert "<injection>" not in html

    def test_evidence_block_appears_in_per_attack_section(self):
        ledger = make_ledger(entries=[
            make_entry(
                make_attack("art-fires"),
                verdict="DETECTED_UNEXPECTED",
                alerts=[{"sid": 2001219, "signature": "ET scan"}],
                notices=[{"note": "Scan::Port_Scan"}],
            ),
        ])
        html = render_html(ledger)
        # Evidence markup present (Markdown block rendered inside HTML)
        assert "Evidence:" in html or "<h4>Evidence" in html
        assert "2001219" in html
        assert "Scan::Port_Scan" in html


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

    def test_per_attack_rows_use_ascii_badge(self):
        ledger = make_ledger(entries=[
            make_entry(make_attack("alpha"), verdict="DETECTED_EXPECTED"),
            make_entry(make_attack("beta"), verdict="DETECTED_UNEXPECTED"),
            make_entry(make_attack("gamma"), verdict="FAILED", status="FAILED"),
        ])
        out = render_stdout_summary(ledger)
        # ASCII badge in stdout -- no unicode checkmark
        assert "DETECTED [x]" in out
        assert "\u2713" not in out
        # UNEXPECTED word is never emitted
        assert "UNEXPECTED" not in out

    def test_columns_are_suri_and_zeek_not_sids(self):
        ledger = make_ledger()
        out = render_stdout_summary(ledger)
        assert "suri" in out
        assert "zeek" in out
        # Old header "sids" must be gone
        header_line = next(
            (line for line in out.splitlines()
             if "#" in line and "attack" in line),
            "",
        )
        assert "sids" not in header_line

    def test_per_attack_row_shows_suri_and_zeek_counts(self):
        ledger = make_ledger(entries=[
            make_entry(
                make_attack("art-fires"),
                verdict="DETECTED_UNEXPECTED",
                alerts=[{"sid": 1}, {"sid": 2}],
                notices=[{"note": "A"}],
            ),
        ])
        out = render_stdout_summary(ledger)
        # Look for a line mentioning art-fires that has both counts
        row = next(
            (line for line in out.splitlines() if "art-fires" in line),
            "",
        )
        assert "2" in row  # Suricata count
        assert "1" in row  # Zeek count


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


# ---------------------------------------------------------------------------
#  End-to-end regression against captured real run
# ---------------------------------------------------------------------------


class TestCapturedRunRegression:
    """Load the first real Agent Orange run's ledger.json and exercise the
    new renderers against it. Catches field-shape drift between
    harvest/runner output and render expectations that unit tests miss.
    """

    FIXTURE_RUN_ID = "20260423T185508Z"

    def _load_captured_ledger(self):
        from pathlib import Path
        import json
        p = (
            Path(__file__).resolve().parent.parent / "runs"
            / self.FIXTURE_RUN_ID / "ledger.json"
        )
        if not p.exists():
            import pytest
            pytest.skip(f"fixture not present: {p}")
        return json.loads(p.read_text(encoding="utf-8"))

    def _rehydrate_ledger(self, raw):
        # Minimal rehydration: render functions only need a RunLedger-like
        # object with the fields they access.
        from agent_orange_pkg.catalog import Attack, Target
        from agent_orange_pkg.ledger import (
            AttackLedgerEntry, Narrative, RunLedger,
        )
        from agent_orange_pkg.ruleset import RulesetSnapshot
        from agent_orange_pkg.runner import AttackRun

        entries = []
        for a in raw["attacks"]:
            am = a["attack"]
            rm = a["run"]
            attack = Attack(
                name=am["name"], mitre=am["mitre"],
                source=am.get("source", "atomic-red-team"),
                art_test=am.get("art_test", ""),
                rationale=am.get("rationale", ""),
                target=Target(
                    type=am["target"]["type"],
                    value=am["target"]["value"],
                ),
                expected_sids=tuple(am.get("expected_sids") or ()),
                expected_zeek_notices=tuple(am.get("expected_zeek_notices") or ()),
                expected_verdict=am.get("expected_verdict", "UNDETECTED"),
                command=am.get("command", ""),
                timeout=am.get("timeout", 45),
            )
            run = AttackRun(
                attack_name=rm.get("attack_name", attack.name),
                mitre=rm.get("mitre", attack.mitre),
                art_test=rm.get("art_test", attack.art_test),
                target=Target(
                    type=rm["target"]["type"],
                    value=rm["target"]["value"],
                ),
                substituted_command=rm.get("substituted_command", ""),
                probe_start_ts=rm.get("probe_start_ts", 0.0),
                probe_end_ts=rm.get("probe_end_ts", 0.0),
                status=rm.get("status", "RAN"),
                exit_code=rm.get("exit_code"),
                stdout=rm.get("stdout", ""),
                stderr=rm.get("stderr", ""),
                error=rm.get("error", ""),
                timed_out=rm.get("timed_out", False),
            )
            entries.append(AttackLedgerEntry(
                attack=attack, run=run, verdict=a["verdict"],
                attributed_alerts=tuple(a.get("attributed_alerts") or ()),
                attributed_notices=tuple(a.get("attributed_notices") or ()),
                observed_evidence={
                    k: tuple(v) for k, v in
                    (a.get("observed_evidence") or {}).items()
                },
            ))

        snap_raw = raw.get("ruleset_snapshot") or {}
        snapshot = RulesetSnapshot(
            enabled_sids=frozenset(snap_raw.get("enabled_sids") or ()),
            hash=snap_raw.get("hash", ""),
            captured_at=snap_raw.get("captured_at", 0.0),
        )
        n_raw = raw.get("narrative") or {}
        narrative = Narrative(
            available=bool(n_raw.get("available")),
            exec_summary=n_raw.get("exec_summary", ""),
            per_attack_commentary=dict(n_raw.get("per_attack_commentary") or {}),
            remediation_suggestions=dict(n_raw.get("remediation_suggestions") or {}),
            drift_commentary=n_raw.get("drift_commentary", ""),
            generated_at=n_raw.get("generated_at", 0.0),
            model=n_raw.get("model", ""),
            error=n_raw.get("error", ""),
        )
        return RunLedger(
            run_id=raw["run_id"],
            started_at=raw.get("started_at", 0.0),
            ended_at=raw.get("ended_at", 0.0),
            victim_ip=raw.get("victim_ip", ""),
            sensor_host=raw.get("sensor_host", ""),
            attacker_host=raw.get("attacker_host", ""),
            attacks=tuple(entries),
            ruleset_snapshot=snapshot,
            ruleset_drift=None,
            zeek_loaded_scripts=raw.get("zeek_loaded_scripts", ""),
            zeek_stats=raw.get("zeek_stats", ""),
            narrative=narrative,
            agent_orange_version=raw.get("agent_orange_version", ""),
            attacks_yaml_path=raw.get("attacks_yaml_path", ""),
        )

    def test_markdown_renders_without_error(self):
        from agent_orange_pkg.render import render_markdown
        ledger = self._rehydrate_ledger(self._load_captured_ledger())
        md = render_markdown(ledger)
        assert len(md) > 0
        assert ledger.run_id in md

    def test_html_renders_without_error(self):
        from agent_orange_pkg.render import render_html
        ledger = self._rehydrate_ledger(self._load_captured_ledger())
        html = render_html(ledger)
        assert html.startswith("<!doctype html>")
        assert html.endswith("</body></html>")

    def test_markdown_attack_table_has_23_rows(self):
        from agent_orange_pkg.render import render_markdown
        ledger = self._rehydrate_ledger(self._load_captured_ledger())
        md = render_markdown(ledger)
        # count lines that look like "| N | `..." where N is an integer
        import re
        row_lines = [
            ln for ln in md.splitlines()
            if re.match(r"^\|\s*\d+\s*\|\s*`art-", ln)
        ]
        assert len(row_lines) == 23

    def test_every_attack_name_present_in_markdown(self):
        from agent_orange_pkg.render import render_markdown
        raw = self._load_captured_ledger()
        ledger = self._rehydrate_ledger(raw)
        md = render_markdown(ledger)
        for a in raw["attacks"]:
            assert a["attack"]["name"] in md

    def test_every_row_has_suricata_and_zeek_cells(self):
        # No cell should be blank / missing; "--" is acceptable.
        from agent_orange_pkg.render import render_markdown
        ledger = self._rehydrate_ledger(self._load_captured_ledger())
        md = render_markdown(ledger)
        import re
        for ln in md.splitlines():
            m = re.match(r"^\|\s*\d+\s*\|\s*`art-", ln)
            if not m:
                continue
            # Expected pipes: 8 (leading + between 7 cells + trailing)
            pipes = ln.count("|")
            assert pipes == 8, f"row has {pipes} pipes, not 8: {ln!r}"
