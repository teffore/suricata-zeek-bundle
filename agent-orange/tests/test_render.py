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
