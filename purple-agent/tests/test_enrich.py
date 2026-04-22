"""Unit tests for purple_agent_pkg.enrich.

These tests exercise the pure-function core of the purple-team agent: the
write-time/read-time normalization rules (confidence, verdict, tool inference),
the Zeek visibility heuristic, and the full _enrich_findings pipeline.

They deliberately do NOT import purple_agent (top-level) or claude_agent_sdk —
the point of the extraction is that these guarantees can be validated without
the SDK being installed.

Run:
    pip install pytest pyyaml
    pytest purple-agent/tests/
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from purple_agent_pkg.enrich import (
    KEV_PROBES,
    MITRE_LOOKUP,
    TACTIC_SEVERITY,
    _enrich_findings,
    _has_zeek_visibility,
    _infer_tool,
    _load_findings,
    _normalize_confidence,
    _normalize_verdict,
)


# --------------------------------------------------------------------------
# _normalize_confidence
# --------------------------------------------------------------------------

class TestNormalizeConfidence:
    """Claimed confidence must be backed by hard evidence.

    Rules under test:
      - "high"/"partial" require a Suricata SID
      - "behavioral" requires a Zeek notice
      - any violation is downgraded to "none" and flagged was_corrected=True
    """

    def test_high_without_sids_is_downgraded(self):
        conf, corrected = _normalize_confidence("high", [], [])
        assert conf == "none"
        assert corrected is True

    def test_high_with_sid_is_preserved(self):
        conf, corrected = _normalize_confidence("high", ["2034567"], [])
        assert conf == "high"
        assert corrected is False

    def test_partial_without_sids_is_downgraded(self):
        conf, corrected = _normalize_confidence("partial", [], ["Scan::Port_Scan"])
        assert conf == "none"
        assert corrected is True

    def test_partial_with_sid_is_preserved(self):
        conf, corrected = _normalize_confidence("partial", ["2100498"], [])
        assert conf == "partial"
        assert corrected is False

    def test_behavioral_without_notice_is_downgraded(self):
        conf, corrected = _normalize_confidence("behavioral", [], [])
        assert conf == "none"
        assert corrected is True

    def test_behavioral_with_notice_is_preserved(self):
        conf, corrected = _normalize_confidence(
            "behavioral", [], ["SSH::Password_Guessing"]
        )
        assert conf == "behavioral"
        assert corrected is False

    def test_behavioral_with_sid_but_no_notice_is_downgraded(self):
        # behavioral MUST have a notice; a SID alone isn't enough for "behavioral"
        conf, corrected = _normalize_confidence("behavioral", ["2034567"], [])
        assert conf == "none"
        assert corrected is True

    def test_none_is_passthrough(self):
        conf, corrected = _normalize_confidence("none", [], [])
        assert conf == "none"
        assert corrected is False

    def test_empty_claim_is_passthrough(self):
        conf, corrected = _normalize_confidence("", [], [])
        assert conf == ""
        assert corrected is False

    def test_case_insensitive(self):
        # The function lowercases the input before deciding.
        conf, corrected = _normalize_confidence("HIGH", ["2034567"], [])
        assert conf == "high"
        assert corrected is False


# --------------------------------------------------------------------------
# _normalize_verdict
# --------------------------------------------------------------------------

class TestNormalizeVerdict:
    """Legacy verdicts (PROMOTE/SKIP/GAP/FP) map onto the 3-state taxonomy."""

    def test_detected_passthrough(self):
        assert _normalize_verdict("DETECTED") == ("DETECTED", False)

    def test_promote_becomes_detected(self):
        # Legacy ledgers used PROMOTE for "this should be added to CI catalog"
        assert _normalize_verdict("PROMOTE") == ("DETECTED", False)

    def test_skip_becomes_detected(self):
        # Legacy SKIP meant "already detected, skip adding again"
        assert _normalize_verdict("SKIP") == ("DETECTED", False)

    def test_undetected_passthrough(self):
        assert _normalize_verdict("UNDETECTED") == ("UNDETECTED", False)

    def test_gap_becomes_undetected(self):
        # Legacy GAP == rule-engineering target == UNDETECTED
        assert _normalize_verdict("GAP") == ("UNDETECTED", False)

    def test_fp_becomes_undetected_with_flag(self):
        # FP preserves false-positive nuance via the fp_flag
        v, fp = _normalize_verdict("FP")
        assert v == "UNDETECTED"
        assert fp is True

    def test_error_passthrough(self):
        assert _normalize_verdict("ERROR") == ("ERROR", False)

    def test_lowercase_input_upcased(self):
        assert _normalize_verdict("detected") == ("DETECTED", False)

    def test_unknown_verdict_passes_through(self):
        v, fp = _normalize_verdict("WEIRDSTATE")
        assert v == "WEIRDSTATE"
        assert fp is False

    def test_none_input(self):
        v, fp = _normalize_verdict(None)
        assert v == ""
        assert fp is False


# --------------------------------------------------------------------------
# _infer_tool
# --------------------------------------------------------------------------

class TestInferTool:
    """Best-effort tool inference from an arbitrary command string."""

    def test_curl(self):
        assert _infer_tool("curl -sS http://victim/path") == "curl"

    def test_nmap(self):
        assert _infer_tool("nmap -sS -p- 172.31.78.152") == "nmap"

    def test_impacket(self):
        assert _infer_tool("impacket-secretsdump administrator@dc.local") == "impacket"

    def test_sqlmap(self):
        assert _infer_tool("sqlmap -u http://victim/login") == "sqlmap"

    def test_nikto(self):
        assert _infer_tool("nikto -h victim") == "nikto"

    def test_nuclei(self):
        assert _infer_tool("nuclei -t cves/ -u http://victim") == "nuclei"

    def test_hydra(self):
        assert _infer_tool("hydra -l admin -P pass.txt ssh://victim") == "hydra"

    def test_python3(self):
        assert _infer_tool("python3 -c 'import socket;...'") == "python3"

    def test_bash_fallback(self):
        # No recognized tool word → "bash" fallback.
        assert _infer_tool("echo hello | base64") == "bash"

    def test_empty_command_returns_empty(self):
        # Empty returns "", NOT "bash" — callers distinguish "no command"
        # from "command with no recognized tool".
        assert _infer_tool("") == ""

    def test_none_command_returns_empty(self):
        assert _infer_tool(None) == ""


# --------------------------------------------------------------------------
# _has_zeek_visibility
# --------------------------------------------------------------------------

class TestHasZeekVisibility:
    """zeek_signals is a free-text field; negative-assertion strings must not
    count as visibility."""

    def test_empty_string(self):
        assert _has_zeek_visibility({"zeek_signals": ""}) is False

    def test_missing_field(self):
        assert _has_zeek_visibility({}) is False

    def test_none_value(self):
        assert _has_zeek_visibility({"zeek_signals": None}) is False

    def test_positive_signal(self):
        assert _has_zeek_visibility(
            {"zeek_signals": "http.log: Host=victim, URI=/api/v1"}
        ) is True

    def test_negative_no(self):
        assert _has_zeek_visibility(
            {"zeek_signals": "no Kerberos log entries"}
        ) is False

    def test_negative_none(self):
        assert _has_zeek_visibility(
            {"zeek_signals": "None observed"}
        ) is False

    def test_negative_connection_refused(self):
        assert _has_zeek_visibility(
            {"zeek_signals": "connection refused at SYN"}
        ) is False

    def test_negative_tcp_refused(self):
        assert _has_zeek_visibility(
            {"zeek_signals": "TCP/88 refused at SYN"}
        ) is False

    def test_leading_whitespace_stripped(self):
        assert _has_zeek_visibility(
            {"zeek_signals": "   no visibility"}
        ) is False


# --------------------------------------------------------------------------
# _load_findings
# --------------------------------------------------------------------------

class TestLoadFindings:
    def test_missing_file_returns_empty(self, tmp_path):
        assert _load_findings(tmp_path / "nope.jsonl") == []

    def test_empty_file_returns_empty(self, tmp_path):
        p = tmp_path / "empty.jsonl"
        p.write_text("", encoding="utf-8")
        assert _load_findings(p) == []

    def test_loads_jsonl(self, tmp_path):
        p = tmp_path / "findings.jsonl"
        p.write_text(
            '{"probe": "a", "verdict": "DETECTED"}\n'
            '{"probe": "b", "verdict": "UNDETECTED"}\n',
            encoding="utf-8",
        )
        out = _load_findings(p)
        assert len(out) == 2
        assert out[0]["probe"] == "a"
        assert out[1]["verdict"] == "UNDETECTED"

    def test_skips_bad_lines(self, tmp_path):
        p = tmp_path / "mixed.jsonl"
        p.write_text(
            '{"probe": "a"}\n'
            'not json\n'
            '{"probe": "b"}\n'
            '\n',
            encoding="utf-8",
        )
        out = _load_findings(p)
        assert [f["probe"] for f in out] == ["a", "b"]


# --------------------------------------------------------------------------
# _enrich_findings — the full pipeline
# --------------------------------------------------------------------------

class TestEnrichFindings:
    """End-to-end enrichment: verdict normalization + MITRE resolution +
    severity derivation + KEV override + Zeek notice/weird split."""

    def test_empty_list(self):
        assert _enrich_findings([], None) == []

    def test_kev_undetected_is_critical(self):
        """KEV-listed + UNDETECTED → Critical, overriding tactic map."""
        raw = [{
            "probe": "citrixbleed-2-cve-2025-5777",  # in KEV_PROBES
            "verdict": "UNDETECTED",
            "mitre_id": "T1190",  # Initial Access (Critical anyway, but KEV path wins)
        }]
        out = _enrich_findings(raw, None)
        assert len(out) == 1
        assert out[0]["severity"] == "Critical"
        assert out[0]["kev"] is True

    def test_fp_is_low_severity(self):
        raw = [{"probe": "p", "verdict": "FP", "mitre_id": "T1190"}]
        out = _enrich_findings(raw, None)
        assert out[0]["verdict"] == "UNDETECTED"
        assert out[0]["fp"] is True
        assert out[0]["severity"] == "Low"

    def test_detected_is_info(self):
        raw = [{
            "probe": "p",
            "verdict": "DETECTED",
            "mitre_id": "T1190",
            "fired_sids": ["2034567"],
        }]
        out = _enrich_findings(raw, None)
        assert out[0]["severity"] == "Info"

    def test_undetected_uses_tactic_map(self):
        raw = [{"probe": "p", "verdict": "UNDETECTED", "mitre_id": "T1595"}]
        out = _enrich_findings(raw, None)
        assert out[0]["mitre_tactic"] == "Reconnaissance"
        assert out[0]["severity"] == "Low"  # Reconnaissance → Low

    def test_zeek_notices_weird_split(self):
        """notice.log entries have namespace (X::Y); weird.log don't. The
        enricher migrates misplaced weird names out of zeek_notices."""
        raw = [{
            "probe": "p",
            "verdict": "UNDETECTED",
            "mitre_id": "T1046",
            "zeek_notices": ["Scan::Port_Scan", "bad_HTTP_request"],
            "zeek_weird": ["data_before_established"],
        }]
        out = _enrich_findings(raw, None)
        assert out[0]["zeek_notices"] == ["Scan::Port_Scan"]
        assert set(out[0]["zeek_weird"]) == {
            "data_before_established", "bad_HTTP_request",
        }

    def test_confidence_downgraded_records_claimed(self):
        """If normalization corrects an inflated claim, the original is stashed
        in claimed_confidence for the report."""
        raw = [{
            "probe": "p",
            "verdict": "DETECTED",
            "mitre_id": "T1190",
            "confidence": "high",
            "fired_sids": [],  # no evidence for "high"
        }]
        out = _enrich_findings(raw, None)
        assert out[0]["confidence"] == "none"
        assert out[0]["claimed_confidence"] == "high"

    def test_severity_sort(self):
        """Enriched list sorts by severity (Critical → Info) then probe name."""
        raw = [
            {"probe": "bbb", "verdict": "DETECTED", "mitre_id": "T1190",
             "fired_sids": ["1"]},  # Info
            {"probe": "aaa", "verdict": "UNDETECTED",
             "mitre_id": "T1190"},  # Critical (Initial Access)
            {"probe": "ccc", "verdict": "UNDETECTED",
             "mitre_id": "T1595"},  # Low (Reconnaissance)
        ]
        out = _enrich_findings(raw, None)
        assert [f["probe"] for f in out] == ["aaa", "ccc", "bbb"]


# --------------------------------------------------------------------------
# Sanity checks on the constants themselves
# --------------------------------------------------------------------------

class TestConstantsIntegrity:
    def test_mitre_lookup_has_entries(self):
        assert len(MITRE_LOOKUP) > 50, "MITRE_LOOKUP should be substantial"

    def test_every_mitre_entry_has_required_keys(self):
        for tid, meta in MITRE_LOOKUP.items():
            assert "tactic" in meta, f"{tid} missing tactic"
            assert "name" in meta, f"{tid} missing name"
            assert "url" in meta, f"{tid} missing url"

    def test_every_mitre_tactic_is_in_severity_map(self):
        """Guards against new MITRE entries using a tactic that the severity
        derivation doesn't know how to weight."""
        for tid, meta in MITRE_LOOKUP.items():
            tactic = meta["tactic"]
            assert tactic in TACTIC_SEVERITY, (
                f"{tid}'s tactic {tactic!r} not in TACTIC_SEVERITY"
            )

    def test_kev_probes_nonempty(self):
        assert len(KEV_PROBES) > 0
