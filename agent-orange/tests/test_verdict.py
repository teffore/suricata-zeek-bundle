"""Unit tests for agent_orange_pkg.verdict.

Covers every verdict tier plus edge cases. Pure function tests with
in-memory alert/notice fixtures.

Run:
    cd agent-orange && pytest tests/test_verdict.py -q
"""

from __future__ import annotations

import pytest

from agent_orange_pkg.verdict import (
    ALL_VERDICTS,
    VERDICT_DETECTED_EXPECTED,
    VERDICT_DETECTED_PARTIAL,
    VERDICT_DETECTED_UNEXPECTED,
    VERDICT_FAILED,
    VERDICT_UNDETECTED,
    classify,
)


def alert(sid):
    return {"sid": sid}


def notice(note):
    return {"note": note}


class TestExpectedSignals:
    def test_all_expected_sids_fire_returns_detected_expected(self):
        assert classify(
            alerts=[alert(2001219), alert(2031502)],
            notices=[],
            expected_sids=[2001219, 2031502],
        ) == VERDICT_DETECTED_EXPECTED

    def test_all_expected_notices_fire_returns_detected_expected(self):
        assert classify(
            alerts=[],
            notices=[notice("Scan::Port_Scan")],
            expected_sids=[],
            expected_zeek_notices=["Scan::Port_Scan"],
        ) == VERDICT_DETECTED_EXPECTED

    def test_mixed_expected_all_fired(self):
        assert classify(
            alerts=[alert(2001219)],
            notices=[notice("Scan::Port_Scan")],
            expected_sids=[2001219],
            expected_zeek_notices=["Scan::Port_Scan"],
        ) == VERDICT_DETECTED_EXPECTED

    def test_some_expected_sids_missing_returns_partial(self):
        assert classify(
            alerts=[alert(2001219)],
            notices=[],
            expected_sids=[2001219, 2031502],
        ) == VERDICT_DETECTED_PARTIAL

    def test_mixed_some_missing_returns_partial(self):
        # Expected both a SID and a notice; only the SID fired.
        assert classify(
            alerts=[alert(2001219)],
            notices=[],
            expected_sids=[2001219],
            expected_zeek_notices=["Scan::Port_Scan"],
        ) == VERDICT_DETECTED_PARTIAL


class TestUnexpectedFires:
    def test_unexpected_sid_fires_returns_detected_unexpected(self):
        # Expected 2001219, but 2031502 fired instead
        assert classify(
            alerts=[alert(2031502)],
            notices=[],
            expected_sids=[2001219],
        ) == VERDICT_DETECTED_UNEXPECTED

    def test_unexpected_notice_fires_returns_detected_unexpected(self):
        assert classify(
            alerts=[],
            notices=[notice("HTTP::SQL_Injection_Attacker")],
            expected_sids=[2001219],
        ) == VERDICT_DETECTED_UNEXPECTED

    def test_nothing_expected_and_something_fires(self):
        # Expected UNDETECTED, but something fired anyway -> unexpected
        assert classify(
            alerts=[alert(9999)],
            notices=[],
            expected_sids=[],
        ) == VERDICT_DETECTED_UNEXPECTED


class TestUndetected:
    def test_silence_with_expectations_returns_undetected(self):
        assert classify(
            alerts=[],
            notices=[],
            expected_sids=[2001219, 2031502],
        ) == VERDICT_UNDETECTED

    def test_silence_with_no_expectations_returns_undetected(self):
        assert classify(
            alerts=[],
            notices=[],
            expected_sids=[],
        ) == VERDICT_UNDETECTED


class TestInputHygiene:
    def test_non_int_sid_silently_ignored(self):
        assert classify(
            alerts=[{"sid": "2001219"}],  # string, not int
            notices=[],
            expected_sids=[2001219],
        ) == VERDICT_UNDETECTED  # nothing parseable fired

    def test_bool_sid_ignored(self):
        # bool is subclass of int in Python; classifier should reject it
        assert classify(
            alerts=[{"sid": True}],
            notices=[],
            expected_sids=[],
        ) == VERDICT_UNDETECTED

    def test_missing_sid_field_ignored(self):
        assert classify(
            alerts=[{"msg": "no sid"}],
            notices=[],
            expected_sids=[],
        ) == VERDICT_UNDETECTED

    def test_duplicate_sid_counted_once(self):
        # Same SID fired three times -- expectations of a single match met
        assert classify(
            alerts=[alert(2001219), alert(2001219), alert(2001219)],
            notices=[],
            expected_sids=[2001219],
        ) == VERDICT_DETECTED_EXPECTED

    def test_non_string_notice_ignored(self):
        assert classify(
            alerts=[],
            notices=[{"note": 42}, {"note": None}, {}],
            expected_sids=[],
            expected_zeek_notices=["Scan::Port_Scan"],
        ) == VERDICT_UNDETECTED


class TestSanity:
    def test_all_verdicts_tuple_is_expected(self):
        assert set(ALL_VERDICTS) == {
            VERDICT_DETECTED_EXPECTED,
            VERDICT_DETECTED_PARTIAL,
            VERDICT_DETECTED_UNEXPECTED,
            VERDICT_UNDETECTED,
            VERDICT_FAILED,
        }

    @pytest.mark.parametrize("verdict", [
        VERDICT_DETECTED_EXPECTED,
        VERDICT_DETECTED_PARTIAL,
        VERDICT_DETECTED_UNEXPECTED,
        VERDICT_UNDETECTED,
    ])
    def test_classify_never_returns_failed(self, verdict):
        # classify() must not return FAILED under any input -- FAILED is
        # emitted by the runner before classify ever gets called.
        assert verdict != VERDICT_FAILED
