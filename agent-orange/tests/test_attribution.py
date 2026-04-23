"""Unit tests for agent_orange_pkg.attribution.

Covers the time-window + dest-match filters. Pure function tests with
hand-authored event fixtures; no harvest or runner dependency.

Run:
    cd agent-orange && pytest tests/test_attribution.py -q
"""

from __future__ import annotations

import pytest

from agent_orange_pkg.attribution import (
    DEFAULT_GRACE_SECONDS,
    filter_events,
    in_time_window,
    matches_target,
)


class TestInTimeWindow:
    def test_inside_window(self):
        assert in_time_window(event_ts=100.5, attack_start_ts=100.0, attack_end_ts=101.0)

    def test_before_window_rejected(self):
        assert not in_time_window(99.9, 100.0, 101.0)

    def test_after_window_plus_grace_rejected(self):
        # 101 + 3 (default grace) = 104; 104.5 is outside
        assert not in_time_window(104.5, 100.0, 101.0)

    def test_within_grace_accepted(self):
        assert in_time_window(103.0, 100.0, 101.0)

    def test_exact_start_boundary_accepted(self):
        assert in_time_window(100.0, 100.0, 101.0)

    def test_exact_end_boundary_accepted(self):
        assert in_time_window(101.0, 100.0, 101.0)

    def test_exact_end_plus_grace_boundary_accepted(self):
        assert in_time_window(104.0, 100.0, 101.0, grace_seconds=3.0)

    def test_custom_grace_zero(self):
        # With grace=0, post-end events are rejected
        assert not in_time_window(101.5, 100.0, 101.0, grace_seconds=0.0)


class TestMatchesTarget:
    # victim ----------------------------------------------------------------

    def test_victim_exact_ip_match(self):
        assert matches_target("172.31.76.116", None, "victim", "172.31.76.116")

    def test_victim_wrong_ip_rejected(self):
        assert not matches_target("10.0.0.1", None, "victim", "172.31.76.116")

    def test_victim_sni_ignored(self):
        # SNI matching doesn't apply to victim-type attribution
        assert not matches_target(None, "trycloudflare.com", "victim", "172.31.76.116")

    # sni -------------------------------------------------------------------

    def test_sni_substring_match(self):
        assert matches_target(
            None, "abc123.trycloudflare.com", "sni", "trycloudflare.com"
        )

    def test_sni_case_insensitive(self):
        assert matches_target(None, "GITHUB.com", "sni", "github.com")

    def test_sni_no_match(self):
        assert not matches_target(None, "example.org", "sni", "trycloudflare.com")

    def test_sni_comma_separated_any_match(self):
        # Multi-host SNI target: any token wins
        target = "anydesk.com,teamviewer.com,rustdesk.com"
        assert matches_target(None, "master7.teamviewer.com", "sni", target)
        assert matches_target(None, "anydesk.com", "sni", target)
        assert not matches_target(None, "zoom.us", "sni", target)

    def test_sni_missing_sni_field_rejected(self):
        # dest_ip set but type is sni -> no sni, no match
        assert not matches_target("1.2.3.4", None, "sni", "github.com")

    # external --------------------------------------------------------------

    def test_external_matches_dest_ip(self):
        assert matches_target("8.8.8.8", None, "external", "8.8.8.8")

    def test_external_matches_sni(self):
        assert matches_target(None, "malicious.example.net", "external", "example.net")

    def test_external_matches_either(self):
        assert matches_target("8.8.8.8", "ignored.com", "external", "8.8.8.8")

    def test_external_no_match(self):
        assert not matches_target("10.0.0.1", "other.com", "external", "evil.org")

    # edge cases ------------------------------------------------------------

    def test_no_dest_no_sni_always_rejected(self):
        assert not matches_target(None, None, "victim", "anything")
        assert not matches_target(None, None, "sni", "anything")
        assert not matches_target(None, None, "external", "anything")

    def test_unknown_target_type_rejected(self):
        assert not matches_target("1.2.3.4", "x", "martian", "1.2.3.4")


class TestFilterEvents:
    def _ev(self, ts, dest_ip=None, sni=None, **extras):
        return {"ts": ts, "dest_ip": dest_ip, "sni": sni, **extras}

    def test_combined_time_and_target(self):
        events = [
            self._ev(100.5, dest_ip="172.31.76.116", sid=2001219),  # in window, right ip
            self._ev(99.0,  dest_ip="172.31.76.116", sid=2001219),  # too early
            self._ev(100.5, dest_ip="10.0.0.1",       sid=2001219),  # wrong ip
            self._ev(103.0, dest_ip="172.31.76.116", sid=2031502),  # in grace, right ip
        ]
        out = filter_events(events, 100.0, 101.0, "victim", "172.31.76.116")
        assert len(out) == 2
        assert {e["sid"] for e in out} == {2001219, 2031502}

    def test_events_without_ts_dropped(self):
        events = [
            self._ev(None, dest_ip="1.1.1.1"),
            {"dest_ip": "1.1.1.1", "sid": 1},  # no ts at all
            self._ev("not-a-number", dest_ip="1.1.1.1"),
        ]
        out = filter_events(events, 0, 100, "victim", "1.1.1.1")
        assert out == []

    def test_bool_ts_dropped(self):
        # `isinstance(True, int)` is True in Python; filter_events must
        # explicitly reject bool ts so a harvest bug doesn't silently land
        # in attack windows as epoch 0/1.
        events = [
            self._ev(True,  dest_ip="1.1.1.1"),
            self._ev(False, dest_ip="1.1.1.1"),
        ]
        out = filter_events(events, 0, 100, "victim", "1.1.1.1")
        assert out == []

    def test_empty_input(self):
        assert filter_events([], 0, 100, "victim", "1.1.1.1") == []

    def test_grace_parameter_honored(self):
        events = [self._ev(105.0, dest_ip="1.1.1.1")]
        # default grace 3s -> outside
        assert filter_events(events, 100, 101, "victim", "1.1.1.1") == []
        # expand grace -> inside
        got = filter_events(events, 100, 101, "victim", "1.1.1.1", grace_seconds=10)
        assert len(got) == 1

    def test_default_grace_matches_constant(self):
        # If someone changes DEFAULT_GRACE_SECONDS, the test that depends on
        # the 3-second boundary should move with it. Fail loudly otherwise.
        assert DEFAULT_GRACE_SECONDS == 3.0
