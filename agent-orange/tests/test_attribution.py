"""Unit tests for agent_orange_pkg.attribution.

Covers the time-window + dest-match filters. Pure function tests with
hand-authored event fixtures; no harvest or runner dependency.

Run:
    cd agent-orange && pytest tests/test_attribution.py -q
"""

from __future__ import annotations

import pytest

from agent_orange_pkg.attribution import (
    AttackWindow,
    DEFAULT_GRACE_SECONDS,
    attribute_all,
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


# ---------------------------------------------------------------------------
#  Exclusive attribution (Fix 2: one event, one attack)
# ---------------------------------------------------------------------------

class TestAttackWindow:
    """AttackWindow is an immutable record bundling the per-attack data
    attribute_all needs: name, time boundaries, and target anchor."""

    def test_constructs_with_all_fields(self):
        w = AttackWindow(
            name="art-x",
            start_ts=100.0,
            end_ts=110.0,
            target_type="victim",
            target_value="172.31.76.116",
        )
        assert w.name == "art-x"
        assert w.start_ts == 100.0
        assert w.end_ts == 110.0
        assert w.target_type == "victim"
        assert w.target_value == "172.31.76.116"

    def test_is_frozen(self):
        w = AttackWindow("a", 0, 1, "victim", "x")
        with pytest.raises((AttributeError, Exception)):
            w.name = "b"  # frozen dataclass -> FrozenInstanceError


class TestAttributeAll:
    """attribute_all maps each event to AT MOST ONE attack window. The
    first window (by start_ts) whose time-window AND target BOTH match
    wins the event. Other windows that would have also matched are
    denied -- this eliminates the 'same SID attributed to 8 attacks'
    bleed problem that filter_events can't prevent on its own.
    """

    def _ev(self, ts, dest_ip=None, sni=None, **extras):
        return {"ts": ts, "dest_ip": dest_ip, "sni": sni, **extras}

    def _w(self, name, start, end, ttype="victim", tval="172.31.76.116"):
        return AttackWindow(
            name=name, start_ts=start, end_ts=end,
            target_type=ttype, target_value=tval,
        )

    def test_returns_dict_keyed_by_window_name(self):
        windows = [self._w("a", 0, 10), self._w("b", 20, 30)]
        out = attribute_all([], windows)
        assert set(out.keys()) == {"a", "b"}
        assert out["a"] == [] and out["b"] == []

    def test_single_event_single_match(self):
        windows = [self._w("a", 100, 110)]
        events = [self._ev(105.0, dest_ip="172.31.76.116", sid=1)]
        out = attribute_all(events, windows)
        assert len(out["a"]) == 1
        assert out["a"][0]["sid"] == 1

    def test_event_in_overlapping_windows_goes_to_first(self):
        # a: [100, 120], b: [105, 115]. Event at 110 is inside both by time
        # and both target the same victim. First-by-start wins -> 'a'.
        windows = [self._w("a", 100, 120), self._w("b", 105, 115)]
        events = [self._ev(110.0, dest_ip="172.31.76.116", sid=9000003)]
        out = attribute_all(events, windows)
        assert len(out["a"]) == 1
        assert out["b"] == []

    def test_first_by_start_even_if_windows_passed_out_of_order(self):
        # Deterministic: attribute_all sorts windows by start_ts internally.
        windows = [self._w("second", 105, 115), self._w("first", 100, 120)]
        events = [self._ev(110.0, dest_ip="172.31.76.116", sid=1)]
        out = attribute_all(events, windows)
        assert len(out["first"]) == 1
        assert out["second"] == []

    def test_target_mismatch_on_first_falls_through_to_second(self):
        # Event targets VICTIM-2. First window's target is VICTIM-1
        # (mismatch), second window is VICTIM-2. Event goes to second
        # (target match matters, not just time).
        windows = [
            self._w("a", 100, 120, tval="172.31.76.1"),
            self._w("b", 100, 120, tval="172.31.76.2"),
        ]
        events = [self._ev(110.0, dest_ip="172.31.76.2", sid=1)]
        out = attribute_all(events, windows)
        assert out["a"] == []
        assert len(out["b"]) == 1

    def test_event_outside_all_windows_dropped(self):
        # Attribution is exclusive but not required -- events that don't
        # match any window at all are simply unassigned.
        windows = [self._w("a", 100, 110), self._w("b", 200, 210)]
        events = [self._ev(150.0, dest_ip="172.31.76.116", sid=1)]
        out = attribute_all(events, windows)
        assert out["a"] == []
        assert out["b"] == []

    def test_bad_ts_events_dropped(self):
        windows = [self._w("a", 0, 1000)]
        events = [
            self._ev(None, dest_ip="172.31.76.116", sid=1),
            self._ev("str", dest_ip="172.31.76.116", sid=2),
            self._ev(True, dest_ip="172.31.76.116", sid=3),  # bool excluded
            self._ev(False, dest_ip="172.31.76.116", sid=4),
        ]
        out = attribute_all(events, windows)
        assert out["a"] == []

    def test_multiple_events_distributed_correctly(self):
        # Three sequential windows, alerts landing in each. Nothing bleeds.
        windows = [
            self._w("a", 100, 110),
            self._w("b", 120, 130),
            self._w("c", 140, 150),
        ]
        events = [
            self._ev(105.0, dest_ip="172.31.76.116", sid=1),   # -> a
            self._ev(125.0, dest_ip="172.31.76.116", sid=2),   # -> b
            self._ev(145.0, dest_ip="172.31.76.116", sid=3),   # -> c
        ]
        out = attribute_all(events, windows)
        assert [e["sid"] for e in out["a"]] == [1]
        assert [e["sid"] for e in out["b"]] == [2]
        assert [e["sid"] for e in out["c"]] == [3]

    def test_event_in_grace_of_a_exclusive_from_b(self):
        # The key bug scenario from run 20260424T201700Z: back-to-back
        # attacks where a late alert from attack A (still in A's grace
        # window) happens to also fall within B's start.
        # a: [100, 110] + 3s grace = valid up to 113.
        # b: [112, 122] starts at 112.
        # Event at 112.5 is in both. First-match (a) wins. With default
        # filter_events, both would have matched, producing bleed.
        windows = [self._w("a", 100, 110), self._w("b", 112, 122)]
        events = [self._ev(112.5, dest_ip="172.31.76.116", sid=9000003)]
        out = attribute_all(events, windows)
        assert len(out["a"]) == 1
        assert out["b"] == []

    def test_empty_windows_returns_empty_dict(self):
        out = attribute_all([{"ts": 100, "dest_ip": "1.1.1.1"}], [])
        assert out == {}

    def test_custom_grace_honored(self):
        # Same 3-parameter shape as filter_events; grace extends end_ts.
        windows = [self._w("a", 100, 110)]
        events = [self._ev(115.0, dest_ip="172.31.76.116", sid=1)]
        # Default grace 3s -> 115 outside [100, 113]
        assert attribute_all(events, windows)["a"] == []
        # Custom grace 10s -> inside [100, 120]
        assert len(attribute_all(events, windows, grace_seconds=10)["a"]) == 1

    def test_sni_target_works(self):
        windows = [self._w(
            "a", 100, 110, ttype="sni", tval="trycloudflare.com",
        )]
        events = [self._ev(105.0, sni="abc.trycloudflare.com", sid=1)]
        out = attribute_all(events, windows)
        assert len(out["a"]) == 1

    def test_preserves_event_order_within_one_window(self):
        windows = [self._w("a", 100, 200)]
        events = [
            self._ev(110.0, dest_ip="172.31.76.116", sid=1),
            self._ev(105.0, dest_ip="172.31.76.116", sid=2),
            self._ev(150.0, dest_ip="172.31.76.116", sid=3),
        ]
        out = attribute_all(events, windows)
        # Iteration order of input preserved (not sorted by ts).
        assert [e["sid"] for e in out["a"]] == [1, 2, 3]

    def test_same_name_duplicate_windows_last_wins_in_result_dict(self):
        # Defensive: duplicate names are a caller bug, but don't crash.
        # The result dict has ONE entry per name; whichever window
        # received the event matters.
        windows = [self._w("a", 100, 110), self._w("a", 200, 210)]
        events = [self._ev(105.0, dest_ip="172.31.76.116", sid=1)]
        out = attribute_all(events, windows)
        # Only one "a" key; we don't require specific contents for
        # pathological duplicate-name input, just don't crash.
        assert "a" in out
