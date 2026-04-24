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
    DEFAULT_PRE_START_GRACE_SECONDS,
    attribute_all,
    filter_events,
    in_time_window,
    matches_target,
)


class TestInTimeWindow:
    def test_inside_window(self):
        assert in_time_window(event_ts=100.5, attack_start_ts=100.0, attack_end_ts=101.0)

    def test_before_window_beyond_pre_grace_rejected(self):
        # Events outside the pre-start grace (default 2s) are rejected.
        # A 3s-early event is beyond the default pre-grace.
        assert not in_time_window(97.0, 100.0, 101.0)

    def test_after_window_plus_grace_rejected(self):
        # 101 + 10 (default grace) = 111; 112 is outside
        assert not in_time_window(112.0, 100.0, 101.0)

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

    def test_pre_start_grace_default_is_2_seconds(self):
        # Absorbs clock skew between controller (records probe_start_ts
        # on local clock) and sensor (stamps events on its own clock).
        # Default is sized for typical NTP-synced hosts (~0.1-1s skew).
        assert DEFAULT_PRE_START_GRACE_SECONDS == 2.0

    def test_event_1s_before_start_accepted_with_default_pre_grace(self):
        # Clock-skew case: sensor timestamp is 1s earlier than the
        # controller's recorded probe_start_ts. Within default 2s pre-grace.
        assert in_time_window(99.0, 100.0, 101.0)

    def test_event_3s_before_start_rejected(self):
        # Beyond default 2s pre-grace -> not attributable (too early).
        assert not in_time_window(97.0, 100.0, 101.0)

    def test_event_at_pre_start_grace_boundary_accepted(self):
        # start - pre_grace = 98.0; equality counts as inside.
        assert in_time_window(98.0, 100.0, 101.0)

    def test_custom_pre_start_grace_honored(self):
        # Caller can widen the pre-grace if they know skew is larger.
        assert in_time_window(95.0, 100.0, 101.0, pre_start_grace_seconds=10)

    def test_pre_start_grace_zero_rejects_all_pre_events(self):
        # Disables the new behavior for callers that want the old semantics.
        assert not in_time_window(99.5, 100.0, 101.0, pre_start_grace_seconds=0.0)


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
        # Use ts=96.0 for "too early" -- beyond the default 2s pre-grace
        # (old test used 99.0 back when there was no pre-grace).
        events = [
            self._ev(100.5, dest_ip="172.31.76.116", sid=2001219),  # in window, right ip
            self._ev(96.0,  dest_ip="172.31.76.116", sid=2001219),  # too early (outside pre-grace)
            self._ev(100.5, dest_ip="10.0.0.1",       sid=2001219),  # wrong ip
            self._ev(103.0, dest_ip="172.31.76.116", sid=2031502),  # in post-grace, right ip
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
        events = [self._ev(115.0, dest_ip="1.1.1.1")]
        # default grace 10s -> 115 outside [100, 111]
        assert filter_events(events, 100, 101, "victim", "1.1.1.1") == []
        # expand grace -> inside
        got = filter_events(events, 100, 101, "victim", "1.1.1.1", grace_seconds=20)
        assert len(got) == 1

    def test_default_grace_matches_constant(self):
        # If someone changes DEFAULT_GRACE_SECONDS, the tests that depend
        # on the boundary must move with it. Fail loudly otherwise.
        assert DEFAULT_GRACE_SECONDS == 10.0


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

    def test_strict_match_beats_grace_match(self):
        # Core correctness rule: an event falling inside attack B's REAL
        # window AND attack A's grace extension is attributed to B (the
        # attack that was actually running when the alert fired).
        # Scenario from run 20260424T205801Z: icmpdoor [312.14, 321.12]
        # + default post-grace covers 323.07. masscan [322, 325] strictly
        # covers 323.07. Attribute to masscan (strict wins over grace).
        windows = [
            self._w("icmpdoor", 312.14, 321.12),
            self._w("masscan", 322.0, 325.0),
        ]
        events = [self._ev(323.07, dest_ip="172.31.76.116", sid=9000003)]
        out = attribute_all(events, windows)
        assert len(out["masscan"]) == 1
        assert out["icmpdoor"] == []

    def test_overlapping_strict_windows_latest_start_wins(self):
        # Defensive: sequential runs shouldn't produce overlapping real
        # windows, but if a caller passes overlapping windows, latest
        # start wins (most recent activity likely caused the alert).
        windows = [self._w("a", 100, 120), self._w("b", 105, 115)]
        events = [self._ev(110.0, dest_ip="172.31.76.116", sid=1)]
        out = attribute_all(events, windows)
        assert len(out["b"]) == 1   # b starts later
        assert out["a"] == []

    def test_latest_end_wins_among_grace_only_matches(self):
        # Both attacks ended; event falls only in their grace windows.
        # Pick the LATEST end_ts (most recent activity).
        # a: [100, 110] grace -> 113. b: [105, 111] grace -> 114.
        # Event at 113.5 is in b's grace only (not a's: 113.5 > 113).
        # Regression: event at 112 is in both graces -> pick b (end=111 > 110).
        windows = [self._w("a", 100, 110), self._w("b", 105, 111)]
        events = [self._ev(112.0, dest_ip="172.31.76.116", sid=1)]
        out = attribute_all(events, windows)
        assert len(out["b"]) == 1
        assert out["a"] == []

    def test_window_input_order_does_not_matter(self):
        # Whatever priority rule is in effect must be independent of the
        # iteration order of the input list.
        w_second = self._w("second", 105, 115)
        w_first = self._w("first", 100, 120)
        events = [self._ev(110.0, dest_ip="172.31.76.116", sid=1)]
        # Event at 110 strict-matches both windows; latest start = "second"
        # (105 > 100). Answer must be "second" regardless of input order.
        out1 = attribute_all(events, [w_first, w_second])
        out2 = attribute_all(events, [w_second, w_first])
        assert out1["second"] == out2["second"]
        assert len(out1["second"]) == 1

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

    def test_event_in_grace_of_a_and_strict_of_b_goes_to_b(self):
        # Back-to-back attacks: a ends, b starts next, alert arrives during
        # b's real window but within a's post-end grace.
        # a: [100, 110] + default post-grace covers up past b's start.
        # b: [112, 122] starts at 112.
        # Event at 112.5 is in a's post-grace AND b's strict window.
        # Strict beats post-grace -> b.
        windows = [self._w("a", 100, 110), self._w("b", 112, 122)]
        events = [self._ev(112.5, dest_ip="172.31.76.116", sid=9000003)]
        out = attribute_all(events, windows)
        assert out["a"] == []
        assert len(out["b"]) == 1

    def test_empty_windows_returns_empty_dict(self):
        out = attribute_all([{"ts": 100, "dest_ip": "1.1.1.1"}], [])
        assert out == {}

    def test_custom_grace_honored(self):
        # Same shape as filter_events; grace extends end_ts.
        windows = [self._w("a", 100, 110)]
        events = [self._ev(125.0, dest_ip="172.31.76.116", sid=1)]
        # Default grace 10s -> 125 outside [100, 120]
        assert attribute_all(events, windows)["a"] == []
        # Custom grace 20s -> inside [100, 130]
        assert len(attribute_all(events, windows, grace_seconds=20)["a"]) == 1

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

    # Pre-start grace tier ---------------------------------------------------

    def test_pre_start_grace_event_attributed(self):
        # Clock-skew case: sensor stamps a packet at ts=99.5 even though
        # the controller recorded probe_start_ts=100. With 2s pre-grace,
        # the event still attributes to window 'a'.
        windows = [self._w("a", 100, 110)]
        events = [self._ev(99.5, dest_ip="172.31.76.116", sid=2260002)]
        out = attribute_all(events, windows)
        assert len(out["a"]) == 1

    def test_pre_start_grace_beyond_window_not_attributed(self):
        # 5s before start is beyond the 2s pre-grace -- unattributed.
        windows = [self._w("a", 100, 110)]
        events = [self._ev(95.0, dest_ip="172.31.76.116", sid=1)]
        out = attribute_all(events, windows)
        assert out["a"] == []

    def test_strict_beats_pre_start_grace(self):
        # Event at ts=99.5 is in A's strict window [90, 100] AND within
        # B's pre-grace (B.start=100, pre_grace=2 -> pre span 98..100).
        # Strict (A) must win.
        windows = [self._w("a", 90, 100), self._w("b", 100, 110)]
        events = [self._ev(99.5, dest_ip="172.31.76.116", sid=9000003)]
        out = attribute_all(events, windows)
        assert len(out["a"]) == 1
        assert out["b"] == []

    def test_post_end_grace_beats_pre_start_grace(self):
        # Event at ts=99.5 is in A's post-end grace (A=[90,98] + 10s grace
        # covers 98..108) AND in B's pre-start grace (B=[100,110], pre=2
        # -> 98..100). Policy: post-end beats pre-start (threshold-delay
        # semantic is rock solid; pre-start is clock-skew heuristic).
        windows = [self._w("a", 90, 98), self._w("b", 100, 110)]
        events = [self._ev(99.5, dest_ip="172.31.76.116", sid=1)]
        out = attribute_all(events, windows)
        assert len(out["a"]) == 1
        assert out["b"] == []

    def test_two_pre_start_graces_earliest_start_wins(self):
        # Two attacks both pre-grace-match one event. Prefer the earlier
        # attack (closer to the event's actual moment): if event_ts=99.5,
        # attack starting at 100 is closer than attack starting at 101.
        # (Note: 101's pre_grace still catches 99.5 since 101-2=99<=99.5.)
        windows = [self._w("a", 100, 110), self._w("b", 101, 111)]
        events = [self._ev(99.5, dest_ip="172.31.76.116", sid=1)]
        out = attribute_all(events, windows)
        assert len(out["a"]) == 1
        assert out["b"] == []

    def test_zeek_service_detection_delay_scenario(self):
        # Literal reproduction of run 20260424T215121Z:
        # whois-tunnel probe_start=1777067485.05, probe_end=1777067486.20
        # (1.15s attack). Zeek's ProtocolDetector::Protocol_Found fired
        # 4.6s after probe_start (at 1777067489.66). Under the old 3s
        # post-end grace, the notice was dropped. The 10s default grace
        # now catches it.
        windows = [AttackWindow(
            name="art-whois-tunnel",
            start_ts=1777067485.05,
            end_ts=1777067486.20,
            target_type="victim",
            target_value="172.31.78.129",
        )]
        events = [self._ev(
            1777067489.66, dest_ip="172.31.78.129",
            note="ProtocolDetector::Protocol_Found",
        )]
        out = attribute_all(events, windows)
        assert len(out["art-whois-tunnel"]) == 1
        assert out["art-whois-tunnel"][0]["note"] == "ProtocolDetector::Protocol_Found"

    def test_whois_tunnel_clock_skew_scenario(self):
        # Literal reproduction of the live-lab case that triggered this fix.
        # Agent-orange records probe_start=1777066627.05 on controller clock.
        # Sensor stamps the SURICATA Applayer alert at 1777066626.55
        # (sensor clock is ~0.9s behind controller). Without pre-grace, the
        # alert was dropped and whois-tunnel was UNDETECTED despite the
        # rule firing on every run.
        # Use target_value="172.31.78.129" to match the real victim IP
        # from the captured attack.
        windows = [AttackWindow(
            name="art-whois-tunnel",
            start_ts=1777066627.05,
            end_ts=1777066628.11,
            target_type="victim",
            target_value="172.31.78.129",
        )]
        events = [self._ev(
            1777066626.55, dest_ip="172.31.78.129",
            sid=2260002, signature="SURICATA Applayer Detect protocol only one direction",
        )]
        out = attribute_all(events, windows)
        assert len(out["art-whois-tunnel"]) == 1
        assert out["art-whois-tunnel"][0]["sid"] == 2260002

    def test_custom_pre_start_grace_in_attribute_all(self):
        # Caller can adjust pre-grace independently of post-grace.
        windows = [self._w("a", 100, 110)]
        events = [self._ev(96.0, dest_ip="172.31.76.116", sid=1)]
        # Default 2s pre-grace -> 96 is outside [98, 100)
        assert attribute_all(events, windows)["a"] == []
        # Widen to 5s -> inside [95, 100)
        assert len(attribute_all(events, windows, pre_start_grace_seconds=5)["a"]) == 1

    # Flow-aware attribution (by community_id / uid / flow_id) -------------

    def test_flow_events_attribute_together_to_first_owner(self):
        # Two events share a community_id. The earliest (ts=105, in a's
        # strict window) anchors the flow. The later event (ts=125, inside
        # b's strict window) would by time alone attribute to b -- but
        # because it's the SAME flow as the earlier event, it goes to a.
        # This is the whois-tunnel scenario: Zeek's late ProtocolDetector
        # notice belongs to the flow that whois opened, even though the
        # emission timestamp lands in icmpdoor's window.
        windows = [self._w("a", 100, 110), self._w("b", 120, 130)]
        events = [
            self._ev(105.0, dest_ip="172.31.76.116", community_id="COMM1", sid=1),
            self._ev(125.0, dest_ip="172.31.76.116", community_id="COMM1", note="Protocol_Found"),
        ]
        out = attribute_all(events, windows)
        assert len(out["a"]) == 2
        assert out["b"] == []

    def test_flow_earliest_event_used_for_attribution_anchor(self):
        # Events arrive out of order in the input list; attribute_all must
        # still pick the EARLIEST event's ts as the flow anchor.
        windows = [self._w("a", 100, 110), self._w("b", 120, 130)]
        events = [
            self._ev(125.0, dest_ip="172.31.76.116", community_id="C", note="n1"),  # late first
            self._ev(105.0, dest_ip="172.31.76.116", community_id="C", sid=1),      # early second
        ]
        out = attribute_all(events, windows)
        assert len(out["a"]) == 2

    def test_uid_used_as_flow_key_when_community_id_absent(self):
        # Zeek events typically carry `uid` (always) and `community_id`
        # (when policy/protocols/conn/community-id is loaded). uid is the
        # reliable fallback.
        windows = [self._w("a", 100, 110), self._w("b", 120, 130)]
        events = [
            self._ev(105.0, dest_ip="172.31.76.116", uid="CXXX", note="n1"),
            self._ev(125.0, dest_ip="172.31.76.116", uid="CXXX", note="n2"),
        ]
        out = attribute_all(events, windows)
        assert len(out["a"]) == 2

    def test_suricata_flow_id_used_as_flow_key(self):
        # Suricata eve.json alerts carry `flow_id` (integer). If neither
        # community_id nor uid present, flow_id is the fallback.
        windows = [self._w("a", 100, 110), self._w("b", 120, 130)]
        events = [
            self._ev(105.0, dest_ip="172.31.76.116", flow_id=12345, sid=1),
            self._ev(125.0, dest_ip="172.31.76.116", flow_id=12345, sid=2),
        ]
        out = attribute_all(events, windows)
        assert len(out["a"]) == 2

    def test_events_with_different_flow_ids_attribute_independently(self):
        # Two unrelated flows running at the same time -> each attributes
        # to its own time-window owner.
        windows = [self._w("a", 100, 110), self._w("b", 120, 130)]
        events = [
            self._ev(105.0, dest_ip="172.31.76.116", community_id="FLOW1", sid=1),
            self._ev(125.0, dest_ip="172.31.76.116", community_id="FLOW2", sid=2),
        ]
        out = attribute_all(events, windows)
        assert len(out["a"]) == 1
        assert len(out["b"]) == 1

    def test_event_with_no_flow_id_falls_back_to_time_attribution(self):
        # Backward compat: events without any flow identifier use the old
        # 3-tier time-based attribution logic. Must not regress.
        windows = [self._w("a", 100, 110), self._w("b", 120, 130)]
        events = [self._ev(125.0, dest_ip="172.31.76.116", sid=1)]
        out = attribute_all(events, windows)
        assert len(out["b"]) == 1  # no flow_id -> pure time attribution

    def test_flow_with_unmatchable_anchor_falls_back_per_event(self):
        # If the flow's earliest event falls outside all windows (even
        # with graces), we shouldn't drop the whole flow. Fall back to
        # per-event time-based attribution as if there were no flow group.
        windows = [self._w("a", 100, 110)]
        events = [
            self._ev(50.0, dest_ip="172.31.76.116", community_id="C", sid=1),  # orphan anchor
            self._ev(105.0, dest_ip="172.31.76.116", community_id="C", sid=2),  # in a's strict
        ]
        out = attribute_all(events, windows)
        # Anchor at 50 unassignable; fall back per-event.
        # 50 has no home; 105 lands in a.
        assert len(out["a"]) == 1
        assert out["a"][0]["sid"] == 2

    def test_mixed_events_flow_and_singleton(self):
        # Three events: two share a flow, one is standalone.
        # Flow anchor at ts=105 -> a. Singleton at ts=125 -> b.
        windows = [self._w("a", 100, 110), self._w("b", 120, 130)]
        events = [
            self._ev(105.0, dest_ip="172.31.76.116", community_id="FX", sid=1),
            self._ev(125.0, dest_ip="172.31.76.116", community_id="FX", note="n"),
            self._ev(122.0, dest_ip="172.31.76.116", sid=9),  # no flow_id
        ]
        out = attribute_all(events, windows)
        assert len(out["a"]) == 2   # flow FX
        assert len(out["b"]) == 1   # singleton sid=9

    def test_flow_key_precedence_community_id_wins_over_uid(self):
        # When both are present, community_id is preferred because it's
        # consistent between Suricata and Zeek (same 5-tuple hash). uid
        # is Zeek-specific. Two events with the SAME community_id but
        # DIFFERENT uids are still the same flow.
        windows = [self._w("a", 100, 110), self._w("b", 120, 130)]
        events = [
            self._ev(105.0, dest_ip="172.31.76.116", community_id="C", uid="U1", sid=1),
            self._ev(125.0, dest_ip="172.31.76.116", community_id="C", uid="U2", sid=2),
        ]
        out = attribute_all(events, windows)
        assert len(out["a"]) == 2  # one flow via community_id
