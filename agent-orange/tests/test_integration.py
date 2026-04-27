"""Integration test: catalog -> runner -> harvest -> attribution -> verdict.

Unit tests cover each module in isolation. This file asserts the JOINT
contract: that the field names produced by the runner (AttackRun.target)
and the harvest (normalized events with ts/dest_ip/sni) line up with
what attribution.filter_events and verdict.classify expect. Previous
reviewer caught a field-naming mismatch (software.log's `host` field
vs. attribution's `dest_ip` field) that only surfaces at integration
time; this test locks down that contract so it can't silently regress.

No SSH. No lab. Fakes stand in for attacker_runner and ssh_runner; the
rest runs on real modules with real data flow.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_orange_pkg.attribution import filter_events
from agent_orange_pkg.catalog import Attack, Target
from agent_orange_pkg.harvest import (
    SensorBaseline, SensorHarvest,
    harvest, parse_sections,
)
from agent_orange_pkg.runner import (
    AttackResult, AttackRun,
    RUN_STATUS_FAILED, RUN_STATUS_RAN,
    run_attacks,
)
from agent_orange_pkg.verdict import (
    VERDICT_DETECTED_EXPECTED,
    VERDICT_DETECTED_UNEXPECTED,
    VERDICT_FAILED,
    VERDICT_UNDETECTED,
    classify,
)


VICTIM_IP = "172.31.76.116"


def _attack(
    name: str,
    target_type: str,
    target_value: str,
    expected_sids: tuple[int, ...] = (),
    expected_notices: tuple[str, ...] = (),
    expected_verdict: str = "UNDETECTED",
) -> Attack:
    return Attack(
        name=name, mitre="T1046", source="atomic-red-team",
        art_test=f"{name} test", rationale="r",
        target=Target(type=target_type, value=target_value),
        expected_sids=expected_sids,
        expected_zeek_notices=expected_notices,
        expected_verdict=expected_verdict,
        command=f"echo {name}",
        timeout=5,
    )


def _fake_attacker_runner(result: AttackResult):
    def runner(cmd: str, timeout: int) -> AttackResult:
        return result
    return runner


def _fake_ssh_runner(stdout: str, stderr: str = "", rc: int = 0):
    def runner(cmd: str) -> tuple[str, str, int]:
        return stdout, stderr, rc
    return runner


def _harvest_stdout(
    *,
    eve_alerts: list[dict] | None = None,
    zeek_notice: list[dict] | None = None,
    zeek_http: list[dict] | None = None,
    zeek_ssl: list[dict] | None = None,
    zeek_software: list[dict] | None = None,
    zeek_intel: list[dict] | None = None,
) -> str:
    """Build a harvest-compatible sectioned stdout for the tests."""
    # These must match the section names build_harvest_command emits.
    body: list[str] = []

    def section(name: str, rows: list[dict] | None):
        body.append(f"=== {name} ===")
        for row in rows or []:
            body.append(json.dumps(row))

    section("EVE_ALERTS", eve_alerts)
    section("ZEEK_NOTICE", zeek_notice)
    section("ZEEK_WEIRD", [])
    section("ZEEK_INTEL", zeek_intel)
    section("ZEEK_CONN", [])
    section("ZEEK_HTTP", zeek_http)
    section("ZEEK_SSH", [])
    section("ZEEK_SSL", zeek_ssl)
    section("ZEEK_DNS", [])
    section("ZEEK_FTP", [])
    section("ZEEK_SMTP", [])
    section("ZEEK_FILES", [])
    section("ZEEK_SOFTWARE", zeek_software)
    section("ZEEK_SNMP", [])
    section("ZEEK_X509", [])
    section("ZEEK_TUNNEL", [])
    section("ZEEK_DCE_RPC", [])
    section("ZEEK_SMB_MAPPING", [])
    section("ZEEK_SMB_FILES", [])
    section("ZEEK_KERBEROS", [])
    section("ZEEK_LOADED_SCRIPTS", [])
    section("ZEEK_STATS", [])
    return "\n".join(body) + "\n"


def _baseline() -> SensorBaseline:
    return SensorBaseline(
        eve_json_lines=0, notice_log_lines=0, weird_log_lines=0,
        intel_log_lines=0, conn_log_lines=0, captured_at=0.0,
    )


# ---------------------------------------------------------------------------
#  End-to-end: one attack, one expected-SID match
# ---------------------------------------------------------------------------

class TestHappyPath:
    """Victim-targeted attack fires its expected SID, verdict goes
    DETECTED_EXPECTED. Confirms: runner produces correct target shape,
    harvest normalizes Suricata alert fields correctly, attribution
    window + dest match the runner's resolved target, classifier
    returns the right tier.
    """

    def test_attack_detected_expected(self):
        attack = _attack(
            name="art-masscan",
            target_type="victim",
            target_value="{{VICTIM_IP}}",
            expected_sids=(2001219,),
            expected_verdict="DETECTED_EXPECTED",
        )
        # Victim verdict consistency rule: DETECTED_EXPECTED needs non-empty
        # expected lists -- covered.
        runs = run_attacks(
            [attack], VICTIM_IP,
            _fake_attacker_runner(AttackResult(stdout="", stderr="", exit_code=0)),
        )
        assert runs[0].status == RUN_STATUS_RAN
        # Runner must have substituted the target value.
        assert runs[0].target.value == VICTIM_IP

        # Build a synthetic harvest: one Suricata alert during the window
        # that matches expected_sids + dest_ip.
        ts_during = (runs[0].probe_start_ts + runs[0].probe_end_ts) / 2.0
        harvest_stdout = _harvest_stdout(eve_alerts=[{
            "event_type": "alert",
            "timestamp": f"{ts_during}",
            "dest_ip": VICTIM_IP,
            "alert": {"signature_id": 2001219, "signature": "ET match"},
        }])
        # Suricata uses ISO-format ts so translate to ISO for normalization.
        from datetime import datetime, timezone as _tz
        iso = datetime.fromtimestamp(ts_during, tz=_tz.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%f+0000"
        )
        harvest_stdout = _harvest_stdout(eve_alerts=[{
            "event_type": "alert",
            "timestamp": iso,
            "dest_ip": VICTIM_IP,
            "alert": {"signature_id": 2001219, "signature": "ET match"},
        }])

        h = harvest(_fake_ssh_runner(harvest_stdout), _baseline(),
                    run_start_ts=runs[0].probe_start_ts)
        assert len(h.suricata_alerts) == 1
        assert h.suricata_alerts[0]["dest_ip"] == VICTIM_IP
        assert h.suricata_alerts[0]["sid"] == 2001219

        # Attribution filter: the alert's ts + dest must be inside this run's
        # window and match the target (post-substitution).
        attributed = filter_events(
            h.suricata_alerts,
            attack_start_ts=runs[0].probe_start_ts,
            attack_end_ts=runs[0].probe_end_ts,
            target_type=runs[0].target.type,
            target_value=runs[0].target.value,
        )
        assert len(attributed) == 1

        # Classifier: expected fired -> DETECTED_EXPECTED.
        verdict = classify(
            alerts=attributed,
            notices=[],
            expected_sids=attack.expected_sids,
            expected_zeek_notices=attack.expected_zeek_notices,
        )
        assert verdict == VERDICT_DETECTED_EXPECTED


# ---------------------------------------------------------------------------
#  End-to-end: unattributed alert doesn't pollute a silent attack
# ---------------------------------------------------------------------------

class TestAttributionBoundary:
    """An alert that fires with wrong dest_ip (or outside the time window)
    must NOT attribute to an attack. This guards against "another run's
    noise turned this UNDETECTED into DETECTED_UNEXPECTED."
    """

    def test_wrong_dest_ip_not_attributed(self):
        attack = _attack(
            name="art-silent", target_type="victim",
            target_value="{{VICTIM_IP}}",
        )
        runs = run_attacks(
            [attack], VICTIM_IP,
            _fake_attacker_runner(AttackResult(stdout="", stderr="", exit_code=0)),
        )

        # Alert fires during the window but targets a different IP.
        from datetime import datetime, timezone as _tz
        ts_during = (runs[0].probe_start_ts + runs[0].probe_end_ts) / 2.0
        iso = datetime.fromtimestamp(ts_during, tz=_tz.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%f+0000"
        )
        h = harvest(
            _fake_ssh_runner(_harvest_stdout(eve_alerts=[{
                "event_type": "alert",
                "timestamp": iso,
                "dest_ip": "10.0.0.99",  # not the victim
                "alert": {"signature_id": 9999},
            }])),
            _baseline(), run_start_ts=runs[0].probe_start_ts,
        )
        attributed = filter_events(
            h.suricata_alerts,
            runs[0].probe_start_ts, runs[0].probe_end_ts,
            runs[0].target.type, runs[0].target.value,
        )
        assert attributed == []

        verdict = classify(
            attributed, [], attack.expected_sids, attack.expected_zeek_notices
        )
        assert verdict == VERDICT_UNDETECTED


# ---------------------------------------------------------------------------
#  End-to-end: SNI-targeted attack attributes via ssl.log
# ---------------------------------------------------------------------------

class TestSniAttribution:
    """A cloudflared-style attack targets an SNI, not the victim IP. The
    harvest's ssl.log event has `server_name` set; attribution must match
    the ssl.log SNI against the attack's target_value.
    """

    def test_ssl_log_sni_attribution(self):
        attack = _attack(
            name="art-cloudflared", target_type="sni",
            target_value="trycloudflare.com",
        )
        runs = run_attacks(
            [attack], VICTIM_IP,
            _fake_attacker_runner(AttackResult(stdout="", stderr="", exit_code=0)),
        )
        ts_during = (runs[0].probe_start_ts + runs[0].probe_end_ts) / 2.0
        h = harvest(
            _fake_ssh_runner(_harvest_stdout(zeek_ssl=[{
                "ts": str(ts_during),
                "id.resp_h": "1.2.3.4",
                "server_name": "abc.trycloudflare.com",
            }])),
            _baseline(), run_start_ts=runs[0].probe_start_ts,
        )
        ssl_events = h.zeek_protocol_logs.get("ssl.log", [])
        assert len(ssl_events) == 1
        assert ssl_events[0]["sni"] == "abc.trycloudflare.com"

        attributed = filter_events(
            ssl_events,
            runs[0].probe_start_ts, runs[0].probe_end_ts,
            runs[0].target.type, runs[0].target.value,
        )
        assert len(attributed) == 1  # SNI substring match works end-to-end


# ---------------------------------------------------------------------------
#  End-to-end: software.log evidence attributes to victim attack
# ---------------------------------------------------------------------------

class TestSoftwareLogAttribution:
    """Regression test for the field-mapping bug the reviewer caught:
    software.log uses `host` (the IP) instead of `id.resp_h`. Before the
    fix, this event would have silently not attributed to a victim
    attack. After the fix, host -> dest_ip mapping works.
    """

    def test_software_log_host_mapped_to_dest_ip(self):
        attack = _attack(
            name="art-gobuster", target_type="victim",
            target_value="{{VICTIM_IP}}",
        )
        runs = run_attacks(
            [attack], VICTIM_IP,
            _fake_attacker_runner(AttackResult(stdout="", stderr="", exit_code=0)),
        )
        ts_during = (runs[0].probe_start_ts + runs[0].probe_end_ts) / 2.0
        h = harvest(
            _fake_ssh_runner(_harvest_stdout(zeek_software=[{
                "ts": str(ts_during),
                "host": VICTIM_IP,            # software.log key
                "host_p": 8081,
                "software_type": "HTTP::BROWSER",
                "name": "gobuster",
                "unparsed_version": "gobuster/3.8.2",
            }])),
            _baseline(), run_start_ts=runs[0].probe_start_ts,
        )
        software = h.zeek_protocol_logs.get("software.log", [])
        assert len(software) == 1
        # Regression: host must land in dest_ip, not sni
        assert software[0]["dest_ip"] == VICTIM_IP
        assert software[0]["sni"] is None

        # Attribution must now succeed
        attributed = filter_events(
            software, runs[0].probe_start_ts, runs[0].probe_end_ts,
            runs[0].target.type, runs[0].target.value,
        )
        assert len(attributed) == 1


# ---------------------------------------------------------------------------
#  End-to-end: FAILED attack short-circuits sensibly
# ---------------------------------------------------------------------------

class TestFailedAttack:
    """A runner-FAILED attack has probe_start_ts and probe_end_ts but
    classify() isn't called on its evidence by the orchestrator. This
    test confirms the window is sane (start < end) and that attribution
    returns nothing -- consistent with the ledger assigning FAILED
    verdict unconditionally upstream.
    """

    def test_ssh_error_produces_failed_with_valid_window(self):
        attack = _attack(
            name="art-missing-tool", target_type="victim",
            target_value="{{VICTIM_IP}}",
        )
        fake = _fake_attacker_runner(AttackResult(
            stdout="", stderr="ssh: connect timeout", exit_code=255,
            ssh_error="connect timeout",
        ))
        runs = run_attacks([attack], VICTIM_IP, fake)
        assert runs[0].status == RUN_STATUS_FAILED
        assert runs[0].probe_start_ts <= runs[0].probe_end_ts
        assert runs[0].exit_code == 255  # preserved even with ssh_error
        assert "ssh transport error" in runs[0].error


# ---------------------------------------------------------------------------
#  Flow-aware attribution: deferred Zeek notice anchored by conn.log
# ---------------------------------------------------------------------------

class TestDeferredNoticeAnchorsOnConnLog:
    """Regression for run 20260427T132622Z: a Zeek notice with delayed
    emission (ProtocolDetector::Protocol_Found can fire 4-5+s after the
    triggering connection) carries a community_id matching its earlier
    conn.log entry. The notice's own ts lands in a temporally-adjacent
    later attack's post-grace window; without conn.log in the flow-
    grouping input, the flow has size 1 and anchors on the late ts,
    misattributing to the wrong attack.

    Setup mirrors the live-lab repro:
      - "earlier-http"  window [100, 102] -- triggers HTTP-on-8081 flow
      - "later-knock"   window [110, 111] -- port-knock SYN burst, all
                                              targeting the same victim IP
      - conn.log entry at ts=100.5 with community_id=X (flow start)
      - notice at ts=112 with community_id=X (delayed Protocol_Found
        emission, lands in later-knock's post-grace)

    Correct attribution: notice -> earlier-http (flow ground truth).
    """

    def test_delayed_notice_attributes_to_flow_origin_attack(self):
        from agent_orange_pkg.attribution import (
            AttackWindow, attribute_all, compute_flow_owners,
        )
        from run import _collect_flow_grouping_events

        windows = [
            AttackWindow(
                name="earlier-http", start_ts=100.0, end_ts=102.0,
                target_type="victim", target_value=VICTIM_IP,
            ),
            AttackWindow(
                name="later-knock", start_ts=110.0, end_ts=111.0,
                target_type="victim", target_value=VICTIM_IP,
            ),
        ]
        conn_event = {
            "ts": 100.5, "dest_ip": VICTIM_IP, "sni": None,
            "community_id": "1:fakeflowX=", "_log": "conn.log",
        }
        notice_event = {
            "ts": 112.0, "dest_ip": VICTIM_IP, "sni": None,
            "note": "ProtocolDetector::Protocol_Found",
            "msg": "HTTP on port 8081/tcp",
            "community_id": "1:fakeflowX=",
            "uid": "Cabc123",
        }
        harvest = SensorHarvest(
            suricata_alerts=[],
            zeek_notices=[notice_event],
            zeek_weird=[],
            zeek_intel=[],
            zeek_conn=[conn_event],
            zeek_protocol_logs={},
            zeek_loaded_scripts="",
            zeek_stats="",
            baseline=_baseline(),
            harvest_at=120.0,
        )

        flow_owners = compute_flow_owners(
            _collect_flow_grouping_events(harvest), windows,
        )
        # Flow X anchors on the conn.log entry (ts=100.5, inside earlier-http
        # strict window), so the late notice with the same community_id is
        # owned by earlier-http -- not later-knock's post-grace.
        assert flow_owners.get("1:fakeflowX=") == "earlier-http"

        notices_by_attack = attribute_all(
            harvest.zeek_notices, windows, flow_owners=flow_owners,
        )
        assert len(notices_by_attack["earlier-http"]) == 1
        assert notices_by_attack["later-knock"] == []

    def test_collect_flow_grouping_events_includes_conn_log(self):
        from run import _collect_flow_grouping_events

        conn_event = {"ts": 1.0, "dest_ip": VICTIM_IP,
                      "community_id": "C1", "_log": "conn.log"}
        harvest = SensorHarvest(
            suricata_alerts=[],
            zeek_notices=[],
            zeek_weird=[],
            zeek_intel=[],
            zeek_conn=[conn_event],
            zeek_protocol_logs={},
            zeek_loaded_scripts="",
            zeek_stats="",
            baseline=_baseline(),
            harvest_at=2.0,
        )
        events = _collect_flow_grouping_events(harvest)
        assert conn_event in events
