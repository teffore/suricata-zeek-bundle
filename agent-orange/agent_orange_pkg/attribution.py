"""attribution.py -- pure filters that map sensor events to attacks.

Agent Orange does attribution retrospectively: after all attacks have
run, a batch sensor harvest is cross-referenced against the ledger's
per-attack time windows. Each event is kept for an attack iff its
timestamp falls inside the attack's window AND its destination matches
the attack's target anchor.

Pure functions, no I/O. Callers pass in the already-parsed events (as
list[dict]) and the attack's Target; filter_events returns the subset
that attribute to that attack.

Event shape (produced by the harvest module in a later PR):

    {
        "ts": 1776945678.123,            # epoch seconds, float
        "dest_ip": "172.31.76.116",       # or None for outbound-SNI events
        "sni": "trycloudflare.com",       # or None for non-TLS events
        ... other log-specific fields ...
    }

Either dest_ip or sni (or both) should be present on an event for
matches_target to classify it as attributable. Missing both => no match.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

# Default post-end grace (seconds) appended to the attack's end timestamp.
# Covers two emission-delay sources:
#
# 1. Suricata's threshold/flow-aging delay -- the rule engine can emit
#    an alert a second or two after the triggering packet arrived.
# 2. Zeek's service-detection delay -- notices like
#    ProtocolDetector::Protocol_Found are emitted after Zeek has
#    observed enough bytes to confirm the protocol, which can be 4-5+
#    seconds after the triggering connection, especially on short
#    attacks where the connection closes before Zeek finishes analysis.
#
# Measured during run 20260424T215121Z: a ProtocolDetector notice for
# a 1.15s whois-to-8443 attack fired 4.6s after probe_start_ts, 0.46s
# past the old 3s grace. Bumped to 10s to absorb that and leave
# headroom for slower service-detection cases.
#
# Longer grace means more potential bleed from earlier attacks into
# later gaps, but attribute_all's strict tier always wins for events
# inside a later attack's real window, so the extra bleed only lands
# on events that would otherwise be unattributed entirely.
DEFAULT_GRACE_SECONDS = 10.0

# Pre-start grace (seconds) subtracted from the attack's start timestamp.
# Absorbs clock skew between the controller (records probe_start_ts on
# LOCAL clock via datetime.now()) and the sensor (stamps captured
# packets on ITS OWN clock via libpcap). NTP-synced hosts typically
# drift by tens-to-hundreds of milliseconds; a Windows controller and
# AWS EC2 sensor were measured at ~0.9s skew. 2s accommodates 2x the
# measured skew with headroom, and is still far shorter than typical
# attack windows so back-to-back attacks don't overlap pre-grace with
# their predecessor's real window in most cases. When they do overlap,
# attribute_all's priority (strict > post-grace > pre-grace) resolves
# the ambiguity toward the more confident tier.
DEFAULT_PRE_START_GRACE_SECONDS = 2.0


@dataclass(frozen=True)
class AttackWindow:
    """Attribution parameters for one attack, bundled for attribute_all.

    Instances are frozen + hashable so callers can build them once from
    the ledger's AttackRun entries and pass them into attribute_all
    repeatedly (per log stream) without re-deriving the fields.
    """
    name: str
    start_ts: float
    end_ts: float
    target_type: str
    target_value: str


def in_time_window(
    event_ts: float,
    attack_start_ts: float,
    attack_end_ts: float,
    grace_seconds: float = DEFAULT_GRACE_SECONDS,
    pre_start_grace_seconds: float = DEFAULT_PRE_START_GRACE_SECONDS,
) -> bool:
    """True iff event_ts falls within the attack's extended window.

    The accepted span is:
        [attack_start_ts - pre_start_grace, attack_end_ts + grace_seconds]

    Both boundaries are inclusive. The post-end grace handles Suricata's
    threshold/flow-aging emit delay; the pre-start grace absorbs clock
    skew between the controller (which records probe_start_ts on its
    own clock) and the sensor (which stamps events on its own clock).

    Set either grace to 0 to disable it. The old "events before start
    cannot be caused by this attack" semantic assumed single-clock
    attribution, which breaks when the controller and sensor are
    separate machines with NTP drift.
    """
    if event_ts < attack_start_ts - pre_start_grace_seconds:
        return False
    return event_ts <= attack_end_ts + grace_seconds


def matches_target(
    event_dest_ip: str | None,
    event_sni: str | None,
    target_type: str,
    target_value: str,
) -> bool:
    """True iff the event's destination matches the attack's target anchor.

    Attribution rules by target.type:

    - victim: event_dest_ip must equal target_value. SNI ignored.
    - sni:    event_sni (if present) must contain any of the SNI tokens
              in target_value (comma-separated). dest_ip ignored. The
              containment check is case-insensitive and substring-based
              so "trycloudflare.com" matches "something.trycloudflare.com"
              and the multi-host entry "anydesk.com,teamviewer.com"
              matches either literal.
    - external: accept match on dest_ip OR sni. Most permissive.

    Missing both event_dest_ip and event_sni => no match regardless of
    target.type.
    """
    if event_dest_ip is None and event_sni is None:
        return False

    if target_type == "victim":
        return event_dest_ip is not None and event_dest_ip == target_value

    if target_type == "sni":
        if event_sni is None:
            return False
        sni_lower = event_sni.lower()
        tokens = [t.strip().lower() for t in target_value.split(",") if t.strip()]
        return any(token in sni_lower for token in tokens)

    if target_type == "external":
        if event_dest_ip is not None and event_dest_ip == target_value:
            return True
        if event_sni is not None:
            sni_lower = event_sni.lower()
            tokens = [t.strip().lower() for t in target_value.split(",") if t.strip()]
            if any(token in sni_lower for token in tokens):
                return True
        return False

    # Unknown target type -- defensively return False. The catalog
    # validator should have rejected this earlier.
    return False


def filter_events(
    events: Iterable[dict[str, Any]],
    attack_start_ts: float,
    attack_end_ts: float,
    target_type: str,
    target_value: str,
    grace_seconds: float = DEFAULT_GRACE_SECONDS,
) -> list[dict[str, Any]]:
    """Return the subset of events attributable to one attack.

    Combines in_time_window and matches_target. Events missing the `ts`
    field are dropped silently -- the harvest module is expected to
    normalize timestamps before handing events to attribution.
    """
    out: list[dict[str, Any]] = []
    for event in events:
        ts = event.get("ts")
        # `isinstance(True, int)` is True in Python; explicitly exclude bool
        # so a harvest bug producing a boolean ts doesn't silently land in
        # attack windows as epoch 0/1. Mirrors verdict._extract_sids hygiene.
        if isinstance(ts, bool) or not isinstance(ts, (int, float)):
            continue
        if not in_time_window(float(ts), attack_start_ts, attack_end_ts, grace_seconds):
            continue
        if not matches_target(
            event.get("dest_ip"), event.get("sni"), target_type, target_value
        ):
            continue
        out.append(event)
    return out


def attribute_all(
    events: Iterable[dict[str, Any]],
    attack_windows: Iterable[AttackWindow],
    grace_seconds: float = DEFAULT_GRACE_SECONDS,
    pre_start_grace_seconds: float = DEFAULT_PRE_START_GRACE_SECONDS,
) -> dict[str, list[dict[str, Any]]]:
    """Exclusive attribution -- each event to AT MOST ONE attack.

    The run-level entry point. filter_events is still available for
    per-attack single-pass filtering (used by narrative-only code paths
    and tests) but for pipelining the whole ledger, callers should use
    this instead to avoid the same-event-in-N-windows bleed problem:
    when 20 of 23 attacks all target VICTIM_IP, the dest-match
    disambiguator is useless and back-to-back attacks double-count
    every alert whose timestamp straddles two windows.

    Priority rule (three tiers, discovered empirically during live-lab
    validation):

    1. STRICT match -- event's ts is inside an attack's real
       [start_ts, end_ts] window. Highest confidence. If multiple
       strict-match (overlapping windows, defensive case), pick the
       LATEST start_ts. Ties broken by name for determinism.

    2. POST-END GRACE match -- ts is in (end_ts, end_ts + grace].
       Accounts for Suricata's threshold bucketing / flow aging delay
       between triggering packet and alert emission. Pick the LATEST
       end_ts (most recently finished attack is most likely the cause).

    3. PRE-START GRACE match -- ts is in [start_ts - pre_grace, start_ts).
       Absorbs clock skew between the controller (records probe
       timestamps on its own clock) and the sensor (stamps events on
       its own clock). Pick the EARLIEST start_ts (closest to the
       event's apparent ts, since ts < start_ts).

    Why the tier ordering? Strict is the ground truth. Post-end grace
    is a well-understood Suricata semantic (threshold delay). Pre-start
    grace is a clock-correction heuristic -- speculative, so it loses
    to both stronger tiers when they apply.

    Why "latest" for strict/post-grace but "earliest" for pre-grace?
    Each picks the attack temporally CLOSEST to the event. A late
    alert should go to the most-recently-finished attack; an
    early-stamped alert should go to the next-to-start attack.

    Run 20260424T205801Z: icmpdoor [312-321] grace -> 324 covered an
    alert at 323.07 that actually came from masscan [322-325] strict.
    First-match-by-start gave it to icmpdoor (wrong -- icmpdoor is
    ICMP, can't trip a SYN-scan rule); strict-beats-grace gives it
    to masscan (right).

    Run 20260424T213703Z: whois-tunnel [start=1777066627.05] -- sensor
    stamped the SURICATA Applayer alert at 1777066626.55 due to ~0.9s
    clock skew. Without pre-start grace the alert was dropped.
    Pre-start grace (default 2s) correctly routes it to whois-tunnel.

    Returns a dict keyed by window.name, with every supplied window
    appearing in the result (empty list if no events attributed).
    Events matching no window are silently dropped. Windows with
    duplicate names are tolerated but collapse to one dict entry.
    """
    windows_list = list(attack_windows)
    result: dict[str, list[dict[str, Any]]] = {w.name: [] for w in windows_list}

    for event in events:
        ts = event.get("ts")
        if isinstance(ts, bool) or not isinstance(ts, (int, float)):
            continue
        ts_f = float(ts)
        dest_ip = event.get("dest_ip")
        sni = event.get("sni")

        # Tier 1: strict (no-grace) matches.
        strict = [
            w for w in windows_list
            if w.start_ts <= ts_f <= w.end_ts
            and matches_target(dest_ip, sni, w.target_type, w.target_value)
        ]
        if strict:
            chosen = max(strict, key=lambda w: (w.start_ts, w.name))
            result[chosen.name].append(event)
            continue

        # Tier 2: post-end grace (Suricata threshold delay).
        post_grace = [
            w for w in windows_list
            if w.end_ts < ts_f <= w.end_ts + grace_seconds
            and matches_target(dest_ip, sni, w.target_type, w.target_value)
        ]
        if post_grace:
            chosen = max(post_grace, key=lambda w: (w.end_ts, w.name))
            result[chosen.name].append(event)
            continue

        # Tier 3: pre-start grace (clock skew correction).
        pre_grace = [
            w for w in windows_list
            if w.start_ts - pre_start_grace_seconds <= ts_f < w.start_ts
            and matches_target(dest_ip, sni, w.target_type, w.target_value)
        ]
        if pre_grace:
            # Earliest start = closest boundary to the pre-start event.
            chosen = min(pre_grace, key=lambda w: (w.start_ts, w.name))
            result[chosen.name].append(event)

    return result
