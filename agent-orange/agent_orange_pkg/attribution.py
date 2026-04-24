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

# Default grace window (seconds) appended to the attack's end timestamp.
# Covers small clock drift between attacker and sensor and slight delay
# between the attack command returning and the first packet landing on
# the sensor.
DEFAULT_GRACE_SECONDS = 3.0


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
) -> bool:
    """True iff event_ts falls within [attack_start_ts, attack_end_ts + grace].

    The grace window extends AFTER the attack, never before -- events that
    fire before the attack started cannot be caused by it. Equality at
    either boundary counts as inside (inclusive).
    """
    if event_ts < attack_start_ts:
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
) -> dict[str, list[dict[str, Any]]]:
    """Exclusive attribution -- each event to AT MOST ONE attack.

    The run-level entry point. filter_events is still available for
    per-attack single-pass filtering (used by narrative-only code paths
    and tests) but for pipelining the whole ledger, callers should use
    this instead to avoid the same-event-in-N-windows bleed problem:
    when 20 of 23 attacks all target VICTIM_IP, the dest-match
    disambiguator is useless and back-to-back attacks double-count
    every alert whose timestamp straddles two windows.

    Algorithm: sort windows by start_ts (stable, deterministic). For
    each event, scan windows in that order; assign to the FIRST one
    whose time-window AND target BOTH match. Break ties toward earlier
    attacks -- consistent with the "alert is caused by the attack that
    triggered it, not the one that happened to run next."

    Returns a dict keyed by window.name, with every supplied window
    appearing in the result (empty list if no events attributed).
    Events matching no window are silently dropped (caller can detect
    this by summing list lengths vs. input events).

    Windows with duplicate names are tolerated but result in a single
    dict entry per name -- the caller is responsible for ensuring
    uniqueness if that matters.
    """
    windows_list = list(attack_windows)
    # Stable sort by start_ts for deterministic first-match.
    sorted_windows = sorted(windows_list, key=lambda w: w.start_ts)

    result: dict[str, list[dict[str, Any]]] = {w.name: [] for w in windows_list}

    for event in events:
        ts = event.get("ts")
        if isinstance(ts, bool) or not isinstance(ts, (int, float)):
            continue
        ts_f = float(ts)
        dest_ip = event.get("dest_ip")
        sni = event.get("sni")
        for w in sorted_windows:
            if not in_time_window(ts_f, w.start_ts, w.end_ts, grace_seconds):
                continue
            if not matches_target(dest_ip, sni, w.target_type, w.target_value):
                continue
            # First match wins; don't bleed to any subsequent window.
            result[w.name].append(event)
            break
    return result
