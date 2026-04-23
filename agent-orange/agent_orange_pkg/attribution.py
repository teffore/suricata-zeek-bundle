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

from typing import Any, Iterable

# Default grace window (seconds) appended to the attack's end timestamp.
# Covers small clock drift between attacker and sensor and slight delay
# between the attack command returning and the first packet landing on
# the sensor.
DEFAULT_GRACE_SECONDS = 3.0


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
