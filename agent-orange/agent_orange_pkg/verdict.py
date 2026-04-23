"""verdict.py -- tiered verdict classifier for a single attack's evidence.

Pure set operations. No LLM, no heuristics beyond comparing the alerts/
notices that have already been attributed to this attack against the
SIDs/notices it was expected to fire. The runner handles FAILED (the
attack command itself didn't run); everything else comes from here.

Verdict tiers:

    DETECTED_EXPECTED    all expected_sids fired, all expected_zeek_notices fired
    DETECTED_PARTIAL     some-but-not-all of the expected signals fired
    DETECTED_UNEXPECTED  no expected signal fired, but SOMETHING did
                         (another SID or a Zeek notice with dest match)
    UNDETECTED           nothing attributable fired

FAILED is emitted directly by the runner when the attack command itself
errored and never produced network traffic -- it's not a classification
outcome, it's a run outcome, so this module doesn't return it.
"""

from __future__ import annotations

from typing import Any, Iterable


VERDICT_DETECTED_EXPECTED = "DETECTED_EXPECTED"
VERDICT_DETECTED_PARTIAL = "DETECTED_PARTIAL"
VERDICT_DETECTED_UNEXPECTED = "DETECTED_UNEXPECTED"
VERDICT_UNDETECTED = "UNDETECTED"
VERDICT_FAILED = "FAILED"  # emitted by runner, included here as a constant

ALL_VERDICTS = (
    VERDICT_DETECTED_EXPECTED,
    VERDICT_DETECTED_PARTIAL,
    VERDICT_DETECTED_UNEXPECTED,
    VERDICT_UNDETECTED,
    VERDICT_FAILED,
)


def classify(
    alerts: Iterable[dict[str, Any]],
    notices: Iterable[dict[str, Any]],
    expected_sids: Iterable[int],
    expected_zeek_notices: Iterable[str] = (),
) -> str:
    """Return the verdict string for one attack's attributed evidence.

    Inputs are the ALREADY-ATTRIBUTED alerts and notices -- the caller
    (the runner) runs the attribution filter first and only passes
    matching events here. That keeps this function pure and trivially
    testable.

    `alerts` items must have an integer `sid` field; items missing or
    with a non-integer sid are silently skipped (the harvest module is
    responsible for normalizing this). `notices` items must have a
    string `note` field (Zeek convention).
    """
    fired_sids = _extract_sids(alerts)
    fired_notices = _extract_notices(notices)
    expected_sid_set = {int(s) for s in expected_sids}
    expected_notice_set = set(expected_zeek_notices)

    # How many of each expected signal fired? Totals include both SID
    # and notice expectations; an attack can declare both.
    sid_expected_hit = fired_sids & expected_sid_set
    notice_expected_hit = fired_notices & expected_notice_set
    total_expected = len(expected_sid_set) + len(expected_notice_set)
    total_expected_hit = len(sid_expected_hit) + len(notice_expected_hit)

    # Anything at all fire?
    any_fire = bool(fired_sids or fired_notices)

    if total_expected == 0:
        # Nothing was expected. Any fire is UNEXPECTED; silence is UNDETECTED.
        return VERDICT_DETECTED_UNEXPECTED if any_fire else VERDICT_UNDETECTED

    if total_expected_hit == 0:
        # Something was expected but none of it fired.
        # Did something ELSE fire (with correct attribution)?
        return VERDICT_DETECTED_UNEXPECTED if any_fire else VERDICT_UNDETECTED

    if total_expected_hit == total_expected:
        return VERDICT_DETECTED_EXPECTED

    return VERDICT_DETECTED_PARTIAL


def _extract_sids(alerts: Iterable[dict[str, Any]]) -> set[int]:
    out: set[int] = set()
    for a in alerts:
        sid = a.get("sid")
        if isinstance(sid, int) and not isinstance(sid, bool):
            out.add(sid)
    return out


def _extract_notices(notices: Iterable[dict[str, Any]]) -> set[str]:
    out: set[str] = set()
    for n in notices:
        note = n.get("note")
        if isinstance(note, str) and note:
            out.add(note)
    return out
