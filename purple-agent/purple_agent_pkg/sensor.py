"""sensor.py — pure-function helpers for sensor-log parsing + ledger audit.

Extracted from purple_agent.py so the end-of-run accuracy audit and Zeek
sweep can be unit-tested without SSH, AWS, or claude-agent-sdk.

The SSH I/O (subprocess.run against the sensor host) stays in
purple_agent.py. Only the deterministic bits live here:

  * parse_sectioned_jq_stream -- splits the compound "=== SECTION ===\n{json}\n..."
    stream produced by the audit + sweep remote commands into a dict of
    per-section entry lists. Used by both _end_of_run_accuracy_audit and
    _end_of_run_zeek_sweep (same format, different marker sets).

  * normalize_suricata_ts -- turns a Suricata-format timestamp into a POSIX
    epoch. Handles the three tz styles that show up in eve.json + the
    agent's own ledger: compact "+0000", colon "+00:00", and shorthand "Z".
    Returns 0.0 on parse failure so callers can treat "no-ts" as "out-of-
    window" without a second branch.

  * compute_audit -- the ledger-vs-sensor cross-check. Given the parsed
    sensor alerts/notices and the ledger, produces the per-probe audit
    dict (verified/unverified SIDs, structural issues, overclaim count,
    aggregate counts).

All three functions are pure: no network, no filesystem, no clock.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, Iterable, List, Mapping


# ============================================================================
#  stream parsing
# ============================================================================

def parse_sectioned_jq_stream(
    raw: str,
    markers: Mapping[str, str],
) -> Dict[str, List[Any]]:
    """Parse a compound "=== SECTION ===\\n{json line}\\n..." stream.

    Both the accuracy audit and Zeek sweep remote commands echo a banner
    like "=== ALERTS ===" followed by jq-compact JSON lines, then another
    banner for the next section. This walks the raw stdout, routes each
    JSON line into the bucket named by the most recent banner, and
    silently skips malformed lines (jq occasionally emits a truncated
    line if the input file rotates mid-tail).

    Args:
        raw: the raw ssh stdout as a single string.
        markers: ordered mapping of banner text -> output key. Example:
            {"=== ALERTS ===": "alerts", "=== NOTICES ===": "notices"}
            Banner text is matched after stripping each input line, so
            surrounding whitespace doesn't matter.

    Returns:
        {output_key: [parsed JSON dicts]} for every key in `markers`.
        Keys always appear in the result even if the section was empty.
        Lines that appear before any banner are dropped.
    """
    buckets: Dict[str, List[Any]] = {key: [] for key in markers.values()}
    current_key: str | None = None
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if line in markers:
            current_key = markers[line]
            continue
        if current_key is None:
            # Content before the first banner -- drop it (shouldn't happen
            # with the remote commands we issue, but jq errors could leak).
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        buckets[current_key].append(entry)
    return buckets


# ============================================================================
#  timestamp normalization
# ============================================================================

def normalize_suricata_ts(ts_raw: Any) -> float:
    """Convert a Suricata/ledger timestamp string into a POSIX epoch float.

    Handles all three tz styles we see in the wild:
      - Compact offset: "2026-04-21T23:58:37.123456+0000"
      - Colon offset:   "2026-04-21T23:58:37.123456+00:00"
      - Zulu shorthand: "2026-04-21T23:58:37Z"

    Python 3.11+ fromisoformat accepts the compact offset natively, but
    older Pythons don't; normalizing here keeps us compatible with both.

    Args:
        ts_raw: the raw timestamp. Anything non-string or empty returns 0.0.

    Returns:
        POSIX epoch seconds as a float, or 0.0 on parse failure. Callers
        treat 0.0 as "unusable for windowing" -- never a real run time.
    """
    if not isinstance(ts_raw, str) or not ts_raw:
        return 0.0
    ts = ts_raw.replace("Z", "+00:00")
    # Compact tz like "+0000" / "-0500" -> insert colon so fromisoformat
    # on pre-3.11 accepts it. Must check ":" is absent from the last 5
    # chars so we don't double-insert on an already-colon-formatted ts.
    if len(ts) >= 5 and ts[-5] in ("+", "-") and ":" not in ts[-5:]:
        ts = ts[:-2] + ":" + ts[-2:]
    try:
        return datetime.fromisoformat(ts).timestamp()
    except Exception:
        return 0.0


# ============================================================================
#  ledger audit
# ============================================================================

def compute_audit(
    sensor_alerts: Iterable[Mapping[str, Any]],
    sensor_notices: Iterable[Mapping[str, Any]],
    ledger: List[Mapping[str, Any]],
    run_start: float,
    window_sec: int,
) -> Dict[str, Any]:
    """Cross-check ledger probe claims against the sensor ground truth.

    The audit is the second half of the agent's trust model: the report
    only lists what the LLM *claimed*, so we have to independently verify
    each claim against the raw sensor logs before the report is honest.

    Causal attribution rule:
      A claimed Suricata SID is "verified" iff the sensor recorded an
      alert with that SID within ±`window_sec` of the probe's own
      timestamp, AND only alerts at-or-after `run_start` are considered
      at all. The run_start floor is critical: without it, a historical
      alert with a matching SID would falsely "verify" a probe that
      actually fired nothing.

    Structural guards:
      - DETECTED verdict with no fired_sids, no zeek_notices, and no
        zeek_signals is flagged as "DETECTED with no evidence". The
        agent is not allowed to claim detection without pointing at
        something.
      - Missing probe names and duplicate probe names are both flagged;
        duplicates usually mean the agent re-ran a probe and the audit
        needs humans to know.

    Args:
        sensor_alerts: parsed alert entries from eve.json. Each should
            have "sid" and "ts" keys; entries without a usable ts are
            skipped.
        sensor_notices: parsed notices (currently used only for the
            aggregate count; future versions may match by note name).
        ledger: the agent's findings ledger, already loaded from JSONL.
        run_start: POSIX epoch for when the run began. Alerts before
            this timestamp are excluded to prevent historical alerts
            from back-verifying current claims.
        window_sec: the total run window (not the ±-window for matching;
            the ±60 matching window is hard-coded and is what actually
            ties an alert to a probe).

    Returns:
        Audit dict matching the legacy shape (run_start_epoch,
        window_sec, total_probes, verdict_distribution,
        sensor_alerts_in_window, sensor_unique_sids,
        sensor_notices_in_window, structural_issues, overclaim_count,
        probe_audits).
    """
    sensor_alerts = list(sensor_alerts)
    sensor_notices = list(sensor_notices)

    # Index sensor alerts by SID with a list of timestamps for the ±60s
    # window comparison. Only alerts at-or-after run_start make the cut.
    sid_timestamps: Dict[str, List[float]] = {}
    for a in sensor_alerts:
        sid = str(a.get("sid", ""))
        ts_epoch = normalize_suricata_ts(a.get("ts", ""))
        if ts_epoch and ts_epoch >= run_start:
            sid_timestamps.setdefault(sid, []).append(ts_epoch)

    probe_audits: List[Dict[str, Any]] = []
    overclaim_count = 0
    structural_issues: List[Dict[str, Any]] = []
    seen_probes: set = set()

    for entry in ledger:
        probe = entry.get("probe", "")
        if not probe:
            structural_issues.append(
                {"issue": "missing probe_name", "entry_ts": entry.get("ts", "")}
            )
            continue
        if probe in seen_probes:
            structural_issues.append({"issue": "duplicate probe name", "probe": probe})
        seen_probes.add(probe)

        verdict = entry.get("verdict", "")
        if verdict == "DETECTED":
            has_sid = bool(entry.get("fired_sids", []))
            has_notice = bool(entry.get("zeek_notices", []))
            zsig = entry.get("zeek_signals", "") or ""
            has_zsig = bool(zsig) and zsig.lower().strip() not in ("empty", "none", "")
            if not (has_sid or has_notice or has_zsig):
                structural_issues.append(
                    {
                        "issue": (
                            "DETECTED with no evidence "
                            "(no fired_sids, no zeek_notices, no zeek_signals)"
                        ),
                        "probe": probe,
                    }
                )

        claimed_sids = entry.get("fired_sids", []) or []
        probe_ts = normalize_suricata_ts(entry.get("ts", ""))

        verified_sids: List[Any] = []
        unverified_sids: List[Any] = []
        if probe_ts:
            for sid in claimed_sids:
                firings = sid_timestamps.get(str(sid), [])
                match = any(abs(t - probe_ts) <= 60 for t in firings)
                (verified_sids if match else unverified_sids).append(sid)

        if unverified_sids:
            overclaim_count += 1

        probe_audits.append(
            {
                "probe": probe,
                "ts": entry.get("ts", ""),
                "verdict": entry.get("verdict", ""),
                "claimed_sids": claimed_sids,
                "verified_sids": verified_sids,
                "unverified_sids": unverified_sids,
            }
        )

    total_probes = len(ledger)
    verdicts: Dict[str, int] = {}
    for e in ledger:
        v = e.get("verdict", "?")
        verdicts[v] = verdicts.get(v, 0) + 1

    return {
        "run_start_epoch": run_start,
        "window_sec": window_sec,
        "total_probes": total_probes,
        "verdict_distribution": verdicts,
        "sensor_alerts_in_window": len(sensor_alerts),
        "sensor_unique_sids": len({str(a.get("sid", "")) for a in sensor_alerts}),
        "sensor_notices_in_window": len(sensor_notices),
        "structural_issues": structural_issues,
        "overclaim_count": overclaim_count,
        "probe_audits": probe_audits,
    }
