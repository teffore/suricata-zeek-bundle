#!/usr/bin/env python3
"""summarize.py -- post-run summarizer for the 10-probe ART speed-test.

Reads the most recent `reports/findings-<ts>.jsonl` + `reports/accuracy-<ts>.json`
produced by purple_agent.py, compares the actual probe order against the pinned
pool, and emits `benchmarks/results/benchmark-<ts>.json` with per-probe
inferred durations and detection summary. Also prints a one-screen summary to
stdout so a human can eyeball the result without opening the JSON.

The core logic is split into pure functions so it can be unit-tested without
an actual agent run.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ----------------------------- pure helpers ----------------------------------

def parse_iso_ts(ts: str) -> float:
    """Parse an ISO-8601 timestamp (with or without 'Z') to epoch seconds.

    Returns 0.0 on failure rather than raising so a single malformed entry
    can't crash the summarizer.
    """
    if not ts:
        return 0.0
    try:
        cleaned = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned).timestamp()
    except ValueError:
        return 0.0


def load_pool_probe_names(pool_path: Path) -> list[str]:
    """Return probe names from a pool YAML in document order.

    Falls back to a regex scan if PyYAML isn't importable, which keeps tests
    runnable in minimal environments. Pool order matters — it's what
    order_honored compares against.
    """
    text = pool_path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore
    except ImportError:
        yaml = None  # type: ignore

    if yaml is not None:
        data = yaml.safe_load(text) or {}
        probes = data.get("probes", []) or []
        return [p.get("name", "") for p in probes if p.get("name")]

    names: list[str] = []
    for line in text.splitlines():
        m = re.match(r"\s*-\s*name:\s*(\S+)\s*$", line)
        if m:
            names.append(m.group(1))
    return names


def load_ledger(ledger_path: Path) -> list[dict]:
    """Parse a findings-*.jsonl file into a list of ledger dicts."""
    entries: list[dict] = []
    with ledger_path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return entries


def find_latest_by_ts(reports_dir: Path, prefix: str, ext: str) -> Path | None:
    """Return the lexicographically-newest reports/<prefix>-<ts>.<ext>.

    The ts format (%Y%m%dT%H%M%SZ) is lex-sortable, so a plain sort works.
    """
    pattern = f"{prefix}-*.{ext}"
    candidates = sorted(reports_dir.glob(pattern))
    return candidates[-1] if candidates else None


def extract_ts_from_path(path: Path, prefix: str) -> str:
    """Pull the timestamp chunk out of a reports artifact filename."""
    stem = path.stem
    if stem.startswith(f"{prefix}-"):
        return stem[len(prefix) + 1:]
    return ""


def compute_per_probe(
    ledger: list[dict],
    expected_order: list[str],
    end_epoch: float,
) -> list[dict]:
    """Build per-probe records with inferred durations.

    Duration for probe N = ts(N+1) - ts(N); the final probe's duration uses
    end_epoch (wall-clock run end) as its upper bound. This bundles SSH +
    LLM + probe-exec time together, which is fine for comparing runs —
    phase-level breakdown is a follow-up concern.
    """
    rows: list[dict] = []
    ledger_ts = [parse_iso_ts(e.get("ts", "")) for e in ledger]

    for idx, entry in enumerate(ledger):
        cur_ts = ledger_ts[idx]
        if idx + 1 < len(ledger) and ledger_ts[idx + 1] >= cur_ts > 0:
            next_ts = ledger_ts[idx + 1]
        else:
            next_ts = end_epoch if end_epoch >= cur_ts > 0 else cur_ts
        duration = max(0.0, next_ts - cur_ts) if cur_ts > 0 else 0.0

        expected_name = expected_order[idx] if idx < len(expected_order) else ""
        actual_name = entry.get("probe", "")
        rows.append({
            "order": idx + 1,
            "expected": expected_name,
            "actual": actual_name,
            "ts": entry.get("ts", ""),
            "inferred_duration_s": round(duration, 2),
            "verdict": entry.get("verdict", ""),
            "confidence": entry.get("confidence", ""),
            "mitre_id": entry.get("mitre_id", ""),
        })
    return rows


def compute_order_honored(actual: list[str], expected: list[str]) -> bool:
    """True iff actual probe sequence exactly matches expected pool order.

    We don't accept partial matches — the whole point of the benchmark is
    that the same 10 probes run in the same order so wall-clock is apples
    to apples.
    """
    if len(actual) != len(expected):
        return False
    return all(a == e for a, e in zip(actual, expected))


def summarize_detection(ledger: list[dict]) -> dict[str, Any]:
    """Bucket ledger entries by verdict for a quick coverage view."""
    total = len(ledger)
    detected = 0
    undetected = 0
    other = 0
    per_verdict: dict[str, int] = {}
    for e in ledger:
        v = (e.get("verdict") or "").strip()
        per_verdict[v] = per_verdict.get(v, 0) + 1
        # Treat anything starting with DETECTED (incl. DETECTED_UNEXPECTED,
        # DETECTED_PARTIAL) as a hit; UNDETECTED as a miss; rest as other.
        v_upper = v.upper()
        if v_upper.startswith("DETECTED"):
            detected += 1
        elif v_upper == "UNDETECTED":
            undetected += 1
        else:
            other += 1
    coverage_pct = round(100.0 * detected / total, 1) if total else 0.0
    return {
        "total": total,
        "detected": detected,
        "undetected": undetected,
        "other": other,
        "coverage_pct": coverage_pct,
        "verdict_distribution": per_verdict,
    }


def build_summary(
    run_id: str,
    start_iso: str,
    end_iso: str,
    start_epoch: float,
    end_epoch: float,
    expected_order: list[str],
    ledger: list[dict],
    audit: dict | None,
) -> dict[str, Any]:
    """Assemble the final benchmark JSON shape."""
    actual_order = [e.get("probe", "") for e in ledger]
    per_probe = compute_per_probe(ledger, expected_order, end_epoch)
    detection = summarize_detection(ledger)
    total_seconds = max(0, int(end_epoch - start_epoch))

    accuracy_block = {
        "overclaim_count": 0,
        "structural_issues_count": 0,
        "sensor_alerts_in_window": 0,
        "sensor_notices_in_window": 0,
    }
    if audit:
        accuracy_block["overclaim_count"] = int(audit.get("overclaim_count", 0) or 0)
        accuracy_block["structural_issues_count"] = len(
            audit.get("structural_issues", []) or []
        )
        accuracy_block["sensor_alerts_in_window"] = int(
            audit.get("sensor_alerts_in_window", 0) or 0
        )
        accuracy_block["sensor_notices_in_window"] = int(
            audit.get("sensor_notices_in_window", 0) or 0
        )

    return {
        "run_id": run_id,
        "started_at": start_iso,
        "ended_at": end_iso,
        "total_seconds": total_seconds,
        "probes_expected": len(expected_order),
        "probes_run": len(ledger),
        "order_honored": compute_order_honored(actual_order, expected_order),
        "expected_order": expected_order,
        "actual_order": actual_order,
        "per_probe": per_probe,
        "detection_summary": detection,
        "accuracy": accuracy_block,
    }


# ----------------------------- stdout printer --------------------------------

def print_summary(summary: dict[str, Any]) -> None:
    """Print a one-screen summary to stdout. Reads from the JSON shape only."""
    bar = "=" * 72
    print(bar)
    print(f"benchmark: {summary['run_id']}")
    print(bar)
    print(f"total wall-clock: {summary['total_seconds']}s "
          f"({summary['total_seconds'] / 60:.1f} min)")
    print(f"probes:           {summary['probes_run']}/{summary['probes_expected']}")
    print(f"order honored:    {summary['order_honored']}")

    det = summary["detection_summary"]
    print(f"detection:        {det['detected']} det / "
          f"{det['undetected']} und / {det['other']} other "
          f"({det['coverage_pct']}% coverage)")

    acc = summary["accuracy"]
    print(f"accuracy:         overclaims={acc['overclaim_count']} "
          f"structural={acc['structural_issues_count']} "
          f"alerts_in_window={acc['sensor_alerts_in_window']}")

    print()
    print(f"{'#':<3} {'probe':<34} {'dur(s)':>7} {'verdict':<12} conf")
    print("-" * 72)
    for row in summary["per_probe"]:
        mismatch = " !" if row["actual"] != row["expected"] else ""
        print(
            f"{row['order']:<3} {(row['actual'] or '(empty)')[:33]:<34} "
            f"{row['inferred_duration_s']:>7.1f} "
            f"{(row['verdict'] or '-')[:11]:<12} "
            f"{(row['confidence'] or '-')[:4]}{mismatch}"
        )
    if not summary["order_honored"]:
        print()
        print("WARN: probe order differs from pool. Totals still comparable,")
        print("      but per-probe duration comparisons are unreliable until")
        print("      you re-run or add a --deterministic-order flag upstream.")


# ------------------------------- cli -----------------------------------------

def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--agent-dir",   required=True, help="purple-agent root (contains reports/)")
    p.add_argument("--pool",        required=True, help="pinned probe pool yaml")
    p.add_argument("--results-dir", required=True, help="where to write benchmark JSON")
    p.add_argument("--start-epoch", required=True, type=float)
    p.add_argument("--end-epoch",   required=True, type=float)
    p.add_argument("--start-iso",   required=True)
    p.add_argument("--end-iso",     required=True)
    args = p.parse_args()

    agent_dir = Path(args.agent_dir).resolve()
    pool_path = Path(args.pool).resolve()
    results_dir = Path(args.results_dir).resolve()
    reports_dir = agent_dir / "reports"

    if not reports_dir.is_dir():
        print(f"summarize: reports dir missing: {reports_dir}", file=sys.stderr)
        return 1

    findings_path = find_latest_by_ts(reports_dir, "findings", "jsonl")
    if findings_path is None:
        print(f"summarize: no findings-*.jsonl in {reports_dir}", file=sys.stderr)
        return 1

    run_id = extract_ts_from_path(findings_path, "findings")
    audit_path = reports_dir / f"accuracy-{run_id}.json"
    audit: dict | None = None
    if audit_path.exists():
        try:
            audit = json.loads(audit_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            audit = None

    ledger = load_ledger(findings_path)
    expected_order = load_pool_probe_names(pool_path)

    summary = build_summary(
        run_id=run_id,
        start_iso=args.start_iso,
        end_iso=args.end_iso,
        start_epoch=args.start_epoch,
        end_epoch=args.end_epoch,
        expected_order=expected_order,
        ledger=ledger,
        audit=audit,
    )

    results_dir.mkdir(parents=True, exist_ok=True)
    out_path = results_dir / f"benchmark-{run_id}.json"
    out_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"benchmark written: {out_path}")
    print()
    print_summary(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
