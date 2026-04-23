"""render.py -- emit a RunLedger as JSON, HTML, and Markdown.

Agent Orange produces three artifacts per run at
agent-orange/runs/<run_id>/:

    ledger.json   -- structured, machine-readable source of truth
    report.html   -- self-contained human-readable report
    report.md     -- terminal / git / wiki-friendly rendering

All three are generated from the same RunLedger. JSON is the
authoritative form; HTML and Markdown are derived views.

No external template engine -- plain Python string composition. Keeps
the agent-orange dependency surface tiny (PyYAML + anthropic only).
"""

from __future__ import annotations

import html as html_mod
import json
import re
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from agent_orange_pkg.ledger import AttackLedgerEntry, Narrative, RunLedger


# Zeek stats.log format: the interval summary lines include
# `pkts_dropped=N`. We scrape this to surface a warning in the report
# when the sensor dropped packets during the run -- UNDETECTED verdicts
# deserve an asterisk when capture was lossy.
_PKTS_DROPPED_RE = re.compile(r"pkts_dropped\s*[=:]\s*(\d+)", re.IGNORECASE)
# TSV-format path matcher for loaded_scripts.log when json-logs isn't
# enabled. Lines are just a script path ending in .zeek or .bro.
_LOADED_SCRIPT_LINE_RE = re.compile(r"^\s*\S+\.(zeek|bro)\s*$")


# Verdict badge mapping: internal tier -> visible text.
# `DETECTED_EXPECTED` is the only tier that carries a mark; PARTIAL and
# UNEXPECTED both render as plain "DETECTED" so the UNEXPECTED word never
# appears in human-facing output. Full tier still lives in ledger.json.
_VERDICT_BADGE_UNICODE = {
    "DETECTED_EXPECTED": "DETECTED \u2713",
    "DETECTED_PARTIAL": "DETECTED",
    "DETECTED_UNEXPECTED": "DETECTED",
    "UNDETECTED": "UNDETECTED",
    "FAILED": "FAILED",
}
_VERDICT_BADGE_ASCII = {
    "DETECTED_EXPECTED": "DETECTED [x]",
    "DETECTED_PARTIAL": "DETECTED",
    "DETECTED_UNEXPECTED": "DETECTED",
    "UNDETECTED": "UNDETECTED",
    "FAILED": "FAILED",
}


def format_verdict_badge(tier: str, style: str) -> str:
    """Return the human-facing badge for an internal verdict tier.

    style:
      "unicode" -- HTML and Markdown renderers pass this. The mark is
                   U+2713. Renders cleanly in all major viewers.
      "ascii"   -- stdout summary passes this. Mark is "[x]". Windows
                   CMD legacy code pages can't render U+2713 reliably.

    Unknown tier -> returns the tier string unchanged (defensive: lets a
    future tier-addition in verdict.py surface visibly without crashing
    the report).
    Unknown style -> falls back to unicode.
    """
    table = _VERDICT_BADGE_ASCII if style == "ascii" else _VERDICT_BADGE_UNICODE
    return table.get(tier, tier)


def format_suricata_cell(alerts) -> str:
    """Format the Suricata column cell for the main attack table.

    Takes an iterable of attributed Suricata alert dicts (each must have
    an integer `sid` field; non-int and missing sid fields are skipped
    defensively, matching verdict._extract_sids hygiene).

    Output shape:
      - 0 alerts      -> "--"
      - 1 alert       -> "1 (<sid>)"
      - 2-3 alerts    -> "N (sid1, sid2, sid3)"
      - 4+ alerts     -> "N (sid1, sid2, sid3, +K more)" where K=N-3

    SIDs are deduplicated and sorted ascending for stable output across
    runs (otherwise dict iteration order could shuffle them).
    """
    if not alerts:
        return "\u2014"
    sids: set[int] = set()
    for a in alerts:
        sid = a.get("sid") if isinstance(a, dict) else None
        if isinstance(sid, int) and not isinstance(sid, bool):
            sids.add(sid)
    if not sids:
        return "\u2014"
    sorted_sids = sorted(sids)
    n = len(sorted_sids)
    if n <= 3:
        inline = ", ".join(str(s) for s in sorted_sids)
        return f"{n} ({inline})"
    head = ", ".join(str(s) for s in sorted_sids[:3])
    extra = n - 3
    return f"{n} ({head}, +{extra} more)"


def format_zeek_cell(notices) -> str:
    """Format the Zeek column cell for the main attack table.

    Takes an iterable of attributed Zeek notice dicts (each must have a
    non-empty string `note` field). Intel Framework hits arrive here
    too -- harvest.py synthesizes "Intel::<tag>" note values for them.

    Output shape:
      - 0 notices    -> "--"
      - 1 notice     -> "1 (<note>)"
      - 2 notices    -> "N (note1, note2)"  (threshold)
      - 3+ notices   -> "N (note1, note2, +K more)" where K=N-2

    Note type names are longer than SIDs (e.g., "FTP::Bruteforcing_User"),
    so we truncate at 2 rather than 3 to keep the column scannable.

    Notes are deduplicated and sorted alphabetically for stable output.
    """
    if not notices:
        return "\u2014"
    names: set[str] = set()
    for n in notices:
        note = n.get("note") if isinstance(n, dict) else None
        if isinstance(note, str) and note:
            names.add(note)
    if not names:
        return "\u2014"
    sorted_names = sorted(names)
    count = len(sorted_names)
    if count <= 2:
        inline = ", ".join(sorted_names)
        return f"{count} ({inline})"
    head = ", ".join(sorted_names[:2])
    extra = count - 2
    return f"{count} ({head}, +{extra} more)"


def _count_loaded_scripts(loaded_text: str) -> int:
    """Count Zeek scripts in a loaded_scripts.log body.

    Handles both formats the sensor may produce:

    - **JSON** (when Zeek has ``policy/tuning/json-logs`` loaded, which
      standalone.sh does): lines like ``{"name":"/path/script.zeek"}``.
      Counted if the line parses as a JSON object with a ``name`` key.
    - **TSV** (Zeek default): lines are just the script path ending in
      ``.zeek`` or ``.bro``. Counted via _LOADED_SCRIPT_LINE_RE.

    Each line is tried against JSON first (cheap fast-fail if it doesn't
    start with ``{``), then the TSV regex. Lines that match neither --
    comments, preamble, whitespace, malformed entries -- are silently
    skipped. This mirrors the tolerance other harvest normalizers apply
    to heterogeneous Zeek log shapes.
    """
    count = 0
    for line in loaded_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("{"):
            # JSON-shaped lines are EXCLUSIVELY in the JSON path; if the
            # parse fails or the object lacks a `name` key, skip entirely.
            # The TSV fallback is only for genuine TSV input, so letting
            # a broken-JSON line fall through and happen to match the
            # `.zeek$` regex (e.g., `{not-valid-json.zeek`) would be an
            # asymmetric false positive.
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict) and "name" in obj:
                count += 1
            continue
        if _LOADED_SCRIPT_LINE_RE.match(stripped):
            count += 1
    return count


def _sensor_health_summary(ledger: RunLedger) -> dict[str, Any]:
    """Pull a few ops-relevant numbers out of zeek_stats/loaded_scripts.

    Pure function; string-scans the raw capture.

    Two "captured" flags so the renderer can distinguish:
      - `captured`            : either diagnostic log has content
      - `loaded_scripts_captured` : specifically loaded_scripts.log had
        content. Zeek rotates this log into the daily archive once per
        Zeek-start; runs after that rotation get an empty capture even
        though Zeek is healthy. Without this flag the report shows
        "Zeek scripts loaded: 0" which misleads operators into thinking
        no scripts are loaded.
    """
    stats_text = ledger.zeek_stats or ""
    loaded_text = ledger.zeek_loaded_scripts or ""
    drops = [int(m.group(1)) for m in _PKTS_DROPPED_RE.finditer(stats_text)]
    return {
        "captured": bool(stats_text or loaded_text),
        "loaded_scripts_captured": bool(loaded_text.strip()),
        "total_packets_dropped": sum(drops),
        "drop_samples": len(drops),
        "loaded_scripts_count": _count_loaded_scripts(loaded_text),
    }


# ---------------------------------------------------------------------------
#  JSON
# ---------------------------------------------------------------------------

def ledger_to_dict(ledger: RunLedger) -> dict[str, Any]:
    """Convert a RunLedger to a plain dict suitable for json.dump.

    Expands every dataclass via dataclasses.asdict (recurses nested
    dataclasses) and normalizes frozensets / tuples. Used by both the
    JSON emitter and the HTML builder so any schema drift happens in
    one place.
    """
    d = _as_plain(ledger)
    # Flatten RulesetSnapshot's enabled_sids (a frozenset) to a sorted
    # list of ints for stable JSON diffs.
    snap = d.get("ruleset_snapshot") or {}
    if isinstance(snap.get("enabled_sids"), (set, frozenset, list)):
        snap["enabled_sids"] = sorted(int(s) for s in snap["enabled_sids"])
    drift = d.get("ruleset_drift")
    if drift is not None:
        for key in ("added_sids", "removed_sids"):
            if isinstance(drift.get(key), (set, frozenset, list)):
                drift[key] = sorted(int(s) for s in drift[key])
    d["summary"] = {
        "total_attacks": len(ledger.attacks),
        "detected": ledger.detected_count(),
        "coverage_pct": ledger.coverage_pct(),
        "total_seconds": ledger.total_seconds(),
        "verdict_counts": ledger.verdict_counts(),
    }
    return d


def _as_plain(value: Any) -> Any:
    """Recursively convert dataclasses / frozensets into JSON-safe shapes."""
    if is_dataclass(value):
        return _as_plain(asdict(value))
    if isinstance(value, dict):
        return {k: _as_plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_as_plain(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted((_as_plain(v) for v in value), key=str)
    return value


def write_json(ledger: RunLedger, out_path: Path) -> None:
    """Write ledger.json. Overwrites any existing file at the path."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(ledger_to_dict(ledger), indent=2, sort_keys=False),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
#  Markdown
# ---------------------------------------------------------------------------

def render_markdown(ledger: RunLedger) -> str:
    """Build the report.md body as a plain string."""
    lines: list[str] = []

    lines.append(f"# Agent Orange Run Report -- {ledger.run_id}")
    lines.append("")
    lines.append(f"- **Run ID:** `{ledger.run_id}`")
    lines.append(f"- **Victim:** `{ledger.victim_ip}`")
    lines.append(f"- **Sensor:** `{ledger.sensor_host}`")
    lines.append(f"- **Attacker:** `{ledger.attacker_host}`")
    lines.append(f"- **Attacks catalog:** `{ledger.attacks_yaml_path}`")
    lines.append(
        f"- **Wall clock:** {ledger.total_seconds()}s "
        f"({ledger.total_seconds() / 60:.1f} min)"
    )
    lines.append(f"- **Agent Orange version:** `{ledger.agent_orange_version}`")
    lines.append("")

    # Summary block
    vc = ledger.verdict_counts()
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Attacks run:** {len(ledger.attacks)}")
    lines.append(f"- **Coverage:** {ledger.coverage_pct()}% "
                 f"({ledger.detected_count()} detected)")
    lines.append(f"- **Verdicts:** " + ", ".join(
        f"{k}={v}" for k, v in sorted(vc.items())
    ))
    lines.append(
        f"- **Ruleset SIDs enabled:** "
        f"{len(ledger.ruleset_snapshot.enabled_sids)}"
    )
    if ledger.ruleset_drift is not None:
        added = len(ledger.ruleset_drift.added_sids)
        removed = len(ledger.ruleset_drift.removed_sids)
        lines.append(
            f"- **Ruleset drift vs prior run:** +{added} / -{removed}"
        )
    lines.append("")

    # Sensor health
    health = _sensor_health_summary(ledger)
    lines.append("## Sensor health")
    lines.append("")
    if not health["captured"]:
        lines.append(
            "_loaded_scripts.log and stats.log were not captured "
            "(sensor may not be running or the harvest missed the file). "
            "UNDETECTED verdicts below should be read cautiously._"
        )
    else:
        drops = health["total_packets_dropped"]
        if health["loaded_scripts_captured"]:
            lines.append(
                f"- Zeek scripts loaded: {health['loaded_scripts_count']}"
            )
        else:
            lines.append(
                "- Zeek scripts loaded: n/a "
                "(loaded_scripts.log not captured -- likely rotated after "
                "Zeek startup; script count still available from the first "
                "run's ledger if one exists)"
            )
        if drops > 0:
            lines.append(
                f"- **Packets dropped during run: {drops}** "
                f"(across {health['drop_samples']} stats-log samples) "
                "-- UNDETECTED verdicts below carry an asterisk."
            )
        else:
            lines.append("- Packets dropped during run: 0")
    lines.append("")

    if ledger.narrative.available:
        lines.append("## Executive summary")
        lines.append("")
        lines.append(ledger.narrative.exec_summary)
        lines.append("")

    # Per-attack table
    lines.append("## Attacks")
    lines.append("")
    lines.append("| # | Attack | MITRE | Verdict | Duration (s) | Fired SIDs |")
    lines.append("|---|---|---|---|---|---|")
    for i, entry in enumerate(ledger.attacks, start=1):
        duration = int(entry.run.probe_end_ts - entry.run.probe_start_ts)
        sids = [
            str(a.get("sid")) for a in entry.attributed_alerts
            if a.get("sid") is not None
        ]
        sids_str = ", ".join(sorted(set(sids))) if sids else "-"
        lines.append(
            f"| {i} | `{entry.attack.name}` | {entry.attack.mitre} "
            f"| {entry.verdict} | {duration} | {sids_str} |"
        )
    lines.append("")

    # Narrative per-attack (if available)
    if ledger.narrative.available and ledger.narrative.per_attack_commentary:
        lines.append("## Per-attack analysis")
        lines.append("")
        for entry in ledger.attacks:
            commentary = ledger.narrative.per_attack_commentary.get(
                entry.attack.name
            )
            if not commentary:
                continue
            lines.append(f"### {entry.attack.name} -- {entry.verdict}")
            lines.append("")
            lines.append(commentary)
            lines.append("")

    # Remediation suggestions
    if ledger.narrative.available and ledger.narrative.remediation_suggestions:
        lines.append("## Remediation suggestions")
        lines.append("")
        lines.append(
            "*These are LLM-generated suggestions for attacks that went "
            "UNDETECTED or produced only observed evidence. Human review "
            "required before deploying any rule.*"
        )
        lines.append("")
        for name, suggestion in ledger.narrative.remediation_suggestions.items():
            lines.append(f"### {name}")
            lines.append("")
            lines.append("```")
            lines.append(suggestion.strip())
            lines.append("```")
            lines.append("")

    # Drift commentary
    if ledger.narrative.available and ledger.narrative.drift_commentary:
        lines.append("## Ruleset drift vs prior run")
        lines.append("")
        lines.append(ledger.narrative.drift_commentary)
        lines.append("")

    if not ledger.narrative.available:
        lines.append("## Narrative")
        lines.append("")
        lines.append(
            f"_LLM narrative unavailable: "
            f"{ledger.narrative.error or '(no reason given)'}._ "
            "Raw data above remains authoritative."
        )
        lines.append("")

    return "\n".join(lines) + "\n"


def write_markdown(ledger: RunLedger, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_markdown(ledger), encoding="utf-8")


# ---------------------------------------------------------------------------
#  HTML
# ---------------------------------------------------------------------------

_HTML_CSS = """
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
       max-width: 1100px; margin: 2rem auto; padding: 0 1rem;
       color: #212529; line-height: 1.55; background: #f8f9fa; }
h1, h2, h3 { color: #1a1a2e; }
h1 { border-bottom: 3px solid #1a1a2e; padding-bottom: .3rem; }
h2 { margin-top: 2rem; border-bottom: 1px solid #dee2e6; padding-bottom: .2rem; }
.meta { color: #495057; font-size: .9rem; margin-bottom: 1rem; }
.meta code { background: #e9ecef; padding: 1px 5px; border-radius: 3px; }
.kpis { display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0; }
.kpi { background: #fff; border: 1px solid #dee2e6; border-radius: 6px;
       padding: .75rem 1rem; min-width: 140px; }
.kpi .num { font-size: 1.6rem; font-weight: bold; color: #1a1a2e; }
.kpi .label { color: #6c757d; font-size: .85rem; }
table { border-collapse: collapse; width: 100%; margin: .5rem 0; background: #fff; }
th, td { border: 1px solid #dee2e6; padding: .4rem .6rem; text-align: left; font-size: .9rem; }
th { background: #e9ecef; }
.verdict { font-weight: bold; padding: 2px 6px; border-radius: 3px;
           font-size: .8rem; white-space: nowrap; }
.v-DETECTED_EXPECTED { background: #d4edda; color: #155724; }
.v-DETECTED_PARTIAL { background: #fff3cd; color: #856404; }
.v-DETECTED_UNEXPECTED { background: #cce5ff; color: #004085; }
.v-UNDETECTED { background: #f8d7da; color: #721c24; }
.v-FAILED { background: #e2e3e5; color: #383d41; }
.narrative { background: #fff; border-left: 4px solid #1a1a2e;
             padding: .75rem 1rem; margin: 1rem 0; border-radius: 0 4px 4px 0; }
.remediation code, pre { background: #f1f3f5; padding: 8px; border-radius: 4px;
                         display: block; white-space: pre-wrap; font-size: .85rem; }
.muted { color: #6c757d; font-style: italic; }
"""


def render_html(ledger: RunLedger) -> str:
    """Build a self-contained HTML document. No external assets."""
    esc = html_mod.escape

    vc = ledger.verdict_counts()
    drift = ledger.ruleset_drift

    parts: list[str] = []
    parts.append("<!doctype html><html lang='en'><head>")
    parts.append("<meta charset='utf-8'>")
    parts.append(f"<title>Agent Orange Run {esc(ledger.run_id)}</title>")
    parts.append(f"<style>{_HTML_CSS}</style>")
    parts.append("</head><body>")

    # Header + meta
    parts.append(f"<h1>Agent Orange Run &mdash; {esc(ledger.run_id)}</h1>")
    parts.append("<div class='meta'>")
    parts.append(
        f"Victim <code>{esc(ledger.victim_ip)}</code> &middot; "
        f"Sensor <code>{esc(ledger.sensor_host)}</code> &middot; "
        f"Attacker <code>{esc(ledger.attacker_host)}</code>"
    )
    parts.append("<br>")
    parts.append(
        f"Wall clock <strong>{ledger.total_seconds()}s</strong> "
        f"({ledger.total_seconds() / 60:.1f} min) &middot; "
        f"Version <code>{esc(ledger.agent_orange_version)}</code>"
    )
    parts.append("</div>")

    # KPIs
    parts.append("<div class='kpis'>")
    parts.append(
        f"<div class='kpi'><div class='num'>{len(ledger.attacks)}</div>"
        "<div class='label'>Attacks run</div></div>"
    )
    parts.append(
        f"<div class='kpi'><div class='num'>{ledger.coverage_pct()}%</div>"
        f"<div class='label'>Coverage ({ledger.detected_count()} detected)</div></div>"
    )
    parts.append(
        f"<div class='kpi'><div class='num'>{len(ledger.ruleset_snapshot.enabled_sids)}</div>"
        "<div class='label'>Suricata SIDs enabled</div></div>"
    )
    if drift is not None:
        parts.append(
            f"<div class='kpi'><div class='num'>+{len(drift.added_sids)} / "
            f"-{len(drift.removed_sids)}</div>"
            "<div class='label'>Ruleset drift vs prior</div></div>"
        )
    parts.append("</div>")

    # Sensor health
    health = _sensor_health_summary(ledger)
    parts.append("<h2>Sensor health</h2>")
    if not health["captured"]:
        parts.append(
            "<p class='muted'>loaded_scripts.log and stats.log were not "
            "captured. UNDETECTED verdicts below should be read cautiously.</p>"
        )
    else:
        drops = health["total_packets_dropped"]
        parts.append("<ul>")
        if health["loaded_scripts_captured"]:
            parts.append(
                f"<li>Zeek scripts loaded: <strong>"
                f"{health['loaded_scripts_count']}</strong></li>"
            )
        else:
            parts.append(
                "<li>Zeek scripts loaded: <em>n/a</em> "
                "<span class='muted'>(loaded_scripts.log not captured "
                "&mdash; likely rotated after Zeek startup)</span></li>"
            )
        if drops > 0:
            parts.append(
                "<li><strong style='color:#dc3545;'>"
                f"Packets dropped during run: {drops}</strong> "
                f"(across {health['drop_samples']} stats-log samples) "
                "&mdash; UNDETECTED verdicts below carry an asterisk.</li>"
            )
        else:
            parts.append("<li>Packets dropped during run: 0</li>")
        parts.append("</ul>")

    # Executive summary
    if ledger.narrative.available:
        parts.append("<h2>Executive summary</h2>")
        parts.append(
            "<div class='narrative'>"
            f"{esc(ledger.narrative.exec_summary)}</div>"
        )

    # Attacks table
    parts.append("<h2>Attacks</h2>")
    parts.append("<table>")
    parts.append(
        "<thead><tr><th>#</th><th>Attack</th><th>MITRE</th><th>Verdict</th>"
        "<th>Duration</th><th>Fired SIDs</th></tr></thead><tbody>"
    )
    for i, entry in enumerate(ledger.attacks, start=1):
        duration = int(entry.run.probe_end_ts - entry.run.probe_start_ts)
        sids = sorted({
            str(a.get("sid")) for a in entry.attributed_alerts
            if a.get("sid") is not None
        })
        sids_str = ", ".join(sids) if sids else "&mdash;"
        parts.append(
            f"<tr><td>{i}</td>"
            f"<td><code>{esc(entry.attack.name)}</code></td>"
            f"<td>{esc(entry.attack.mitre)}</td>"
            f"<td><span class='verdict v-{esc(entry.verdict)}'>"
            f"{esc(entry.verdict)}</span></td>"
            f"<td>{duration}s</td>"
            f"<td>{sids_str}</td></tr>"
        )
    parts.append("</tbody></table>")

    # Per-attack narrative
    if ledger.narrative.available and ledger.narrative.per_attack_commentary:
        parts.append("<h2>Per-attack analysis</h2>")
        for entry in ledger.attacks:
            commentary = ledger.narrative.per_attack_commentary.get(
                entry.attack.name
            )
            if not commentary:
                continue
            parts.append(
                f"<h3><code>{esc(entry.attack.name)}</code> &mdash; "
                f"<span class='verdict v-{esc(entry.verdict)}'>"
                f"{esc(entry.verdict)}</span></h3>"
            )
            parts.append(f"<p>{esc(commentary)}</p>")

    # Remediation
    if ledger.narrative.available and ledger.narrative.remediation_suggestions:
        parts.append("<h2>Remediation suggestions</h2>")
        parts.append(
            "<p class='muted'>LLM-generated suggestions for UNDETECTED "
            "attacks. Human review required before deploying any rule.</p>"
        )
        for name, suggestion in ledger.narrative.remediation_suggestions.items():
            parts.append(f"<h3><code>{esc(name)}</code></h3>")
            parts.append(
                f"<pre class='remediation'>{esc(suggestion.strip())}</pre>"
            )

    # Drift
    if ledger.narrative.available and ledger.narrative.drift_commentary:
        parts.append("<h2>Ruleset drift</h2>")
        parts.append(
            "<div class='narrative'>"
            f"{esc(ledger.narrative.drift_commentary)}</div>"
        )

    # Unavailable narrative notice
    if not ledger.narrative.available:
        parts.append("<h2>Narrative</h2>")
        parts.append(
            "<p class='muted'>LLM narrative unavailable: "
            f"{esc(ledger.narrative.error or '(no reason given)')}. "
            "Raw data above remains authoritative.</p>"
        )

    parts.append("</body></html>")
    return "\n".join(parts)


def write_html(ledger: RunLedger, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_html(ledger), encoding="utf-8")


# ---------------------------------------------------------------------------
#  Stdout summary
# ---------------------------------------------------------------------------

def render_stdout_summary(ledger: RunLedger) -> str:
    """One-screen text summary for operators tailing the terminal."""
    lines: list[str] = []
    bar = "=" * 72
    lines.append(bar)
    lines.append(f"agent-orange run: {ledger.run_id}")
    lines.append(bar)
    lines.append(
        f"wall clock : {ledger.total_seconds()}s "
        f"({ledger.total_seconds() / 60:.1f} min)"
    )
    lines.append(f"attacks    : {len(ledger.attacks)}")
    lines.append(
        f"coverage   : {ledger.coverage_pct()}% "
        f"({ledger.detected_count()} detected)"
    )
    vc = ledger.verdict_counts()
    lines.append("verdicts   : " + ", ".join(
        f"{k}={v}" for k, v in sorted(vc.items())
    ))
    lines.append(
        f"ruleset    : {len(ledger.ruleset_snapshot.enabled_sids)} SIDs enabled"
    )
    if ledger.ruleset_drift is not None:
        lines.append(
            f"drift      : +{len(ledger.ruleset_drift.added_sids)} / "
            f"-{len(ledger.ruleset_drift.removed_sids)} vs prior run"
        )
    lines.append("")
    fmt = "{:<3} {:<34} {:<22} {:>7} {}"
    lines.append(fmt.format("#", "attack", "verdict", "dur(s)", "sids"))
    lines.append("-" * 72)
    for i, entry in enumerate(ledger.attacks, start=1):
        duration = int(entry.run.probe_end_ts - entry.run.probe_start_ts)
        sids = sorted({
            str(a.get("sid")) for a in entry.attributed_alerts
            if a.get("sid") is not None
        })
        sids_str = ",".join(sids) if sids else "-"
        lines.append(fmt.format(
            i,
            entry.attack.name[:33],
            entry.verdict[:21],
            duration,
            sids_str[:20],
        ))
    return "\n".join(lines)
