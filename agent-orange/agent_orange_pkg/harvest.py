"""harvest.py -- batch sensor query + log parsing.

One SSH call at start-of-run captures line-count baselines for the
always-growing logs (eve.json, notice.log, weird.log, intel.log,
conn.log). One SSH call at end-of-run reads forward from those
baselines plus the current-hour protocol logs, producing a single
SensorHarvest with normalized events.

Why two calls, not per-probe: Zeek's log-batching behaviour (entries
aren't flushed until the connection closes or the bucket rotates)
means "check right after a probe" misses late-flushing events. By
waiting until the run is over, everything has settled.

Event normalization produces a dict with at least:
    { "ts": <float, epoch seconds>,
      "dest_ip": <str or None>,
      "sni": <str or None>,
      ... log-specific fields preserved ... }

downstream attribution.filter_events can then do pure set operations
on these events.

SSH I/O is abstracted via a runner callable so tests can inject fake
harvest responses without touching a real sensor.

Known constraint: Zeek rotates current/*.log hourly. An Agent Orange run
that crosses the hour boundary may read baseline line counts against a
freshly rotated file, silently losing events in the baseline-to-rotation
window. The target scope (a 23-attack ART battery) stays well inside one
hour, so this is tolerable now. A future fix can detect rotation via
stat's inode or mtime and fall back to a timestamp-filtered full read.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable


# Sensor-side log paths. These match the Suricata+Zeek install produced
# by standalone.sh; changing them requires a coordinated standalone.sh
# update.
SURICATA_EVE = "/var/log/suricata/eve.json"
ZEEK_CURRENT = "/opt/zeek/logs/current"

# Logs that grow quickly and need line-count baselines so we read
# forward instead of re-reading the whole file at harvest time.
BASELINE_LOGS: tuple[str, ...] = (
    "eve.json",
    "notice.log",
    "weird.log",
    "intel.log",
    "conn.log",
)

# Protocol logs harvested in full at end-of-run, then timestamp-filtered
# client-side. Zeek rotates these hourly so the files stay bounded.
PROTOCOL_LOGS: tuple[str, ...] = (
    "http.log",
    "ssh.log",
    "ssl.log",
    "dns.log",
    "ftp.log",
    "smtp.log",
    "files.log",
    "software.log",
    "snmp.log",
    "x509.log",
    "tunnel.log",
    "dce_rpc.log",
    "smb_mapping.log",
    "smb_files.log",
    "kerberos.log",
)

# Diagnostic logs -- read once, stored raw for the run-health section.
DIAGNOSTIC_LOGS: tuple[str, ...] = (
    "loaded_scripts.log",
    "stats.log",
)


class HarvestError(RuntimeError):
    """Raised when a harvest SSH call fails or returns unparseable data."""


# ---------------------------------------------------------------------------
#  SSH runner protocol
# ---------------------------------------------------------------------------

# A ssh_runner is a callable the orchestrator provides. It takes a single
# shell command string to execute on the sensor and returns (stdout, stderr,
# exit_code). Tests inject a fake; production wires it to subprocess.run.
SshRunner = Callable[[str], tuple[str, str, int]]


# ---------------------------------------------------------------------------
#  Data types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SensorBaseline:
    """Line counts captured at run start so harvest reads forward."""
    eve_json_lines: int
    notice_log_lines: int
    weird_log_lines: int
    intel_log_lines: int
    conn_log_lines: int
    captured_at: float  # epoch seconds

    def line_for(self, log_name: str) -> int:
        mapping = {
            "eve.json": self.eve_json_lines,
            "notice.log": self.notice_log_lines,
            "weird.log": self.weird_log_lines,
            "intel.log": self.intel_log_lines,
            "conn.log": self.conn_log_lines,
        }
        return mapping.get(log_name, 0)


@dataclass(frozen=True)
class SensorHarvest:
    """All sensor evidence for one Agent Orange run."""
    suricata_alerts: list[dict]
    zeek_notices: list[dict]
    zeek_weird: list[dict]
    zeek_intel: list[dict]
    zeek_conn: list[dict]
    # Keyed by log filename (without path): e.g. "http.log" -> [events...]
    zeek_protocol_logs: dict[str, list[dict]]
    zeek_loaded_scripts: str  # raw text, diagnostic only
    zeek_stats: str           # raw text, diagnostic only
    baseline: SensorBaseline
    harvest_at: float         # epoch seconds


# ---------------------------------------------------------------------------
#  Timestamp normalization
# ---------------------------------------------------------------------------

def parse_suricata_ts(raw: Any) -> float | None:
    """Parse Suricata eve.json ts. Returns None if unparseable."""
    if not isinstance(raw, str):
        return None
    # Suricata's format: "2026-04-23T15:43:46.123456+0000"
    # Python fromisoformat wants "+00:00" not "+0000"; normalize.
    s = raw.strip()
    if len(s) >= 5 and (s[-5] == "+" or s[-5] == "-") and s[-3] != ":":
        s = s[:-2] + ":" + s[-2:]
    try:
        return datetime.fromisoformat(s).timestamp()
    except ValueError:
        return None


def parse_zeek_ts(raw: Any) -> float | None:
    """Parse Zeek JSON ts. Zeek emits ts as a string epoch float."""
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        return float(raw)
    if isinstance(raw, str):
        try:
            return float(raw)
        except ValueError:
            return None
    return None


# ---------------------------------------------------------------------------
#  Event normalization
# ---------------------------------------------------------------------------

def _normalize_suricata_alert(raw: dict) -> dict | None:
    """Turn a raw eve.json alert line into the attribution-ready shape.

    Returns None if the event isn't an alert or lacks a ts we can parse.
    """
    if raw.get("event_type") != "alert":
        return None
    ts = parse_suricata_ts(raw.get("timestamp"))
    if ts is None:
        return None
    alert = raw.get("alert", {}) or {}
    sid = alert.get("signature_id")
    # Suricata reports sid as int already; be defensive.
    if isinstance(sid, str):
        try:
            sid = int(sid)
        except ValueError:
            sid = None

    tls = raw.get("tls", {}) or {}
    http = raw.get("http", {}) or {}
    sni = tls.get("sni") or http.get("hostname") or None

    return {
        "ts": ts,
        "dest_ip": raw.get("dest_ip"),
        "sni": sni,
        "sid": sid,
        "signature": alert.get("signature"),
        "category": alert.get("category"),
        "severity": alert.get("severity"),
        "src_ip": raw.get("src_ip"),
        "dest_port": raw.get("dest_port"),
        "proto": raw.get("proto"),
    }


def _normalize_zeek_notice(raw: dict) -> dict | None:
    ts = parse_zeek_ts(raw.get("ts"))
    if ts is None:
        return None
    return {
        "ts": ts,
        "dest_ip": raw.get("id.resp_h") or raw.get("dst"),
        "sni": raw.get("server_name"),
        "note": raw.get("note"),
        "msg": raw.get("msg"),
        "src": raw.get("id.orig_h") or raw.get("src"),
        "suppress_for": raw.get("suppress_for"),
    }


def _resolve_dest_ip(raw: dict, log_name: str) -> str | None:
    """Return the destination IP for a Zeek event, log-name aware.

    Zeek's log schemas vary: most logs use `id.resp_h`, but software.log uses
    `host`, files.log uses `rx_hosts` (a set of addrs for file receivers),
    and a few older logs use `dst`. Fall back to the common keys when no
    per-log mapping applies so we degrade gracefully on future logs.
    """
    if log_name == "software.log":
        host = raw.get("host")
        return host if isinstance(host, str) else None
    if log_name == "files.log":
        rx = raw.get("rx_hosts")
        if isinstance(rx, list) and rx and isinstance(rx[0], str):
            return rx[0]
        return None
    for key in ("id.resp_h", "dst"):
        value = raw.get(key)
        if isinstance(value, str):
            return value
    return None


def _resolve_sni(raw: dict, log_name: str) -> str | None:
    """Return the SNI (or equivalent hostname) for a Zeek event.

    Only logs that carry a meaningful hostname field contribute to SNI
    attribution: ssl.log/x509.log (`server_name`), http.log (`host`),
    dns.log (`query`). For software.log `host` is an IP, not a hostname,
    so it must NOT leak into the sni field (earlier versions did -- the
    reviewer caught this).
    """
    if log_name in ("ssl.log", "x509.log"):
        value = raw.get("server_name")
        return value if isinstance(value, str) else None
    if log_name == "http.log":
        value = raw.get("host")
        return value if isinstance(value, str) else None
    if log_name == "dns.log":
        value = raw.get("query")
        return value if isinstance(value, str) else None
    # Default: accept server_name if present, no other guesses.
    value = raw.get("server_name")
    return value if isinstance(value, str) else None


def _normalize_generic_zeek(raw: dict, log_name: str) -> dict | None:
    """Best-effort normalization for any Zeek log.

    Produces a dict with `ts` (epoch float), `dest_ip`, `sni`, a `_log`
    tag for provenance, and all original fields preserved so report
    layers can show rich log-specific context without re-reading the
    source files.

    For intel.log, synthesizes a `note` field so the verdict classifier
    treats an Intel Framework hit as a Zeek-side detection (it doesn't
    natively carry a `note` field, so without this it'd be invisible
    to coverage math).
    """
    ts = parse_zeek_ts(raw.get("ts"))
    if ts is None:
        return None
    out = dict(raw)
    out["ts"] = ts
    out["dest_ip"] = _resolve_dest_ip(raw, log_name)
    out["sni"] = _resolve_sni(raw, log_name)
    out["_log"] = log_name
    if log_name == "intel.log" and "note" not in out:
        out["note"] = _synthesize_intel_note(raw)
    return out


def _synthesize_intel_note(raw: dict) -> str:
    """Produce a classifier-friendly note string for a Zeek intel hit.

    Intel events have `matched` (list of Intel types) and
    `seen.indicator_type`. We prefer `matched[0]` because it's the
    concrete Intel type the event actually triggered on; fall back to
    `seen.indicator_type`, then a generic tag so something useful
    always makes it to the verdict layer.
    """
    matched = raw.get("matched")
    if isinstance(matched, list) and matched and isinstance(matched[0], str):
        return f"Intel::{matched[0].removeprefix('Intel::')}"
    indicator_type = raw.get("seen.indicator_type")
    if isinstance(indicator_type, str) and indicator_type:
        return f"Intel::{indicator_type.removeprefix('Intel::')}"
    return "Intel::HIT"


# ---------------------------------------------------------------------------
#  SSH command builders
# ---------------------------------------------------------------------------

def build_baseline_command() -> str:
    """Shell command that emits the five baseline line counts as JSON."""
    # Use sudo wc -l (files may be root-owned). Missing files -> 0.
    # Emit a single JSON object for easy parsing.
    parts = [
        f'EVE=$(sudo wc -l {SURICATA_EVE} 2>/dev/null | awk \'{{print $1}}\'); EVE=${{EVE:-0}}',
        f'NOTICE=$(sudo wc -l {ZEEK_CURRENT}/notice.log 2>/dev/null | awk \'{{print $1}}\'); NOTICE=${{NOTICE:-0}}',
        f'WEIRD=$(sudo wc -l {ZEEK_CURRENT}/weird.log 2>/dev/null | awk \'{{print $1}}\'); WEIRD=${{WEIRD:-0}}',
        f'INTEL=$(sudo wc -l {ZEEK_CURRENT}/intel.log 2>/dev/null | awk \'{{print $1}}\'); INTEL=${{INTEL:-0}}',
        f'CONN=$(sudo wc -l {ZEEK_CURRENT}/conn.log 2>/dev/null | awk \'{{print $1}}\'); CONN=${{CONN:-0}}',
        'printf \'{"eve":%s,"notice":%s,"weird":%s,"intel":%s,"conn":%s}\\n\' "$EVE" "$NOTICE" "$WEIRD" "$INTEL" "$CONN"',
    ]
    return "; ".join(parts)


def build_harvest_command(baseline: SensorBaseline) -> str:
    """Shell command that emits a sectioned dump of all sensor logs.

    Format: "=== SECTION_NAME ===" header, then JSONL body, repeated.
    """
    lines = []

    def section(name: str, body: str) -> None:
        lines.append(f'echo "=== {name} ==="')
        lines.append(body)

    # Baselined logs: tail forward from captured line count.
    # +1 offset so tail -n +N emits from line N onward inclusive.
    eve_start = baseline.eve_json_lines + 1
    notice_start = baseline.notice_log_lines + 1
    weird_start = baseline.weird_log_lines + 1
    intel_start = baseline.intel_log_lines + 1
    conn_start = baseline.conn_log_lines + 1

    section("EVE_ALERTS",
            f'sudo tail -n +{eve_start} {SURICATA_EVE} 2>/dev/null || true')
    section("ZEEK_NOTICE",
            f'sudo tail -n +{notice_start} {ZEEK_CURRENT}/notice.log 2>/dev/null || true')
    section("ZEEK_WEIRD",
            f'sudo tail -n +{weird_start} {ZEEK_CURRENT}/weird.log 2>/dev/null || true')
    section("ZEEK_INTEL",
            f'sudo tail -n +{intel_start} {ZEEK_CURRENT}/intel.log 2>/dev/null || true')
    section("ZEEK_CONN",
            f'sudo tail -n +{conn_start} {ZEEK_CURRENT}/conn.log 2>/dev/null || true')

    # Protocol logs: read full current file; filter client-side.
    for logname in PROTOCOL_LOGS:
        section(f"ZEEK_{logname.replace('.log','').upper()}",
                f'sudo cat {ZEEK_CURRENT}/{logname} 2>/dev/null || true')

    # Diagnostic logs: kept raw for the run-health section.
    for logname in DIAGNOSTIC_LOGS:
        section(f"ZEEK_{logname.replace('.log','').upper()}",
                f'sudo cat {ZEEK_CURRENT}/{logname} 2>/dev/null || true')

    return "\n".join(lines)


# ---------------------------------------------------------------------------
#  Sectioned output parser
# ---------------------------------------------------------------------------

def parse_sections(raw: str) -> dict[str, list[str]]:
    """Split a sectioned dump into a dict of section -> lines (str, no trailing \\n).

    Empty sections produce an empty list. Unknown sections are preserved.
    """
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in raw.splitlines():
        if line.startswith("=== ") and line.endswith(" ==="):
            current = line[4:-4].strip()
            sections.setdefault(current, [])
            continue
        if current is None:
            continue
        if line:  # drop blank lines that slipped in
            sections[current].append(line)
    return sections


def _parse_jsonl(lines: list[str]) -> list[dict]:
    out: list[dict] = []
    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


# ---------------------------------------------------------------------------
#  Public API
# ---------------------------------------------------------------------------

def capture_baseline(ssh_runner: SshRunner) -> SensorBaseline:
    """Run the baseline command on the sensor, parse the JSON result."""
    cmd = build_baseline_command()
    stdout, stderr, rc = ssh_runner(cmd)
    if rc != 0:
        raise HarvestError(
            f"baseline SSH failed (rc={rc}): {stderr.strip() or '<no stderr>'}"
        )
    try:
        obj = json.loads(stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError) as exc:
        raise HarvestError(
            f"baseline parse failed: stdout={stdout!r}"
        ) from exc
    return SensorBaseline(
        eve_json_lines=int(obj.get("eve", 0)),
        notice_log_lines=int(obj.get("notice", 0)),
        weird_log_lines=int(obj.get("weird", 0)),
        intel_log_lines=int(obj.get("intel", 0)),
        conn_log_lines=int(obj.get("conn", 0)),
        captured_at=datetime.now(timezone.utc).timestamp(),
    )


def harvest(
    ssh_runner: SshRunner,
    baseline: SensorBaseline,
    run_start_ts: float,
) -> SensorHarvest:
    """Run the harvest command on the sensor, parse + normalize all events.

    Events from protocol logs (which aren't baselined) are timestamp-filtered
    client-side against run_start_ts so historical traffic doesn't pollute
    the harvest.
    """
    cmd = build_harvest_command(baseline)
    stdout, stderr, rc = ssh_runner(cmd)
    if rc != 0:
        raise HarvestError(
            f"harvest SSH failed (rc={rc}): {stderr.strip() or '<no stderr>'}"
        )
    sections = parse_sections(stdout)

    suricata_alerts: list[dict] = []
    for raw in _parse_jsonl(sections.get("EVE_ALERTS", [])):
        ev = _normalize_suricata_alert(raw)
        if ev is not None:
            suricata_alerts.append(ev)

    zeek_notices = [
        ev for ev in (_normalize_zeek_notice(r)
                      for r in _parse_jsonl(sections.get("ZEEK_NOTICE", [])))
        if ev is not None
    ]
    zeek_weird = [
        ev for ev in (_normalize_generic_zeek(r, "weird.log")
                      for r in _parse_jsonl(sections.get("ZEEK_WEIRD", [])))
        if ev is not None
    ]
    zeek_intel = [
        ev for ev in (_normalize_generic_zeek(r, "intel.log")
                      for r in _parse_jsonl(sections.get("ZEEK_INTEL", [])))
        if ev is not None
    ]
    zeek_conn = [
        ev for ev in (_normalize_generic_zeek(r, "conn.log")
                      for r in _parse_jsonl(sections.get("ZEEK_CONN", [])))
        if ev is not None
    ]

    protocol: dict[str, list[dict]] = {}
    for logname in PROTOCOL_LOGS:
        section_name = f"ZEEK_{logname.replace('.log', '').upper()}"
        events = [
            ev for ev in (_normalize_generic_zeek(r, logname)
                          for r in _parse_jsonl(sections.get(section_name, [])))
            if ev is not None and ev["ts"] >= run_start_ts
        ]
        if events:
            protocol[logname] = events

    loaded_scripts = "\n".join(sections.get("ZEEK_LOADED_SCRIPTS", []))
    stats = "\n".join(sections.get("ZEEK_STATS", []))

    return SensorHarvest(
        suricata_alerts=suricata_alerts,
        zeek_notices=zeek_notices,
        zeek_weird=zeek_weird,
        zeek_intel=zeek_intel,
        zeek_conn=zeek_conn,
        zeek_protocol_logs=protocol,
        zeek_loaded_scripts=loaded_scripts,
        zeek_stats=stats,
        baseline=baseline,
        harvest_at=datetime.now(timezone.utc).timestamp(),
    )
