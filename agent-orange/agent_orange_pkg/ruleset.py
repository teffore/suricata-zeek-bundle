"""ruleset.py -- Suricata enabled-SID snapshot + drift comparison.

At run start, Agent Orange captures the set of enabled Suricata SIDs
on the sensor. The snapshot lets the end-of-run narrative layer
distinguish between:

    "same probe, different verdict" = a real variance story
    "SID was removed from ET Open between runs" = external feed churn

Without this, ET rule churn (SIDs renamed/retired daily by upstream)
looks identical to real detection changes and the user can't tell
which is which.

Snapshot is computed by grepping /etc/suricata/rules/*.rules for the
`sid:<N>;` pattern. Simple, doesn't require a running Suricata, works
even if the service is mid-restart.

Drift is a pure set operation over two snapshots. ssh_runner is the
same injectable callable pattern used in harvest.py.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable


# Same runner protocol as harvest.py — (command) -> (stdout, stderr, rc).
SshRunner = Callable[[str], tuple[str, str, int]]

# Suricata 8 via `suricata-update` on Ubuntu places rules under
# /var/lib/suricata/rules/, NOT /etc/suricata/rules/. The directory is
# typically group-readable by `suricata` only, so the glob must expand
# inside sudo (see build_snapshot_command).
SURICATA_RULES_GLOB = "/var/lib/suricata/rules/*.rules"
SID_PATTERN = re.compile(r"\bsid\s*:\s*(\d+)\s*;", re.IGNORECASE)


class RulesetError(RuntimeError):
    """Raised when the snapshot SSH call fails."""


# ---------------------------------------------------------------------------
#  Types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RulesetSnapshot:
    """One Suricata ruleset snapshot at a point in time."""
    enabled_sids: frozenset[int]
    hash: str                # sha256 of sorted SID list, stable across runs
    captured_at: float       # epoch seconds


@dataclass(frozen=True)
class RulesetDrift:
    """Delta between two RulesetSnapshots.

    added_sids    -- SIDs present in current, absent from prior
    removed_sids  -- SIDs absent from current, present in prior
    hash_changed  -- convenience flag; true iff either set is non-empty
    """
    added_sids: frozenset[int]
    removed_sids: frozenset[int]
    hash_changed: bool


# ---------------------------------------------------------------------------
#  Command builder
# ---------------------------------------------------------------------------

def build_snapshot_command() -> str:
    r"""Emit enabled SIDs to stdout, one per line.

    Pipeline:
      1. ``sudo sh -c 'cat /var/lib/suricata/rules/*.rules'`` -- glob
         expansion runs inside the sudo'd shell because the rules
         directory is typically group-readable by ``suricata`` only;
         the ubuntu caller can't list it, so an outside-sudo glob
         expands to nothing.
      2. Drop comment lines.
      3. Extract sid values. Uses POSIX ``[[:space:]]`` because ``\s``
         is a Perl regex extension that isn't reliably supported by
         ``grep -E`` across distros.
      4. ``sort -un`` for determinism.
    """
    return (
        f"sudo sh -c 'cat {SURICATA_RULES_GLOB} 2>/dev/null' "
        r"| grep -v '^[[:space:]]*#' "
        r"| grep -oE 'sid[[:space:]]*:[[:space:]]*[0-9]+' "
        r"| grep -oE '[0-9]+' "
        "| sort -un"
    )


# ---------------------------------------------------------------------------
#  Pure parsing
# ---------------------------------------------------------------------------

def parse_sids(raw: str) -> frozenset[int]:
    """Parse the stdout of build_snapshot_command() into a frozenset.

    Also accepts freeform input (e.g., raw rule text) via SID_PATTERN for
    flexibility; unit tests exercise both. Non-integer tokens are skipped.
    """
    sids: set[int] = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        # Direct integer per line (build_snapshot_command output).
        if line.isdigit():
            try:
                sids.add(int(line))
                continue
            except ValueError:
                pass
        # Freeform fallback: extract any sid:N tokens present.
        for match in SID_PATTERN.finditer(line):
            try:
                sids.add(int(match.group(1)))
            except ValueError:
                continue
    return frozenset(sids)


def compute_hash(sids: frozenset[int]) -> str:
    """SHA-256 over sorted SID list for a stable, human-comparable hash."""
    blob = ",".join(str(s) for s in sorted(sids)).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def compute_drift(
    current: RulesetSnapshot,
    prior: RulesetSnapshot | None,
) -> RulesetDrift | None:
    """Return drift between prior and current; None if no prior exists."""
    if prior is None:
        return None
    added = frozenset(current.enabled_sids - prior.enabled_sids)
    removed = frozenset(prior.enabled_sids - current.enabled_sids)
    return RulesetDrift(
        added_sids=added,
        removed_sids=removed,
        hash_changed=(current.hash != prior.hash),
    )


# ---------------------------------------------------------------------------
#  Public API
# ---------------------------------------------------------------------------

def snapshot_ruleset(ssh_runner: SshRunner) -> RulesetSnapshot:
    """Capture the sensor's current enabled-SID set via one SSH call.

    Raises RulesetError if the SSH layer fails (non-zero rc). An empty
    ruleset -- zero SIDs -- is valid output (nothing enabled) and doesn't
    raise, though it probably indicates a misconfigured sensor worth
    flagging in the report.
    """
    cmd = build_snapshot_command()
    stdout, stderr, rc = ssh_runner(cmd)
    if rc != 0:
        raise RulesetError(
            f"ruleset snapshot SSH failed (rc={rc}): "
            f"{stderr.strip() or '<no stderr>'}"
        )
    sids = parse_sids(stdout)
    return RulesetSnapshot(
        enabled_sids=sids,
        hash=compute_hash(sids),
        captured_at=datetime.now(timezone.utc).timestamp(),
    )
