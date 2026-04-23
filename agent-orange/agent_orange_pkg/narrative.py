"""narrative.py -- single Anthropic SDK call for the end-of-run narrative.

The deterministic pipeline writes the ledger first. This module then
reads the complete ledger + the most recent prior run's ledger and
produces a Narrative with:

    - exec_summary: one paragraph covering coverage + notable wins/misses
    - per_attack_commentary: 1-3 sentences per attack explaining the
      evidence that led to the verdict
    - remediation_suggestions: for UNDETECTED attacks, a concrete
      Suricata rule or Zeek script snippet that would catch the
      activity (human review required before deploying)
    - drift_commentary: analysis of verdict flips + ruleset changes
      since the prior run

The LLM never changes verdicts. It only explains them. If the LLM call
fails for any reason, return a Narrative with available=False so the
renderer can show "narrative unavailable" and keep the raw ledger
usable. Pipeline never depends on LLM success.

Anthropic client is injected (keeps the module testable) and optional
(falls through to building one from env). Tests always inject fakes.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Protocol

from agent_orange_pkg.ledger import AttackLedgerEntry, Narrative, RunLedger


DEFAULT_MODEL = "claude-opus-4-7"
DEFAULT_MAX_TOKENS = 4096
# Cap evidence passed to the LLM per attack so very noisy probes don't
# blow the context window. The full evidence stays in the ledger; LLM
# just gets a representative slice.
EVIDENCE_CAP_PER_ATTACK = 8


class AnthropicClient(Protocol):
    """Subset of the Anthropic SDK we use.

    Defined as a Protocol so fakes can duck-type without subclassing
    the real client. Real anthropic.Anthropic() satisfies this because
    it exposes .messages.create(...).
    """
    messages: Any  # real client exposes .messages.create(...)


SYSTEM_PROMPT = """\
You are the narrative layer for Agent Orange, a deterministic purple-team
detection-testing agent. The deterministic pipeline has already classified
every attack's verdict using pure set operations against attributed
sensor evidence. Your job is ONLY to explain those verdicts in plain
English and suggest remediation for UNDETECTED attacks.

Strict rules:

1. Never contradict a verdict. If the pipeline said UNDETECTED, you say
   UNDETECTED. Your commentary explains WHY the evidence (or absence of
   evidence) produced that verdict.

2. Per-attack commentary: 1-3 short sentences. Be concrete about what
   fired and what did not. If the attack was FAILED, explain the error
   and suggest a lab-ops fix (not a detection fix).

3. Remediation suggestions: only for UNDETECTED attacks (or DETECTED
   attacks where the expected SIDs were a subset of what fired and
   there's a gap worth closing). Offer a concrete Suricata rule or
   Zeek script snippet. Mark every suggestion as "Suggested -- human
   review required". Do not suggest rules that duplicate ones already
   firing.

4. Drift commentary: a paragraph comparing against the prior run. Call
   out verdict flips (attacks that changed tier) and ruleset changes
   (SIDs added/removed). If no prior run exists, say so and note that
   this is the first run.

5. Executive summary: one paragraph. Lead with coverage % and count,
   then notable observations. No filler.

Output STRICTLY in this JSON structure -- no other keys, no prose
outside the JSON:

{
  "exec_summary": "string",
  "per_attack_commentary": {"attack_name": "string", ...},
  "remediation_suggestions": {"attack_name": "string", ...},
  "drift_commentary": "string"
}
"""


def generate_narrative(
    ledger: RunLedger,
    prior_ledger: RunLedger | None,
    *,
    client: AnthropicClient | None = None,
    model: str = DEFAULT_MODEL,
) -> Narrative:
    """Produce a Narrative for the given ledger.

    If `client` is None, try to instantiate anthropic.Anthropic() from
    the environment. If that raises, return an unavailable Narrative
    with a descriptive error -- the pipeline continues.
    """
    try:
        real_client = client or _default_client()
    except Exception as exc:  # pragma: no cover -- import/env failure
        return _unavailable(f"LLM client init failed: {exc}")

    try:
        user_message = _build_user_message(ledger, prior_ledger)
    except Exception as exc:
        return _unavailable(f"LLM input build failed: {exc}")

    try:
        response = real_client.messages.create(
            model=model,
            max_tokens=DEFAULT_MAX_TOKENS,
            temperature=0,
            system=[
                {
                    "type": "text",
                    "text": SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[{"role": "user", "content": user_message}],
        )
    except Exception as exc:
        return _unavailable(f"LLM call failed: {exc}")

    text = _extract_text(response)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return _unavailable(
            f"LLM output was not valid JSON: {exc}; first 200 chars: "
            f"{text[:200]!r}"
        )

    return Narrative(
        available=True,
        exec_summary=_require_str(data, "exec_summary"),
        per_attack_commentary=_require_dict_str(data, "per_attack_commentary"),
        remediation_suggestions=_require_dict_str(data, "remediation_suggestions"),
        drift_commentary=_require_str(data, "drift_commentary"),
        generated_at=datetime.now(timezone.utc).timestamp(),
        model=model,
        error="",
    )


# ---------------------------------------------------------------------------
#  Helpers (pure, testable)
# ---------------------------------------------------------------------------

def _unavailable(error: str) -> Narrative:
    return Narrative(
        available=False,
        exec_summary="",
        per_attack_commentary={},
        remediation_suggestions={},
        drift_commentary="",
        generated_at=0.0,
        model="",
        error=error,
    )


def _default_client():  # pragma: no cover -- requires real anthropic SDK
    import anthropic
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY environment variable not set")
    return anthropic.Anthropic(api_key=api_key)


def _extract_text(response: Any) -> str:
    """Pull text content out of an Anthropic messages.create() response.

    Handles real SDK response objects (content is a list of blocks) and
    fake dict/list responses injected by tests.
    """
    content = getattr(response, "content", None)
    if content is None and isinstance(response, dict):
        content = response.get("content")
    if content is None:
        return ""
    text_parts: list[str] = []
    for block in content:
        # Real SDK blocks have a .text attribute; dict fakes use ["text"].
        t = getattr(block, "text", None)
        if t is None and isinstance(block, dict):
            t = block.get("text")
        if isinstance(t, str):
            text_parts.append(t)
    return "".join(text_parts)


def _require_str(data: dict, key: str) -> str:
    v = data.get(key, "")
    return v if isinstance(v, str) else ""


def _require_dict_str(data: dict, key: str) -> dict[str, str]:
    v = data.get(key, {})
    if not isinstance(v, dict):
        return {}
    return {str(k): str(val) for k, val in v.items()}


def _build_user_message(
    ledger: RunLedger,
    prior_ledger: RunLedger | None,
) -> str:
    """Compose the user-message JSON the LLM sees.

    Structured as a single JSON document for parsing reliability.
    Evidence lists are capped at EVIDENCE_CAP_PER_ATTACK to keep
    token count bounded.
    """
    payload = {
        "run_id": ledger.run_id,
        "victim_ip": ledger.victim_ip,
        "wall_clock_seconds": ledger.total_seconds(),
        "total_attacks": len(ledger.attacks),
        "coverage_pct": ledger.coverage_pct(),
        "verdict_counts": ledger.verdict_counts(),
        "ruleset": {
            "enabled_sid_count": len(ledger.ruleset_snapshot.enabled_sids),
            "hash": ledger.ruleset_snapshot.hash,
        },
        "attacks": [
            _compact_entry(e) for e in ledger.attacks
        ],
    }
    if ledger.ruleset_drift is not None:
        payload["ruleset_drift"] = {
            "added_sids": sorted(ledger.ruleset_drift.added_sids),
            "removed_sids": sorted(ledger.ruleset_drift.removed_sids),
            "hash_changed": ledger.ruleset_drift.hash_changed,
        }
    if prior_ledger is not None:
        payload["prior_run"] = {
            "run_id": prior_ledger.run_id,
            "verdict_counts": prior_ledger.verdict_counts(),
            "coverage_pct": prior_ledger.coverage_pct(),
            "attack_verdicts": {
                e.attack.name: e.verdict for e in prior_ledger.attacks
            },
        }
    return json.dumps(payload, indent=2)


def _compact_entry(entry: AttackLedgerEntry) -> dict[str, Any]:
    """Trim an AttackLedgerEntry down to what the LLM needs."""
    alerts = [
        {k: v for k, v in a.items() if k in (
            "sid", "signature", "category", "severity", "dest_ip", "sni"
        )}
        for a in entry.attributed_alerts[:EVIDENCE_CAP_PER_ATTACK]
    ]
    notices = [
        {k: v for k, v in n.items() if k in ("note", "msg", "dest_ip", "sni")}
        for n in entry.attributed_notices[:EVIDENCE_CAP_PER_ATTACK]
    ]
    observed_counts = {k: len(v) for k, v in entry.observed_evidence.items()}
    return {
        "name": entry.attack.name,
        "mitre": entry.attack.mitre,
        "art_test": entry.attack.art_test,
        "rationale": entry.attack.rationale,
        "expected_sids": list(entry.attack.expected_sids),
        "expected_zeek_notices": list(entry.attack.expected_zeek_notices),
        "expected_verdict": entry.attack.expected_verdict,
        "verdict": entry.verdict,
        "status": entry.run.status,
        "duration_s": round(
            entry.run.probe_end_ts - entry.run.probe_start_ts, 2
        ),
        "error": entry.run.error,
        "target": {
            "type": entry.run.target.type,
            "value": entry.run.target.value,
        },
        "attributed_alerts_sample": alerts,
        "attributed_alerts_total": len(entry.attributed_alerts),
        "attributed_notices_sample": notices,
        "attributed_notices_total": len(entry.attributed_notices),
        "observed_evidence_counts": observed_counts,
    }
