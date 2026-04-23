"""narrative.py -- single claude-agent-sdk call for the end-of-run narrative.

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

Uses claude-agent-sdk so the call goes through the user's Claude Code
subscription (same auth path purple-agent uses). No separate Anthropic
API key required.

The actual LLM invocation is abstracted behind a callable so tests can
inject canned responses without spawning a subprocess.
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from typing import Any, Callable

from agent_orange_pkg.ledger import AttackLedgerEntry, Narrative, RunLedger


# Default can be overridden with `AGENT_ORANGE_MODEL` for ops who want to
# pin to a specific version or experiment with haiku for cheaper runs.
DEFAULT_MODEL = os.environ.get("AGENT_ORANGE_MODEL", "claude-opus-4-7")
# Cap evidence passed to the LLM per attack so very noisy probes don't
# blow the context window. Full evidence stays in the ledger; LLM just
# gets a representative slice.
EVIDENCE_CAP_PER_ATTACK = 8


# An InvokeLLM is (system_prompt, user_message, model) -> response_text.
# Production uses _real_invoke_llm via claude-agent-sdk. Tests pass a
# fake function that returns canned text -- no subprocess, no SDK.
InvokeLLM = Callable[[str, str, str], str]


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


# ---------------------------------------------------------------------------
#  Public API
# ---------------------------------------------------------------------------

def generate_narrative(
    ledger: RunLedger,
    prior_ledger: RunLedger | None,
    *,
    invoke: InvokeLLM | None = None,
    model: str = DEFAULT_MODEL,
) -> Narrative:
    """Produce a Narrative for the given ledger.

    By default calls claude-agent-sdk (uses the user's Claude Code
    subscription auth -- no ANTHROPIC_API_KEY needed). Pass `invoke`
    for tests or to swap in a different provider.

    Any exception during the LLM call or any non-JSON response produces
    an unavailable Narrative with a descriptive error. The pipeline
    continues either way.
    """
    try:
        user_message = _build_user_message(ledger, prior_ledger)
    except Exception as exc:
        return _unavailable(f"LLM input build failed: {exc}")

    invoker = invoke or _real_invoke_llm

    try:
        text = invoker(SYSTEM_PROMPT, user_message, model)
    except Exception as exc:
        return _unavailable(f"LLM call failed: {exc}")

    json_blob = _extract_json_object(text)
    if not json_blob:
        return _unavailable(
            f"LLM output had no JSON object; first 200 chars: {text[:200]!r}"
        )
    try:
        data = json.loads(json_blob)
    except json.JSONDecodeError as exc:
        return _unavailable(
            f"LLM output was not valid JSON: {exc}; first 200 chars: "
            f"{json_blob[:200]!r}"
        )

    exec_summary = _require_str(data, "exec_summary")
    if not exec_summary.strip():
        # The helpers silently coerce wrong-typed fields to "". A completely
        # empty exec_summary means the model returned nothing useful -- fall
        # back to unavailable rather than rendering a successful-looking
        # narrative with no content.
        return _unavailable(
            "LLM returned JSON with empty/malformed exec_summary"
        )

    return Narrative(
        available=True,
        exec_summary=exec_summary,
        per_attack_commentary=_require_dict_str(data, "per_attack_commentary"),
        remediation_suggestions=_require_dict_str(data, "remediation_suggestions"),
        drift_commentary=_require_str(data, "drift_commentary"),
        generated_at=datetime.now(timezone.utc).timestamp(),
        model=model,
        error="",
    )


def _extract_json_object(text: str) -> str:
    """Return the first balanced `{...}` block in text, or empty string.

    Claude occasionally prefixes its output with prose ("Here is the
    analysis:\\n\\n{...}") despite instructions. Trying json.loads on the
    raw text fails in those cases, so we scan for the first balanced
    object and hand only that to the parser. Brace-counting (not regex)
    because JSON can nest.
    """
    start = text.find("{")
    if start < 0:
        return ""
    depth = 0
    in_str = False
    escape = False
    for i in range(start, len(text)):
        c = text[i]
        if escape:
            escape = False
            continue
        if c == "\\" and in_str:
            escape = True
            continue
        if c == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return ""


# ---------------------------------------------------------------------------
#  claude-agent-sdk bridge (production invoker)
# ---------------------------------------------------------------------------

def _real_invoke_llm(system_prompt: str, user_message: str, model: str) -> str:
    """Call claude-agent-sdk.query() synchronously, return concatenated text.

    Wraps the async iterator from `query()` with asyncio.run so callers
    can stay sync. claude-agent-sdk invokes the local `claude` CLI,
    which authenticates via the user's Claude Code subscription.
    """
    return asyncio.run(_query_and_collect(system_prompt, user_message, model))


async def _query_and_collect(
    system_prompt: str, user_message: str, model: str,
) -> str:  # pragma: no cover -- requires live claude CLI
    # Imports inside the function so test environments without the SDK
    # still pass -- the default path is only reached when no invoker
    # was injected.
    from claude_agent_sdk import (
        AssistantMessage, ClaudeAgentOptions, TextBlock, query,
    )

    options = ClaudeAgentOptions(
        system_prompt=system_prompt,
        model=model,
        # One-shot completion: we only need the LLM's reply, not tool
        # execution. Leaving allowed_tools empty + max_turns=1 ensures
        # the CLI doesn't start an agent loop.
        max_turns=1,
    )

    parts: list[str] = []
    async for message in query(prompt=user_message, options=options):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    parts.append(block.text)
    return "".join(parts)


# ---------------------------------------------------------------------------
#  Pure helpers (testable without claude-agent-sdk)
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
    payload: dict[str, Any] = {
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
        "attacks": [_compact_entry(e) for e in ledger.attacks],
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
