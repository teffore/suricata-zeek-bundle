"""Unit tests for agent_orange_pkg.narrative.

claude-agent-sdk is NOT imported here; a fake invoker callable is
injected directly into generate_narrative so tests don't spawn a
`claude` subprocess or need a subscription.
"""

from __future__ import annotations

import json

from agent_orange_pkg.narrative import (
    EVIDENCE_CAP_PER_ATTACK, SYSTEM_PROMPT,
    _build_user_message, _compact_entry,
    _require_dict_str, _require_str,
    generate_narrative,
)
from tests._ledger_fixtures import (
    make_attack, make_entry, make_ledger, make_narrative,
)


# ---------------------------------------------------------------------------
#  _compact_entry
# ---------------------------------------------------------------------------

class TestCompactEntry:
    def test_includes_core_fields(self):
        entry = make_entry(make_attack("a"), verdict="UNDETECTED")
        out = _compact_entry(entry)
        assert out["name"] == "a"
        assert out["verdict"] == "UNDETECTED"
        assert out["status"] == "RAN"
        assert out["duration_s"] == 10.0  # 110 - 100
        assert out["target"] == {"type": "victim", "value": "172.31.76.116"}

    def test_alert_sample_capped(self):
        alerts = [{"sid": i} for i in range(20)]
        entry = make_entry(make_attack("a"), alerts=alerts)
        out = _compact_entry(entry)
        assert len(out["attributed_alerts_sample"]) == EVIDENCE_CAP_PER_ATTACK
        assert out["attributed_alerts_total"] == 20

    def test_drops_non_whitelisted_alert_fields(self):
        alerts = [{"sid": 1, "signature": "x", "secret": "no"}]
        entry = make_entry(make_attack("a"), alerts=alerts)
        out = _compact_entry(entry)
        assert "secret" not in out["attributed_alerts_sample"][0]
        assert out["attributed_alerts_sample"][0]["signature"] == "x"


# ---------------------------------------------------------------------------
#  _build_user_message
# ---------------------------------------------------------------------------

class TestBuildUserMessage:
    def test_no_prior_omits_prior_run(self):
        msg = _build_user_message(make_ledger(), prior_ledger=None)
        data = json.loads(msg)
        assert "prior_run" not in data

    def test_with_prior_includes_attack_verdicts(self):
        prior = make_ledger(
            run_id="20260422T000000Z",
            entries=[
                make_entry(make_attack("a"), verdict="DETECTED_EXPECTED"),
                make_entry(make_attack("b"), verdict="UNDETECTED"),
            ],
        )
        msg = _build_user_message(make_ledger(), prior_ledger=prior)
        data = json.loads(msg)
        assert data["prior_run"]["run_id"] == "20260422T000000Z"
        assert data["prior_run"]["attack_verdicts"]["a"] == "DETECTED_EXPECTED"

    def test_verdict_counts_present(self):
        msg = _build_user_message(make_ledger(), prior_ledger=None)
        data = json.loads(msg)
        assert "verdict_counts" in data


# ---------------------------------------------------------------------------
#  _require_* helpers
# ---------------------------------------------------------------------------

class TestRequireHelpers:
    def test_require_str_happy(self):
        assert _require_str({"x": "y"}, "x") == "y"

    def test_require_str_missing_returns_empty(self):
        assert _require_str({}, "x") == ""

    def test_require_str_non_string_returns_empty(self):
        assert _require_str({"x": 42}, "x") == ""

    def test_require_dict_str_happy(self):
        assert _require_dict_str({"x": {"a": "b"}}, "x") == {"a": "b"}

    def test_require_dict_str_coerces_values(self):
        assert _require_dict_str({"x": {"a": 1}}, "x") == {"a": "1"}

    def test_require_dict_str_wrong_type_returns_empty(self):
        assert _require_dict_str({"x": "not a dict"}, "x") == {}


# ---------------------------------------------------------------------------
#  generate_narrative (fake invoker)
# ---------------------------------------------------------------------------

def _canned_json_invoker(
    exec_summary: str = "summary text",
    per_attack: dict[str, str] | None = None,
    remediation: dict[str, str] | None = None,
    drift: str = "drift text",
):
    """Return an invoke(system, user, model) callable that returns canned JSON.

    Also records its last invocation in `.last_call` for assertion.
    """
    payload = json.dumps({
        "exec_summary": exec_summary,
        "per_attack_commentary": per_attack or {"a": "commentary"},
        "remediation_suggestions": remediation or {"a": "rule snippet"},
        "drift_commentary": drift,
    })
    calls: list[dict] = []

    def invoker(system: str, user: str, model: str) -> str:
        calls.append({"system": system, "user": user, "model": model})
        return payload

    invoker.calls = calls  # type: ignore[attr-defined]
    return invoker


class TestGenerateNarrative:
    def test_happy_path(self):
        invoke = _canned_json_invoker("gopher")
        n = generate_narrative(make_ledger(), None, invoke=invoke)
        assert n.available is True
        assert n.exec_summary == "gopher"
        assert n.per_attack_commentary == {"a": "commentary"}
        assert n.remediation_suggestions == {"a": "rule snippet"}
        assert n.drift_commentary == "drift text"
        assert n.model  # populated from default
        assert n.generated_at > 0

    def test_passes_system_prompt(self):
        invoke = _canned_json_invoker()
        generate_narrative(make_ledger(), None, invoke=invoke)
        assert invoke.calls[0]["system"] == SYSTEM_PROMPT  # type: ignore[attr-defined]

    def test_passes_default_model(self):
        invoke = _canned_json_invoker()
        generate_narrative(make_ledger(), None, invoke=invoke)
        assert invoke.calls[0]["model"] == "claude-opus-4-7"  # type: ignore[attr-defined]

    def test_user_message_is_json(self):
        invoke = _canned_json_invoker()
        generate_narrative(make_ledger(), None, invoke=invoke)
        user_msg = invoke.calls[0]["user"]  # type: ignore[attr-defined]
        # Should be valid JSON with known top-level keys
        data = json.loads(user_msg)
        assert "run_id" in data
        assert "attacks" in data

    def test_non_json_llm_output_returns_unavailable(self):
        def invoke(system: str, user: str, model: str) -> str:
            return "this is not json"
        n = generate_narrative(make_ledger(), None, invoke=invoke)
        assert n.available is False
        assert "not valid JSON" in n.error

    def test_invoker_exception_returns_unavailable(self):
        def invoke(system: str, user: str, model: str) -> str:
            raise RuntimeError("api down")
        n = generate_narrative(make_ledger(), None, invoke=invoke)
        assert n.available is False
        assert "api down" in n.error

    def test_model_override_respected(self):
        invoke = _canned_json_invoker()
        generate_narrative(
            make_ledger(), None, invoke=invoke, model="claude-haiku-4-5",
        )
        assert invoke.calls[0]["model"] == "claude-haiku-4-5"  # type: ignore[attr-defined]
