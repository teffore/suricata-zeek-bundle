"""Unit tests for agent_orange_pkg.narrative.

Anthropic SDK is NOT imported here; a fake client is injected.
"""

from __future__ import annotations

import json

from agent_orange_pkg.narrative import (
    EVIDENCE_CAP_PER_ATTACK,
    _build_user_message, _compact_entry,
    _extract_text, _require_dict_str, _require_str,
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
#  _extract_text
# ---------------------------------------------------------------------------

class FakeBlock:
    def __init__(self, text: str):
        self.text = text


class FakeResponse:
    def __init__(self, content: list):
        self.content = content


class TestExtractText:
    def test_object_style_blocks(self):
        r = FakeResponse([FakeBlock("hello "), FakeBlock("world")])
        assert _extract_text(r) == "hello world"

    def test_dict_style_blocks(self):
        r = {"content": [{"text": "hi"}, {"text": " there"}]}
        assert _extract_text(r) == "hi there"

    def test_missing_content_returns_empty(self):
        assert _extract_text({}) == ""
        assert _extract_text(FakeResponse([])) == ""

    def test_non_text_block_ignored(self):
        r = FakeResponse([FakeBlock("keep"), {"type": "image"}])
        assert _extract_text(r) == "keep"


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
#  generate_narrative (fake client)
# ---------------------------------------------------------------------------

class FakeMessages:
    def __init__(self, response):
        self._response = response
        self.last_call: dict = {}

    def create(self, **kwargs):
        self.last_call = kwargs
        return self._response


class FakeClient:
    def __init__(self, response):
        self.messages = FakeMessages(response)


class TestGenerateNarrative:
    def _valid_response(self, exec_summary: str = "summary text"):
        payload = {
            "exec_summary": exec_summary,
            "per_attack_commentary": {"a": "commentary"},
            "remediation_suggestions": {"a": "rule snippet"},
            "drift_commentary": "drift text",
        }
        return FakeResponse([FakeBlock(json.dumps(payload))])

    def test_happy_path(self):
        client = FakeClient(self._valid_response("gopher"))
        n = generate_narrative(make_ledger(), None, client=client)
        assert n.available is True
        assert n.exec_summary == "gopher"
        assert n.per_attack_commentary == {"a": "commentary"}
        assert n.remediation_suggestions == {"a": "rule snippet"}
        assert n.drift_commentary == "drift text"
        assert n.model  # populated
        assert n.generated_at > 0

    def test_non_json_llm_output_returns_unavailable(self):
        client = FakeClient(FakeResponse([FakeBlock("this is not json")]))
        n = generate_narrative(make_ledger(), None, client=client)
        assert n.available is False
        assert "not valid JSON" in n.error

    def test_llm_exception_returns_unavailable(self):
        class BoomMessages:
            def create(self, **kwargs):
                raise RuntimeError("api down")
        class BoomClient:
            messages = BoomMessages()
        n = generate_narrative(make_ledger(), None, client=BoomClient())
        assert n.available is False
        assert "api down" in n.error

    def test_passes_system_prompt_with_cache_control(self):
        client = FakeClient(self._valid_response())
        generate_narrative(make_ledger(), None, client=client)
        system = client.messages.last_call["system"]
        assert isinstance(system, list)
        assert system[0]["cache_control"] == {"type": "ephemeral"}

    def test_temperature_is_zero(self):
        client = FakeClient(self._valid_response())
        generate_narrative(make_ledger(), None, client=client)
        assert client.messages.last_call["temperature"] == 0
