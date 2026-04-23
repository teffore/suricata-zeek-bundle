"""Unit tests for agent_orange_pkg.catalog.

Pure fixture-driven tests -- no network, no lab, no real attacks.yaml
dependency. Also round-trips the real attacks.yaml at the bottom to
catch schema drift between the loader and the data.

Run:
    cd agent-orange && pytest tests/test_catalog.py -q
"""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from agent_orange_pkg.catalog import (
    Attack, CatalogError, Target,
    DEFAULT_TIMEOUT_SECONDS,
    load_attacks_yaml,
)


MINIMAL = dedent(
    """\
    attacks:
      - name: art-sample
        mitre: T1046
        source: atomic-red-team
        art_test: "T1046 (test)"
        rationale: "one-line"
        target:
          type: victim
          value: "{{VICTIM_IP}}"
        expected_sids: [2001219]
        expected_zeek_notices: []
        expected_verdict: DETECTED_EXPECTED
        command: |
          echo hi
    """
)


def _write(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "attacks.yaml"
    p.write_text(content, encoding="utf-8")
    return p


class TestHappyPath:
    def test_minimal_loads(self, tmp_path: Path):
        path = _write(tmp_path, MINIMAL)
        attacks = load_attacks_yaml(path)
        assert len(attacks) == 1
        a = attacks[0]
        assert isinstance(a, Attack)
        assert a.name == "art-sample"
        assert a.mitre == "T1046"
        assert a.source == "atomic-red-team"
        assert a.target == Target(type="victim", value="{{VICTIM_IP}}")
        assert a.expected_sids == (2001219,)
        assert a.expected_zeek_notices == ()
        assert a.expected_verdict == "DETECTED_EXPECTED"
        assert a.timeout == DEFAULT_TIMEOUT_SECONDS

    def test_timeout_override(self, tmp_path: Path):
        content = MINIMAL + "    timeout: 15\n"
        # The above appends `    timeout: 15` under the single attack;
        # verify the last attack reflects it.
        path = _write(tmp_path, content)
        attacks = load_attacks_yaml(path)
        assert attacks[0].timeout == 15

    def test_sni_target_type(self, tmp_path: Path):
        content = MINIMAL.replace(
            'type: victim\n      value: "{{VICTIM_IP}}"',
            'type: sni\n      value: "trycloudflare.com"',
        )
        attacks = load_attacks_yaml(_write(tmp_path, content))
        assert attacks[0].target == Target(type="sni", value="trycloudflare.com")

    def test_expected_verdict_undetected(self, tmp_path: Path):
        # UNDETECTED requires empty expected lists per the cross-validator.
        content = MINIMAL.replace(
            "expected_verdict: DETECTED_EXPECTED",
            "expected_verdict: UNDETECTED",
        ).replace(
            "expected_sids: [2001219]", "expected_sids: []"
        )
        attacks = load_attacks_yaml(_write(tmp_path, content))
        assert attacks[0].expected_verdict == "UNDETECTED"
        assert attacks[0].expected_sids == ()

    def test_multiple_attacks_preserved_in_order(self, tmp_path: Path):
        block_template = dedent(
            """\
              - name: {name}
                mitre: T1046
                source: atomic-red-team
                art_test: "T (x)"
                rationale: "r"
                target:
                  type: victim
                  value: "v"
                expected_sids: []
                expected_zeek_notices: []
                expected_verdict: UNDETECTED
                command: |
                  echo {name}
            """
        )
        body = "attacks:\n" + "".join(
            block_template.format(name=f"art-{i}") for i in range(3)
        )
        attacks = load_attacks_yaml(_write(tmp_path, body))
        assert [a.name for a in attacks] == ["art-0", "art-1", "art-2"]


class TestRejection:
    def test_missing_file(self, tmp_path: Path):
        with pytest.raises(CatalogError, match="not found"):
            load_attacks_yaml(tmp_path / "nope.yaml")

    def test_not_a_mapping(self, tmp_path: Path):
        with pytest.raises(CatalogError, match="top-level `attacks:`"):
            load_attacks_yaml(_write(tmp_path, "just a string\n"))

    def test_attacks_not_a_list(self, tmp_path: Path):
        with pytest.raises(CatalogError, match="must be a list"):
            load_attacks_yaml(_write(tmp_path, "attacks: not-a-list\n"))

    def test_missing_required_field(self, tmp_path: Path):
        bad = MINIMAL.replace("    mitre: T1046\n", "")
        with pytest.raises(CatalogError, match="missing required fields"):
            load_attacks_yaml(_write(tmp_path, bad))

    def test_bad_source_value(self, tmp_path: Path):
        bad = MINIMAL.replace("source: atomic-red-team", "source: hand-rolled")
        with pytest.raises(CatalogError, match="source must be"):
            load_attacks_yaml(_write(tmp_path, bad))

    def test_bad_target_type(self, tmp_path: Path):
        bad = MINIMAL.replace("type: victim", "type: laboratory")
        with pytest.raises(CatalogError, match="target.type must be"):
            load_attacks_yaml(_write(tmp_path, bad))

    def test_bad_expected_verdict(self, tmp_path: Path):
        bad = MINIMAL.replace(
            "expected_verdict: DETECTED_EXPECTED",
            "expected_verdict: DETECTED_PARTIAL",  # not valid as expectation
        )
        with pytest.raises(CatalogError, match="expected_verdict must be"):
            load_attacks_yaml(_write(tmp_path, bad))

    def test_expected_sids_not_a_list(self, tmp_path: Path):
        bad = MINIMAL.replace("expected_sids: [2001219]", "expected_sids: 2001219")
        with pytest.raises(CatalogError, match="expected_sids must be a list"):
            load_attacks_yaml(_write(tmp_path, bad))

    def test_expected_sids_contains_non_int(self, tmp_path: Path):
        bad = MINIMAL.replace("expected_sids: [2001219]", 'expected_sids: ["2001219"]')
        with pytest.raises(CatalogError, match=r"expected_sids\[0\] must be an int"):
            load_attacks_yaml(_write(tmp_path, bad))

    def test_negative_timeout_rejected(self, tmp_path: Path):
        bad = MINIMAL + "    timeout: -5\n"
        with pytest.raises(CatalogError, match="timeout must be a positive int"):
            load_attacks_yaml(_write(tmp_path, bad))

    def test_unknown_attack_field_rejected(self, tmp_path: Path):
        # A typo like `expected_sid:` (singular) next to the real field should
        # raise, not silently drop the value.
        bad = MINIMAL.replace(
            "    expected_sids: [2001219]\n",
            "    expected_sids: [2001219]\n    expected_sid: 9999\n",
        )
        with pytest.raises(CatalogError, match="unknown fields"):
            load_attacks_yaml(_write(tmp_path, bad))

    def test_unknown_target_field_rejected(self, tmp_path: Path):
        bad = MINIMAL.replace(
            "      value: \"{{VICTIM_IP}}\"\n",
            "      value: \"{{VICTIM_IP}}\"\n      typo_field: true\n",
        )
        with pytest.raises(CatalogError, match="target has unknown fields"):
            load_attacks_yaml(_write(tmp_path, bad))

    def test_detected_expected_with_empty_lists_rejected(self, tmp_path: Path):
        # Cross-validation: can't declare DETECTED_EXPECTED with empty
        # expected lists -- the classifier can't possibly return
        # DETECTED_EXPECTED under that combination.
        bad = MINIMAL.replace(
            "expected_sids: [2001219]", "expected_sids: []"
        )
        with pytest.raises(
            CatalogError, match="DETECTED_EXPECTED requires at least one"
        ):
            load_attacks_yaml(_write(tmp_path, bad))

    def test_undetected_with_nonempty_lists_rejected(self, tmp_path: Path):
        bad = MINIMAL.replace(
            "expected_verdict: DETECTED_EXPECTED", "expected_verdict: UNDETECTED"
        )
        with pytest.raises(
            CatalogError, match="UNDETECTED is inconsistent with non-empty"
        ):
            load_attacks_yaml(_write(tmp_path, bad))

    def test_duplicate_names(self, tmp_path: Path):
        # Second list item must sit at col 2 (same as first `- name:` under
        # `attacks:`), with fields at col 4. Do not use dedent() here -- the
        # literal indentation is load-bearing.
        dup = MINIMAL + (
            '  - name: art-sample\n'
            '    mitre: T1046\n'
            '    source: atomic-red-team\n'
            '    art_test: "T (x)"\n'
            '    rationale: "r"\n'
            '    target:\n'
            '      type: victim\n'
            '      value: "v"\n'
            '    expected_sids: []\n'
            '    expected_zeek_notices: []\n'
            '    expected_verdict: UNDETECTED\n'
            '    command: "echo hi"\n'
        )
        with pytest.raises(CatalogError, match="duplicate attack name"):
            load_attacks_yaml(_write(tmp_path, dup))


class TestRealAttacksYaml:
    """Sanity: the checked-in agent-orange/attacks.yaml must load cleanly."""

    def test_real_file_parses(self):
        # Repo structure: agent-orange/attacks.yaml relative to this test file
        # at agent-orange/tests/test_catalog.py -> ../attacks.yaml
        real = Path(__file__).resolve().parent.parent / "attacks.yaml"
        assert real.exists(), f"expected {real} to exist"
        attacks = load_attacks_yaml(real)
        # Sanity: at least the initial port count
        assert len(attacks) >= 23
        # All atomic-red-team sourced
        assert all(a.source == "atomic-red-team" for a in attacks)
        # All names unique
        assert len({a.name for a in attacks}) == len(attacks)
        # All have a MITRE technique
        assert all(a.mitre.startswith("T") for a in attacks)

    def test_real_file_verdict_consistency(self):
        # Every attack's expected_verdict must be internally consistent
        # with its expected signal lists. The cross-validator in catalog.py
        # enforces this at load time, so if this test ever fails it means
        # either the validator regressed or attacks.yaml was edited by
        # hand without running it through the loader first.
        real = Path(__file__).resolve().parent.parent / "attacks.yaml"
        attacks = load_attacks_yaml(real)
        for a in attacks:
            total_expected = len(a.expected_sids) + len(a.expected_zeek_notices)
            if a.expected_verdict == "DETECTED_EXPECTED":
                assert total_expected > 0, (
                    f"{a.name}: DETECTED_EXPECTED with no expected signals"
                )
            if a.expected_verdict == "UNDETECTED":
                assert total_expected == 0, (
                    f"{a.name}: UNDETECTED with non-empty expected lists "
                    f"({len(a.expected_sids)} SIDs, "
                    f"{len(a.expected_zeek_notices)} notices)"
                )
