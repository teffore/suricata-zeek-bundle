"""Unit tests for agent_orange_pkg.ruleset.

Covers SID parsing, snapshot hashing, drift computation, and the
snapshot_ruleset public API with a fake ssh_runner.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from agent_orange_pkg.ruleset import (
    RulesetDrift, RulesetError, RulesetSnapshot,
    build_snapshot_command,
    compute_drift, compute_hash,
    parse_sids, snapshot_ruleset,
)


# ---------------------------------------------------------------------------
#  parse_sids
# ---------------------------------------------------------------------------

class TestParseSids:
    def test_direct_integer_lines(self):
        raw = "1\n2\n3\n42\n"
        assert parse_sids(raw) == frozenset({1, 2, 3, 42})

    def test_freeform_rule_text(self):
        raw = (
            'alert tcp any any -> any any (msg:"test"; sid:2001219; rev:1;)\n'
            'alert tcp any any -> any any (msg:"x"; sid:2031502;)\n'
        )
        assert parse_sids(raw) == frozenset({2001219, 2031502})

    def test_duplicates_deduped(self):
        raw = "1\n1\n1\n2\n"
        assert parse_sids(raw) == frozenset({1, 2})

    def test_blank_lines_ignored(self):
        raw = "1\n\n2\n\n\n3\n"
        assert parse_sids(raw) == frozenset({1, 2, 3})

    def test_non_numeric_tokens_skipped(self):
        raw = "abc\n1\nxyz\n2\n"
        assert parse_sids(raw) == frozenset({1, 2})

    def test_empty_input(self):
        assert parse_sids("") == frozenset()

    def test_whitespace_around_integer(self):
        raw = "  1  \n  2  \n"
        assert parse_sids(raw) == frozenset({1, 2})


# ---------------------------------------------------------------------------
#  compute_hash
# ---------------------------------------------------------------------------

class TestComputeHash:
    def test_same_sids_same_hash(self):
        a = compute_hash(frozenset({1, 2, 3}))
        b = compute_hash(frozenset({3, 2, 1}))  # order-independent
        assert a == b

    def test_different_sids_different_hash(self):
        assert compute_hash(frozenset({1, 2, 3})) != compute_hash(frozenset({1, 2, 4}))

    def test_empty_has_stable_hash(self):
        # sha256 of empty-joined-string
        assert compute_hash(frozenset()) == \
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_hash_is_hex_string(self):
        h = compute_hash(frozenset({1, 2, 3}))
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)


# ---------------------------------------------------------------------------
#  compute_drift
# ---------------------------------------------------------------------------

def _snap(sids: set[int]) -> RulesetSnapshot:
    s = frozenset(sids)
    return RulesetSnapshot(enabled_sids=s, hash=compute_hash(s), captured_at=0.0)


class TestComputeDrift:
    def test_no_prior_returns_none(self):
        assert compute_drift(_snap({1, 2}), None) is None

    def test_identical_snapshots_empty_drift(self):
        drift = compute_drift(_snap({1, 2, 3}), _snap({1, 2, 3}))
        assert drift is not None
        assert drift.added_sids == frozenset()
        assert drift.removed_sids == frozenset()
        assert drift.hash_changed is False

    def test_added_only(self):
        drift = compute_drift(_snap({1, 2, 3, 4}), _snap({1, 2, 3}))
        assert drift.added_sids == frozenset({4})
        assert drift.removed_sids == frozenset()
        assert drift.hash_changed is True

    def test_removed_only(self):
        drift = compute_drift(_snap({1, 2}), _snap({1, 2, 3}))
        assert drift.removed_sids == frozenset({3})
        assert drift.added_sids == frozenset()
        assert drift.hash_changed is True

    def test_added_and_removed(self):
        drift = compute_drift(_snap({1, 2, 4}), _snap({1, 2, 3}))
        assert drift.added_sids == frozenset({4})
        assert drift.removed_sids == frozenset({3})
        assert drift.hash_changed is True


# ---------------------------------------------------------------------------
#  build_snapshot_command
# ---------------------------------------------------------------------------

class TestBuildSnapshotCommand:
    def test_includes_rules_glob(self):
        cmd = build_snapshot_command()
        assert "/etc/suricata/rules/*.rules" in cmd

    def test_filters_comment_lines(self):
        cmd = build_snapshot_command()
        # Must drop comment lines so commented-out rules don't leak.
        assert "grep -v '^\\s*#'" in cmd or "grep -v" in cmd

    def test_sorts_unique(self):
        cmd = build_snapshot_command()
        assert "sort -un" in cmd


# ---------------------------------------------------------------------------
#  snapshot_ruleset (fake ssh_runner)
# ---------------------------------------------------------------------------

def _fake_runner(stdout: str = "", stderr: str = "", rc: int = 0):
    def runner(cmd: str) -> tuple[str, str, int]:
        return stdout, stderr, rc
    return runner


class TestSnapshotRuleset:
    def test_happy_path(self):
        runner = _fake_runner(stdout="2001219\n2031502\n9000003\n")
        snap = snapshot_ruleset(runner)
        assert snap.enabled_sids == frozenset({2001219, 2031502, 9000003})
        assert len(snap.hash) == 64

    def test_empty_ruleset_is_not_an_error(self):
        runner = _fake_runner(stdout="")
        snap = snapshot_ruleset(runner)
        assert snap.enabled_sids == frozenset()
        assert snap.hash == compute_hash(frozenset())

    def test_nonzero_rc_raises(self):
        runner = _fake_runner(stderr="permission denied", rc=1)
        with pytest.raises(RulesetError, match="ruleset snapshot SSH failed"):
            snapshot_ruleset(runner)

    def test_captured_at_is_recent(self):
        runner = _fake_runner(stdout="1\n")
        snap = snapshot_ruleset(runner)
        now = datetime.now(timezone.utc).timestamp()
        assert abs(now - snap.captured_at) < 5  # within 5 seconds
