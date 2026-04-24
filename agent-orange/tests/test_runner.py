"""Unit tests for agent_orange_pkg.runner.

Covers {{VICTIM_IP}} substitution, timeout + failure classification,
and sequential execution. ssh_runner is a fake callable so no network
touch.
"""

from __future__ import annotations

import pytest

from agent_orange_pkg.catalog import Attack, Target
from agent_orange_pkg.runner import (
    AttackResult, AttackRun,
    FAILURE_MARKERS,
    RUN_STATUS_FAILED, RUN_STATUS_RAN,
    detect_failure_marker,
    resolve_attack,
    run_attack, run_attacks,
    substitute_command, substitute_target,
)


# ---------------------------------------------------------------------------
#  Substitution
# ---------------------------------------------------------------------------

class TestSubstituteCommand:
    def test_single_replacement(self):
        assert substitute_command("curl http://{{VICTIM_IP}}/", "10.0.0.5") == \
            "curl http://10.0.0.5/"

    def test_multiple_replacements(self):
        cmd = "masscan {{VICTIM_IP}} -p 80; echo {{VICTIM_IP}}"
        assert substitute_command(cmd, "10.0.0.5") == \
            "masscan 10.0.0.5 -p 80; echo 10.0.0.5"

    def test_no_placeholder(self):
        assert substitute_command("curl -A 'rclone/v1' https://s3...", "10.0.0.5") == \
            "curl -A 'rclone/v1' https://s3..."


class TestSubstituteTarget:
    def test_victim_target_substituted(self):
        t = Target(type="victim", value="{{VICTIM_IP}}")
        out = substitute_target(t, "172.31.76.116")
        assert out == Target(type="victim", value="172.31.76.116")

    def test_sni_target_unchanged(self):
        t = Target(type="sni", value="trycloudflare.com")
        assert substitute_target(t, "10.0.0.5") == t

    def test_external_with_placeholder_substituted(self):
        # Edge case: external target containing the placeholder.
        t = Target(type="external", value="{{VICTIM_IP}}.example.com")
        assert substitute_target(t, "10.0.0.5").value == "10.0.0.5.example.com"


class TestResolveAttack:
    def _attack(self, **overrides) -> Attack:
        defaults = dict(
            name="art-x", mitre="T1046", source="atomic-red-team",
            art_test="T1046", rationale="r",
            target=Target(type="victim", value="{{VICTIM_IP}}"),
            expected_sids=(),
            expected_zeek_notices=(),
            expected_verdict="UNDETECTED",
            command="curl http://{{VICTIM_IP}}/",
        )
        defaults.update(overrides)
        return Attack(**defaults)

    def test_both_target_and_command_substituted(self):
        a = self._attack()
        resolved = resolve_attack(a, "10.0.0.5")
        assert resolved.command == "curl http://10.0.0.5/"
        assert resolved.target == Target(type="victim", value="10.0.0.5")

    def test_original_attack_unchanged(self):
        a = self._attack()
        resolve_attack(a, "10.0.0.5")
        # Frozen dataclass; resolve returns a new one, original immutable.
        assert a.target.value == "{{VICTIM_IP}}"
        assert "{{VICTIM_IP}}" in a.command


# ---------------------------------------------------------------------------
#  run_attack status classification
# ---------------------------------------------------------------------------

def _attack(**overrides) -> Attack:
    defaults = dict(
        name="art-x", mitre="T1046", source="atomic-red-team",
        art_test="T1046", rationale="r",
        target=Target(type="victim", value="{{VICTIM_IP}}"),
        expected_sids=(),
        expected_zeek_notices=(),
        expected_verdict="UNDETECTED",
        command="true",
        timeout=10,
    )
    defaults.update(overrides)
    return Attack(**defaults)


class TestRunAttack:
    def test_exit_zero_returns_ran(self):
        def fake(cmd: str, timeout: int) -> AttackResult:
            return AttackResult(stdout="ok", stderr="", exit_code=0)
        run = run_attack(_attack(), "10.0.0.5", fake)
        assert run.status == RUN_STATUS_RAN
        assert run.exit_code == 0
        assert run.error == ""
        assert run.timed_out is False
        assert run.substituted_command == "true"

    def test_timeout_returns_failed(self):
        def fake(cmd: str, timeout: int) -> AttackResult:
            return AttackResult(
                stdout="", stderr="", exit_code=124,
                timed_out=True,
            )
        run = run_attack(_attack(timeout=5), "10.0.0.5", fake)
        assert run.status == RUN_STATUS_FAILED
        assert run.timed_out is True
        assert "timed out after 5s" in run.error

    def test_ssh_error_returns_failed(self):
        def fake(cmd: str, timeout: int) -> AttackResult:
            return AttackResult(
                stdout="", stderr="ssh: connect to host: timed out",
                exit_code=255, ssh_error="connect to host: timed out",
            )
        run = run_attack(_attack(), "10.0.0.5", fake)
        assert run.status == RUN_STATUS_FAILED
        assert "ssh transport error" in run.error
        # exit_code preserved even when ssh_error is set -- operators
        # debugging intermittent auth failures want the 255 too.
        assert run.exit_code == 255

    def test_nonzero_exit_returns_failed(self):
        def fake(cmd: str, timeout: int) -> AttackResult:
            return AttackResult(stdout="", stderr="tool-missing", exit_code=127)
        run = run_attack(_attack(), "10.0.0.5", fake)
        assert run.status == RUN_STATUS_FAILED
        assert "non-zero exit: 127" in run.error

    def test_records_substituted_command_and_target(self):
        def fake(cmd: str, timeout: int) -> AttackResult:
            return AttackResult(stdout="", stderr="", exit_code=0)
        attack = _attack(
            command="curl http://{{VICTIM_IP}}:8081/",
            target=Target(type="victim", value="{{VICTIM_IP}}"),
        )
        run = run_attack(attack, "172.31.76.116", fake)
        assert run.substituted_command == "curl http://172.31.76.116:8081/"
        assert run.target == Target(type="victim", value="172.31.76.116")

    def test_start_ts_is_before_end_ts(self):
        def fake(cmd: str, timeout: int) -> AttackResult:
            return AttackResult(stdout="", stderr="", exit_code=0)
        run = run_attack(_attack(), "10.0.0.5", fake)
        assert run.probe_start_ts <= run.probe_end_ts

    def test_passes_timeout_to_runner(self):
        # Runner must receive the attack's timeout value.
        captured = {}

        def fake(cmd: str, timeout: int) -> AttackResult:
            captured["timeout"] = timeout
            return AttackResult(stdout="", stderr="", exit_code=0)

        run_attack(_attack(timeout=42), "10.0.0.5", fake)
        assert captured["timeout"] == 42


# ---------------------------------------------------------------------------
#  Failure-marker detection (Fix 1: silent-failure classification)
# ---------------------------------------------------------------------------

class TestDetectFailureMarker:
    """A command can exit 0 (because of `|| true` in the shell wrapper)
    yet still have silently failed — e.g., gobuster exits 0 after emitting
    'no such file or directory' for a missing wordlist, producing no real
    network traffic. detect_failure_marker scans stdout+stderr for known
    shell-level failure strings so the runner can override RAN to FAILED.
    """

    def test_no_markers_returns_none(self):
        assert detect_failure_marker("ok", "") is None

    def test_empty_inputs_returns_none(self):
        assert detect_failure_marker("", "") is None

    def test_no_such_file_in_stdout_detected(self):
        out = 'stat /usr/share/wordlists/dirb/common.txt: no such file or directory'
        assert detect_failure_marker(out, "") == "no such file or directory"

    def test_no_such_file_capitalized_detected(self):
        # Some tools print with capital N.
        out = 'ffuf: No such file or directory'
        assert detect_failure_marker(out, "") == "No such file or directory"

    def test_could_not_resolve_host_detected(self):
        out = 'curl: (6) Could not resolve host: devtunnels.ms'
        assert detect_failure_marker(out, "") == "Could not resolve host"

    def test_command_not_found_detected(self):
        err = 'bash: dnscat: command not found'
        assert detect_failure_marker("", err) == "command not found"

    def test_dnscat_not_allowed_detected(self):
        # dnscat2 exits 0 after printing this CLI-validation error.
        out = "It looks like you used --dns and also passed a domain on the commandline.\nThat's not allowed!"
        assert detect_failure_marker(out, "") == "That's not allowed!"

    def test_ffuf_encountered_errors_detected(self):
        out = 'Encountered error(s): 1 errors occurred.'
        assert detect_failure_marker(out, "") == "Encountered error(s)"

    def test_name_or_service_not_known_detected(self):
        err = 'ssh: Could not resolve hostname foo: Name or service not known'
        # First match wins -- "Could not resolve" appears earlier in the tuple.
        assert detect_failure_marker("", err) in FAILURE_MARKERS

    def test_marker_in_stderr_detected(self):
        assert detect_failure_marker("", "no such file or directory") is not None

    def test_marker_with_surrounding_context_detected(self):
        out = 'prefix noise\n' + 'middle: no such file or directory' + '\nsuffix'
        assert detect_failure_marker(out, "") == "no such file or directory"


class TestRunAttackFailureMarkers:
    """run_attack must downgrade exit-code-0 results to FAILED when the
    output contains a known failure marker. Preserves exit_code for ops
    visibility."""

    def test_exit_zero_with_wordlist_missing_marks_failed(self):
        def fake(cmd, timeout):
            return AttackResult(
                stdout='stat /usr/share/wordlists/dirb/common.txt: no such file or directory\n',
                stderr="", exit_code=0,
            )
        run = run_attack(_attack(), "10.0.0.5", fake)
        assert run.status == RUN_STATUS_FAILED
        assert "failure marker" in run.error
        assert "no such file or directory" in run.error
        # exit_code is preserved (0) so operators can see shell swallowed it
        assert run.exit_code == 0

    def test_exit_zero_with_dns_failure_marks_failed(self):
        def fake(cmd, timeout):
            return AttackResult(
                stdout='curl: (6) Could not resolve host: foo.example\n',
                stderr="", exit_code=0,
            )
        run = run_attack(_attack(), "10.0.0.5", fake)
        assert run.status == RUN_STATUS_FAILED
        assert "Could not resolve host" in run.error

    def test_exit_zero_with_dnscat_cli_error_marks_failed(self):
        def fake(cmd, timeout):
            return AttackResult(
                stdout="That's not allowed!\n",
                stderr="", exit_code=0,
            )
        run = run_attack(_attack(), "10.0.0.5", fake)
        assert run.status == RUN_STATUS_FAILED
        assert "That's not allowed!" in run.error

    def test_clean_output_still_ran(self):
        # Regression guard: clean output with exit=0 still classifies RAN.
        def fake(cmd, timeout):
            return AttackResult(stdout='whatever cleanup complete', stderr="", exit_code=0)
        run = run_attack(_attack(), "10.0.0.5", fake)
        assert run.status == RUN_STATUS_RAN
        assert run.error == ""

    def test_marker_in_stderr_marks_failed(self):
        # stderr is scanned too, not just stdout.
        def fake(cmd, timeout):
            return AttackResult(
                stdout="", stderr='tool: command not found\n', exit_code=0,
            )
        run = run_attack(_attack(), "10.0.0.5", fake)
        assert run.status == RUN_STATUS_FAILED
        assert "command not found" in run.error

    def test_ssh_error_takes_precedence_over_marker(self):
        # If SSH itself failed, that's the primary error, not the marker.
        def fake(cmd, timeout):
            return AttackResult(
                stdout='no such file or directory',
                stderr="ssh: connect timeout",
                exit_code=255, ssh_error="connect timeout",
            )
        run = run_attack(_attack(), "10.0.0.5", fake)
        assert run.status == RUN_STATUS_FAILED
        # ssh_error wins the error message; don't clobber with marker text.
        assert "ssh transport error" in run.error
        assert "no such file" not in run.error

    def test_nonzero_exit_takes_precedence_over_marker(self):
        # Non-zero exit is a stronger signal and should be reported verbatim.
        def fake(cmd, timeout):
            return AttackResult(
                stdout='no such file or directory', stderr="", exit_code=127,
            )
        run = run_attack(_attack(), "10.0.0.5", fake)
        assert run.status == RUN_STATUS_FAILED
        assert "non-zero exit: 127" in run.error
        # Don't also stamp the marker -- keeps error messages clean.
        assert "failure marker" not in run.error


# ---------------------------------------------------------------------------
#  run_attacks sequential semantics
# ---------------------------------------------------------------------------

class TestRunAttacks:
    def test_returns_one_run_per_input(self):
        def fake(cmd: str, timeout: int) -> AttackResult:
            return AttackResult(stdout="", stderr="", exit_code=0)
        attacks = [_attack(name=f"art-{i}") for i in range(3)]
        runs = run_attacks(attacks, "10.0.0.5", fake)
        assert [r.attack_name for r in runs] == ["art-0", "art-1", "art-2"]

    def test_failure_does_not_halt_run(self):
        calls = {"n": 0}

        def fake(cmd: str, timeout: int) -> AttackResult:
            calls["n"] += 1
            # First call fails, subsequent succeed.
            if calls["n"] == 1:
                return AttackResult(stdout="", stderr="", exit_code=127)
            return AttackResult(stdout="", stderr="", exit_code=0)

        attacks = [_attack(name=f"art-{i}") for i in range(3)]
        runs = run_attacks(attacks, "10.0.0.5", fake)
        assert runs[0].status == RUN_STATUS_FAILED
        assert runs[1].status == RUN_STATUS_RAN
        assert runs[2].status == RUN_STATUS_RAN

    def test_windows_are_non_overlapping(self):
        # Sequential semantics: each probe_start_ts >= previous probe_end_ts.
        def fake(cmd: str, timeout: int) -> AttackResult:
            return AttackResult(stdout="", stderr="", exit_code=0)
        attacks = [_attack(name=f"art-{i}") for i in range(4)]
        runs = run_attacks(attacks, "10.0.0.5", fake)
        for prev, cur in zip(runs, runs[1:]):
            assert cur.probe_start_ts >= prev.probe_end_ts
