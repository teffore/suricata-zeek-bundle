"""runner.py -- sequential attack runner over SSH.

The deterministic heart of Agent Orange. Takes a list of Attack +
SSH params; for each attack: substitute `{{VICTIM_IP}}` placeholders,
record probe_start_ts, SSH to the attacker and run the command, record
probe_end_ts, classify status as RAN or FAILED. No sensor queries
during the run -- those happen once at the end via harvest.py.

SSH I/O is abstracted via an AttackerRunner callable so tests can
inject canned results without hitting a real attacker.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Callable

from agent_orange_pkg.catalog import Attack, Target

VICTIM_IP_PLACEHOLDER = "{{VICTIM_IP}}"

RUN_STATUS_RAN = "RAN"
RUN_STATUS_FAILED = "FAILED"


# ---------------------------------------------------------------------------
#  Types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AttackResult:
    """Output of one SSH-based attack command.

    The runner converts this to an AttackRun by tagging it with the
    matching Attack + timestamps + status classification.
    """
    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool = False
    ssh_error: str = ""  # populated when SSH layer itself failed


# AttackerRunner signature: takes the substituted attacker-side command +
# a timeout in seconds. Returns an AttackResult. Callers handle SSH
# transport; this module stays transport-agnostic.
AttackerRunner = Callable[[str, int], AttackResult]


@dataclass(frozen=True)
class AttackRun:
    """The canonical ledger entry for one executed attack."""
    attack_name: str
    mitre: str
    art_test: str
    target: Target                  # post-substitution
    substituted_command: str
    probe_start_ts: float           # epoch seconds, local clock
    probe_end_ts: float             # epoch seconds, local clock
    status: str                     # RUN_STATUS_RAN | RUN_STATUS_FAILED
    exit_code: int | None
    stdout: str
    stderr: str
    error: str                      # non-empty when FAILED
    timed_out: bool


# ---------------------------------------------------------------------------
#  Substitution helpers
# ---------------------------------------------------------------------------

def substitute_command(command: str, victim_ip: str) -> str:
    """Replace every {{VICTIM_IP}} in the attack command."""
    return command.replace(VICTIM_IP_PLACEHOLDER, victim_ip)


def substitute_target(target: Target, victim_ip: str) -> Target:
    """Return a Target with any {{VICTIM_IP}} in target.value replaced.

    Only meaningful when target.type == 'victim' but applied generically
    to keep the contract simple -- SNI and external targets never contain
    the placeholder in practice.
    """
    if VICTIM_IP_PLACEHOLDER not in target.value:
        return target
    return Target(
        type=target.type,
        value=target.value.replace(VICTIM_IP_PLACEHOLDER, victim_ip),
    )


def resolve_attack(attack: Attack, victim_ip: str) -> Attack:
    """Return a fresh Attack with {{VICTIM_IP}} substitutions applied.

    Safe to pass the resolved Attack to attribution.filter_events without
    further processing.
    """
    return replace(
        attack,
        command=substitute_command(attack.command, victim_ip),
        target=substitute_target(attack.target, victim_ip),
    )


# ---------------------------------------------------------------------------
#  Runner
# ---------------------------------------------------------------------------

def run_attack(
    attack: Attack,
    victim_ip: str,
    attacker_runner: AttackerRunner,
) -> AttackRun:
    """Execute one attack, return its AttackRun record.

    - Substitutes {{VICTIM_IP}} in command + target.
    - Times the SSH call with local clock; sub-second granularity.
    - Marks RAN if attacker_runner returns a result with exit_code == 0
      and no SSH error and no timeout. Any other case is FAILED with
      descriptive error text.
    """
    resolved = resolve_attack(attack, victim_ip)
    start_ts = datetime.now(timezone.utc).timestamp()
    result = attacker_runner(resolved.command, resolved.timeout)
    end_ts = datetime.now(timezone.utc).timestamp()

    if result.ssh_error:
        status = RUN_STATUS_FAILED
        error = f"ssh transport error: {result.ssh_error}"
    elif result.timed_out:
        status = RUN_STATUS_FAILED
        error = f"attack timed out after {resolved.timeout}s"
    elif result.exit_code != 0:
        # Note: many attack commands end with `|| true` to swallow expected
        # non-zero exits (e.g., scp with BatchMode=yes that fails auth on
        # purpose). Those still return exit 0. A non-zero here means the
        # wrapper itself failed, not the sub-command -- treat as FAILED.
        status = RUN_STATUS_FAILED
        error = f"non-zero exit: {result.exit_code}"
    else:
        status = RUN_STATUS_RAN
        error = ""

    return AttackRun(
        attack_name=attack.name,
        mitre=attack.mitre,
        art_test=attack.art_test,
        target=resolved.target,
        substituted_command=resolved.command,
        probe_start_ts=start_ts,
        probe_end_ts=end_ts,
        status=status,
        # Preserve raw exit_code even when ssh_error is set; operators
        # debugging intermittent auth failures want the 255 alongside the
        # transport-error message, not None.
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
        error=error,
        timed_out=result.timed_out,
    )


def run_attacks(
    attacks: list[Attack],
    victim_ip: str,
    attacker_runner: AttackerRunner,
) -> list[AttackRun]:
    """Run attacks strictly sequentially. Returns one AttackRun per input.

    Sequential is non-negotiable for this pipeline: attribution windows
    are per-attack and overlap-free only if one attack finishes before
    the next starts. A FAILED attack does NOT halt the pipeline;
    subsequent attacks still execute.
    """
    return [run_attack(a, victim_ip, attacker_runner) for a in attacks]
