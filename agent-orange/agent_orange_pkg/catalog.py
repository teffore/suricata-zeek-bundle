"""catalog.py -- attacks.yaml loader + strict schema validator.

Agent Orange refuses to run an attack whose entry is missing a required
field. Better to fail at startup with a clear message than to run with a
silently-broken entry (happens all the time with purple-agent's looser
schema). Pure functions only; no filesystem or network side effects
beyond the single read of the yaml path passed in.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


VALID_TARGET_TYPES = {"victim", "sni", "external"}
VALID_EXPECTED_VERDICTS = {"DETECTED_EXPECTED", "UNDETECTED"}
REQUIRED_ATTACK_FIELDS = (
    "name", "mitre", "source", "art_test", "rationale",
    "target", "expected_sids", "expected_zeek_notices",
    "expected_verdict", "command",
)
REQUIRED_TARGET_FIELDS = ("type", "value")
DEFAULT_TIMEOUT_SECONDS = 45


class CatalogError(ValueError):
    """Raised when attacks.yaml is malformed or fails schema validation."""


@dataclass(frozen=True)
class Target:
    """Attribution anchor for an attack's evidence filtering.

    type: "victim" | "sni" | "external"
    value: victim-IP placeholder, SNI string, or external hostname/IP.
    """
    type: str
    value: str


@dataclass(frozen=True)
class Attack:
    """A single validated atomic red team attack from attacks.yaml.

    All fields are required except `timeout`, which defaults to 45s.
    Lists are tuple-ified so Attack instances are hashable and trivially
    safe to pass between threads or reuse across runs.
    """
    name: str
    mitre: str
    source: str
    art_test: str
    rationale: str
    target: Target
    expected_sids: tuple[int, ...]
    expected_zeek_notices: tuple[str, ...]
    expected_verdict: str
    command: str
    timeout: int = DEFAULT_TIMEOUT_SECONDS


def load_attacks_yaml(path: Path) -> list[Attack]:
    """Parse attacks.yaml, validate every entry, return a list of Attack.

    Raises CatalogError with a clear message on any schema violation.
    Names are verified unique. File-not-found and YAML parse errors are
    re-raised as CatalogError so callers have one exception type to
    handle.
    """
    try:
        import yaml
    except ImportError as exc:
        raise CatalogError(
            "PyYAML is required to load attacks.yaml. Install with "
            "`pip install PyYAML`."
        ) from exc

    if not path.exists():
        raise CatalogError(f"attacks.yaml not found: {path}")

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise CatalogError(f"attacks.yaml parse error: {exc}") from exc

    if not isinstance(raw, dict) or "attacks" not in raw:
        raise CatalogError(
            "attacks.yaml must be a mapping with a top-level `attacks:` key"
        )

    entries = raw["attacks"]
    if not isinstance(entries, list):
        raise CatalogError("`attacks:` must be a list of attack entries")

    attacks: list[Attack] = []
    seen_names: set[str] = set()

    for idx, entry in enumerate(entries):
        attack = _parse_entry(entry, idx)
        if attack.name in seen_names:
            raise CatalogError(
                f"duplicate attack name: {attack.name!r} (entry #{idx})"
            )
        seen_names.add(attack.name)
        attacks.append(attack)

    return attacks


def _parse_entry(entry: Any, idx: int) -> Attack:
    """Validate and convert one YAML entry into a frozen Attack dataclass."""
    if not isinstance(entry, dict):
        raise CatalogError(f"entry #{idx} must be a mapping, got {type(entry).__name__}")

    missing = [f for f in REQUIRED_ATTACK_FIELDS if f not in entry]
    if missing:
        name_hint = entry.get("name", f"<entry #{idx}>")
        raise CatalogError(
            f"attack {name_hint!r} missing required fields: {', '.join(missing)}"
        )

    name = _require_str(entry["name"], f"entry #{idx}: name")
    mitre = _require_str(entry["mitre"], f"{name}: mitre")
    source = _require_str(entry["source"], f"{name}: source")
    if source != "atomic-red-team":
        raise CatalogError(
            f"{name}: source must be 'atomic-red-team', got {source!r}"
        )
    art_test = _require_str(entry["art_test"], f"{name}: art_test")
    rationale = _require_str(entry["rationale"], f"{name}: rationale")
    command = _require_str(entry["command"], f"{name}: command")

    target = _parse_target(entry["target"], name)
    expected_sids = _parse_int_list(entry["expected_sids"], f"{name}: expected_sids")
    expected_zeek_notices = _parse_str_list(
        entry["expected_zeek_notices"], f"{name}: expected_zeek_notices"
    )

    expected_verdict = _require_str(entry["expected_verdict"], f"{name}: expected_verdict")
    if expected_verdict not in VALID_EXPECTED_VERDICTS:
        raise CatalogError(
            f"{name}: expected_verdict must be one of "
            f"{sorted(VALID_EXPECTED_VERDICTS)}, got {expected_verdict!r}"
        )

    timeout = entry.get("timeout", DEFAULT_TIMEOUT_SECONDS)
    if not isinstance(timeout, int) or timeout <= 0:
        raise CatalogError(
            f"{name}: timeout must be a positive int, got {timeout!r}"
        )

    return Attack(
        name=name,
        mitre=mitre,
        source=source,
        art_test=art_test,
        rationale=rationale,
        target=target,
        expected_sids=tuple(expected_sids),
        expected_zeek_notices=tuple(expected_zeek_notices),
        expected_verdict=expected_verdict,
        command=command,
        timeout=timeout,
    )


def _parse_target(value: Any, name: str) -> Target:
    if not isinstance(value, dict):
        raise CatalogError(f"{name}: target must be a mapping, got {type(value).__name__}")
    missing = [f for f in REQUIRED_TARGET_FIELDS if f not in value]
    if missing:
        raise CatalogError(f"{name}: target missing fields: {', '.join(missing)}")
    t_type = _require_str(value["type"], f"{name}: target.type")
    if t_type not in VALID_TARGET_TYPES:
        raise CatalogError(
            f"{name}: target.type must be one of {sorted(VALID_TARGET_TYPES)}, "
            f"got {t_type!r}"
        )
    t_value = _require_str(value["value"], f"{name}: target.value")
    return Target(type=t_type, value=t_value)


def _require_str(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CatalogError(f"{label} must be a non-empty string, got {value!r}")
    return value


def _parse_int_list(value: Any, label: str) -> list[int]:
    if not isinstance(value, list):
        raise CatalogError(f"{label} must be a list, got {type(value).__name__}")
    out: list[int] = []
    for i, item in enumerate(value):
        if not isinstance(item, int) or isinstance(item, bool):
            raise CatalogError(
                f"{label}[{i}] must be an int, got {type(item).__name__}: {item!r}"
            )
        out.append(item)
    return out


def _parse_str_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list):
        raise CatalogError(f"{label} must be a list, got {type(value).__name__}")
    out: list[str] = []
    for i, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise CatalogError(
                f"{label}[{i}] must be a non-empty string, got {item!r}"
            )
        out.append(item)
    return out
