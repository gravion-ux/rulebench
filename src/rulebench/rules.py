"""Sigma rule loading and the rule model."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

__all__ = [
    "Rule",
    "RuleError",
    "RuleParseError",
    "VALID_LEVELS",
    "load_rule",
    "load_rules",
    "load_rules_with_errors",
]

#: The five severity levels the specification defines.
VALID_LEVELS = ("informational", "low", "medium", "high", "critical")


class RuleParseError(ValueError):
    """Raised when a rule file cannot be parsed into a rule."""


@dataclass(frozen=True)
class Rule:
    """A parsed Sigma rule."""

    id: str
    title: str
    description: str
    status: str
    level: str
    logsource: Mapping[str, str]
    detection: Mapping[str, Any]
    condition: str | list[str] | None
    tags: tuple[str, ...]
    fields: tuple[str, ...]
    falsepositives: tuple[str, ...]
    path: Path
    name: str
    raw: Mapping[str, Any] = field(default_factory=dict)

    @property
    def selections(self) -> dict[str, Any]:
        """Return the detection selections, without the condition.

        :returns: A mapping of search identifier name to selection.
        """
        return {name: value for name, value in self.detection.items() if name != "condition"}

    @property
    def identifier(self) -> str:
        """Return the best identifier for referring to this rule.

        :returns: The rule id when present, otherwise the file stem.
        """
        return self.id or self.name


def _as_tuple(value: Any) -> tuple[str, ...]:
    """Coerce a YAML value into a tuple of strings.

    :param value: The raw value.
    :returns: The tuple of strings.
    """
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value)
    return (str(value),)


def load_rule(path: str | Path) -> Rule:
    """Load a single Sigma rule from a YAML file.

    :param path: Path to the rule file.
    :returns: The parsed rule.
    :raises RuleParseError: When the file is missing, is not valid YAML, is not
        a mapping, or lacks a title or a detection block.
    """
    target = Path(path)
    try:
        raw_text = target.read_text(encoding="utf-8")
    except OSError as error:
        raise RuleParseError(f"could not read rule {target}: {error}") from error
    try:
        document = yaml.safe_load(raw_text)
    except yaml.YAMLError as error:
        raise RuleParseError(f"rule {target} is not valid YAML: {error}") from error
    if not isinstance(document, Mapping):
        raise RuleParseError(f"rule {target} must contain a YAML mapping")
    if "title" not in document:
        raise RuleParseError(f"rule {target} has no title")
    if "detection" not in document:
        raise RuleParseError(f"rule {target} has no detection block")
    detection = document["detection"]
    if not isinstance(detection, Mapping):
        raise RuleParseError(f"rule {target} has a detection block that is not a mapping")

    logsource = document.get("logsource")
    if logsource is None:
        logsource_mapping: Mapping[str, str] = {}
    elif isinstance(logsource, Mapping):
        logsource_mapping = {str(key): str(value) for key, value in logsource.items()}
    else:
        raise RuleParseError(f"rule {target} has a logsource that is not a mapping")

    condition = detection.get("condition")
    if condition is not None and not isinstance(condition, (str, list)):
        raise RuleParseError(f"rule {target} has a condition that is neither a string nor a list")

    return Rule(
        id=str(document.get("id", "")),
        title=str(document["title"]),
        description=str(document.get("description", "")),
        status=str(document.get("status", "")),
        level=str(document.get("level", "")),
        logsource=logsource_mapping,
        detection=dict(detection),
        condition=condition,
        tags=_as_tuple(document.get("tags")),
        fields=_as_tuple(document.get("fields")),
        falsepositives=_as_tuple(document.get("falsepositives")),
        path=target,
        name=target.stem,
        raw=dict(document),
    )


@dataclass(frozen=True)
class RuleError:
    """A rule file that could not be parsed."""

    path: Path
    message: str

    def __str__(self) -> str:
        return self.message


def load_rules_with_errors(directory: str | Path) -> tuple[list[Rule], list[RuleError]]:
    """Load every rule in a directory, collecting parse failures.

    :param directory: Directory holding ``.yml`` and ``.yaml`` rule files.
    :returns: The rules that loaded and the errors for the ones that did not.
    """
    root = Path(directory)
    rules: list[Rule] = []
    errors: list[RuleError] = []
    if not root.is_dir():
        raise RuleParseError(f"rules directory not found: {root}")
    for candidate in sorted(root.rglob("*")):
        if candidate.suffix.lower() not in {".yml", ".yaml"}:
            continue
        try:
            rules.append(load_rule(candidate))
        except RuleParseError as error:
            errors.append(RuleError(path=candidate, message=str(error)))
    return rules, errors


def load_rules(directory: str | Path) -> list[Rule]:
    """Load every rule in a directory, raising on the first broken rule.

    :param directory: Directory holding ``.yml`` and ``.yaml`` rule files.
    :returns: The parsed rules.
    :raises RuleParseError: When the directory is missing or a rule is broken.
    """
    rules, errors = load_rules_with_errors(directory)
    if errors:
        raise RuleParseError(errors[0].message)
    return rules
