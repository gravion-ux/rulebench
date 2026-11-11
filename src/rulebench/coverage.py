"""ATT&CK coverage analysis derived from rule tags."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from rulebench.rules import Rule

__all__ = ["coverage_report", "extract_techniques", "load_techniques"]

#: The shape of a technique identifier, for example ``t1059`` or ``t1059.001``.
TECHNIQUE_PATTERN = re.compile(r"^t\d{4}(?:\.\d{3})?$", re.IGNORECASE)


def extract_techniques(tags: Iterable[str]) -> set[str]:
    """Extract ATT&CK technique identifiers from rule tags.

    A tag of ``attack.t1059`` yields ``T1059``; a tag of ``attack.t1059.001``
    yields both ``T1059`` and ``T1059.001``. Tags that name a tactic rather
    than a technique, such as ``attack.execution``, are ignored.

    :param tags: The rule tags.
    :returns: The technique identifiers, upper-cased.
    """
    techniques: set[str] = set()
    for tag in tags:
        parts = str(tag).split(".")
        if len(parts) < 2 or parts[0].lower() != "attack":
            continue
        if not TECHNIQUE_PATTERN.match(parts[1]):
            continue
        technique = parts[1].upper()
        techniques.add(technique)
        if len(parts) >= 3 and parts[2]:
            sub_technique = f"{technique}.{parts[2].upper()}"
            if TECHNIQUE_PATTERN.match(sub_technique):
                techniques.add(sub_technique)
    return techniques


def load_techniques(path: str | Path) -> set[str]:
    """Load the expected technique list from a JSON file.

    Accepted shapes are a list of identifiers, an object with a ``techniques``
    key holding such a list, and a list of objects carrying an ``id``,
    ``technique`` or ``external_id`` key.

    :param path: Path to the technique list.
    :returns: The technique identifiers.
    :raises ValueError: When the file is missing, malformed or has an
        unsupported shape.
    """
    target = Path(path)
    try:
        raw = target.read_text(encoding="utf-8")
    except OSError as error:
        raise ValueError(f"could not read technique list {target}: {error}") from error
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ValueError(f"technique list {target} is not valid JSON: {error}") from error

    if isinstance(document, dict):
        document = document.get("techniques")
    if not isinstance(document, list):
        raise ValueError(f"technique list {target} must contain a list of techniques")

    techniques: set[str] = set()
    for item in document:
        if isinstance(item, str):
            techniques.add(item.upper())
        elif isinstance(item, dict):
            for key in ("id", "technique", "external_id"):
                if key in item and isinstance(item[key], str):
                    techniques.add(item[key].upper())
                    break
    return techniques


def coverage_report(rules: Sequence[Rule], techniques: Iterable[str]) -> dict[str, Any]:
    """Build an ATT&CK coverage report for a collection of rules.

    :param rules: The rules to analyse.
    :param techniques: The technique identifiers that should be covered.
    :returns: The coverage report.
    """
    expected = {str(technique).upper() for technique in techniques}
    covered: set[str] = set()
    by_technique: dict[str, list[str]] = {}

    for rule in rules:
        for technique in extract_techniques(rule.tags):
            covered.add(technique)
            by_technique.setdefault(technique, []).append(rule.identifier)

    matched = expected & covered
    ratio = (len(matched) / len(expected)) if expected else 0.0
    return {
        "expected": sorted(expected),
        "covered": sorted(matched),
        "missing": sorted(expected - covered),
        "extra": sorted(covered - expected),
        "coverageRatio": round(ratio, 4),
        "rules": {technique: sorted(by_technique[technique]) for technique in sorted(by_technique)},
    }
