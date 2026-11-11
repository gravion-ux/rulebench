"""Rule quality checks.

The linter reports defects that make a rule wrong or untrustworthy rather than
merely stylistically different: rules that can never fire, rules that always
fire, duplicated identifiers, and conditions that do not parse.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from rulebench.conditions import ConditionError, OneOf, parse_condition
from rulebench.modifiers import KNOWN_MODIFIERS, parse_field_spec
from rulebench.rules import Rule

__all__ = ["ERROR", "WARNING", "LintFinding", "lint_rules"]

#: Severity of a lint finding that makes the rule unusable.
ERROR = "error"

#: Severity of a lint finding that makes the rule suspicious.
WARNING = "warning"


@dataclass(frozen=True)
class LintFinding:
    """One problem found in a rule."""

    code: str
    severity: str
    message: str
    path: str
    rule: str

    def to_dict(self) -> dict[str, str]:
        """Render the finding as a plain dictionary.

        :returns: The finding as a dictionary.
        """
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "path": self.path,
            "rule": self.rule,
        }


def _values_of(value: Any) -> frozenset[str]:
    """Render a rule value as a set of comparable strings.

    :param value: The raw value.
    :returns: The value set.
    """
    if isinstance(value, (list, tuple)):
        return frozenset(str(item) for item in value)
    return frozenset({str(value)})


def _selection_fields(rule: Rule, name: str) -> dict[str, frozenset[str]]:
    """Return the field/value sets of one selection.

    :param rule: The rule to inspect.
    :param name: The selection name.
    :returns: A mapping of field specification to value set.
    """
    selection = rule.selections.get(name)
    if not isinstance(selection, Mapping):
        return {}
    return {str(field): _values_of(value) for field, value in selection.items()}


def _is_filter(name: str) -> bool:
    """Report whether a search identifier is a filter by naming convention.

    :param name: The search identifier name.
    :returns: True when the name looks like a filter.
    """
    return name.lower().startswith("filter")


def _uses_them(rule: Rule) -> bool:
    """Report whether a condition uses ``of them``.

    :param rule: The rule to inspect.
    :returns: True when the condition contains a ``them`` expression.
    """
    if rule.condition is None:
        return False
    try:
        nodes = parse_condition(rule.condition)
    except ConditionError:
        return False
    return _contains_them(nodes)


def _contains_them(nodes: tuple[Any, ...]) -> bool:
    """Walk an expression tree looking for a ``them`` expression.

    :param nodes: The expression trees.
    :returns: True when one of them uses ``them``.
    """
    for node in nodes:
        if isinstance(node, OneOf):
            if node.pattern == "them":
                return True
        elif hasattr(node, "operands"):
            if _contains_them(node.operands):
                return True
        elif hasattr(node, "operand") and _contains_them((node.operand,)):
            return True
    return False


def _signature(rule: Rule) -> dict[str, frozenset[str]]:
    """Build the constraint signature of a rule.

    Only selections are used; filters narrow a rule rather than broaden it, so
    including them would invert the shadowing comparison.

    :param rule: The rule to inspect.
    :returns: A mapping of field specification to value set.
    """
    signature: dict[str, frozenset[str]] = {}
    for name in rule.selections:
        if _is_filter(name):
            continue
        for field, values in _selection_fields(rule, name).items():
            existing = signature.get(field)
            signature[field] = values if existing is None else existing & values
    return signature


def _contradictions(rule: Rule) -> list[str]:
    """Find filters that contradict the selections they are meant to refine.

    :param rule: The rule to inspect.
    :returns: A message per contradictory filter.
    """
    messages: list[str] = []
    filters = [name for name in rule.selections if _is_filter(name)]
    selections = [name for name in rule.selections if not _is_filter(name)]
    for filter_name in filters:
        filter_fields = _selection_fields(rule, filter_name)
        for selection_name in selections:
            selection_fields = _selection_fields(rule, selection_name)
            for field, filter_values in filter_fields.items():
                if field not in selection_fields:
                    continue
                selection_values = selection_fields[field]
                overlap = filter_values & selection_values
                if not overlap:
                    messages.append(
                        f"filter {filter_name!r} can never exclude anything matched by "
                        f"{selection_name!r}: {field} values are disjoint"
                    )
                elif filter_values <= selection_values:
                    messages.append(
                        f"filter {filter_name!r} excludes every event matched by "
                        f"{selection_name!r}: {field} is fully covered"
                    )
    return messages


def _modifier_problems(rule: Rule) -> list[str]:
    """Find modifiers that rulebench cannot evaluate faithfully.

    :param rule: The rule to inspect.
    :returns: A message per unsupported modifier.
    """
    problems: list[str] = []
    for name, selection in rule.selections.items():
        if not isinstance(selection, Mapping):
            continue
        for field in selection:
            try:
                spec = parse_field_spec(str(field))
            except ValueError as error:
                problems.append(f"selection {name!r} has an invalid field specification: {error}")
                continue
            for modifier in spec.modifiers:
                if modifier not in KNOWN_MODIFIERS:
                    problems.append(f"selection {name!r} uses unknown modifier {modifier!r}")
                elif modifier == "expand":
                    problems.append(
                        f"selection {name!r} uses the 'expand' modifier, which requires placeholder "
                        "expansion; rulebench rejects the rule"
                    )
    return problems


def _is_shadowed(narrow: Mapping[str, frozenset[str]], broad: Mapping[str, frozenset[str]]) -> bool:
    """Report whether a narrow rule can never fire on its own.

    A rule is shadowed when every constraint it has is also held, or loosened,
    by another rule, and it is strictly more constrained somewhere.

    :param narrow: The constraint signature of the narrower rule.
    :param broad: The constraint signature of the broader rule.
    :returns: True when the narrow rule is shadowed.
    """
    if not narrow or not broad:
        return False
    shared = set(narrow) & set(broad)
    if not shared:
        return False
    for field in shared:
        if not broad[field] >= narrow[field]:
            return False
    if set(narrow) - set(broad):
        return True
    return any(narrow[field] < broad[field] for field in shared)


def lint_rules(rules: list[Rule]) -> list[LintFinding]:
    """Run every lint check over a collection of rules.

    :param rules: The rules to inspect.
    :returns: The findings, ordered by rule path then code.
    """
    findings: list[LintFinding] = []

    def add(rule: Rule, code: str, severity: str, message: str) -> None:
        findings.append(
            LintFinding(
                code=code,
                severity=severity,
                message=message,
                path=str(rule.path),
                rule=rule.identifier,
            )
        )

    for rule in rules:
        if rule.condition is None or (isinstance(rule.condition, str) and not rule.condition.strip()):
            add(rule, "missing-condition", ERROR, "the detection block has no condition")
        else:
            try:
                parse_condition(rule.condition)
            except ConditionError as error:
                add(rule, "invalid-condition", ERROR, str(error))

        if not rule.logsource:
            add(rule, "missing-logsource", ERROR, "the rule has no logsource")

        for message in _contradictions(rule):
            add(rule, "contradictory-filter", ERROR, message)

        for message in _modifier_problems(rule):
            add(rule, "unsupported-modifier", ERROR, message)

        if _uses_them(rule) and any(_is_filter(name) for name in rule.selections):
            add(
                rule,
                "them-includes-filter",
                WARNING,
                "the condition uses 'of them', which also covers the filter selections; "
                "prefer 'of selection*' so the filter is excluded",
            )

    ids: dict[str, list[Rule]] = {}
    titles: dict[str, list[Rule]] = {}
    for rule in rules:
        if rule.id:
            ids.setdefault(rule.id, []).append(rule)
        if rule.title:
            titles.setdefault(rule.title.casefold(), []).append(rule)

    for rule_id, group in ids.items():
        if len(group) > 1:
            paths = ", ".join(str(item.path) for item in group)
            for rule in group:
                add(
                    rule,
                    "duplicate-id",
                    ERROR,
                    f"rule id {rule_id!r} is shared with {len(group) - 1} other rule(s): {paths}",
                )

    for group in titles.values():
        if len(group) > 1:
            paths = ", ".join(str(item.path) for item in group)
            for rule in group:
                add(
                    rule,
                    "duplicate-title",
                    WARNING,
                    f"title {rule.title!r} is shared with {len(group) - 1} other rule(s): {paths}",
                )

    signatures = [(rule, _signature(rule)) for rule in rules]
    for rule, signature in signatures:
        for other, other_signature in signatures:
            if rule is other:
                continue
            if rule.logsource != other.logsource:
                continue
            if not _is_shadowed(signature, other_signature):
                continue
            add(
                rule,
                "shadowed-rule",
                WARNING,
                f"rule is shadowed by {other.identifier}: the broader rule always wins "
                "so this rule never fires alone",
            )
            break

    findings.sort(key=lambda item: (item.path, item.code, item.message))
    return findings
