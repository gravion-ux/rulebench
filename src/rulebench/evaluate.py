"""Rule evaluation against events, and the conformance case engine.

A rule matches an event when its condition expression evaluates true against
the event's fields. Search identifier blocks are conjunctions of field tests,
keyword lists search the whole event, and ``filter`` blocks remove events.

The conformance case engine turns that evaluation into an assertion: a case
declares the outcome a rule must produce for a given event, and the engine
reports whether the rule actually produced it.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from rulebench.conditions import (
    ConditionError,
    evaluate_condition,
    parse_condition,
    pattern_matches,
)
from rulebench.events import Event, event_from_mapping
from rulebench.modifiers import (
    ModifierError,
    has_wildcard,
    match_field,
    parse_field_spec,
    wildcard_regex,
)
from rulebench.rules import Rule, RuleError

__all__ = [
    "Case",
    "CaseError",
    "CaseResult",
    "EvaluationError",
    "evaluate_rule",
    "load_cases",
    "match_selection",
    "run_cases",
]

#: The outcome a rule must produce for an event to satisfy a case.
EXPECTATIONS = ("match", "no-match", "error")


class EvaluationError(ValueError):
    """Raised when a rule cannot be evaluated against an event."""


class CaseError(ValueError):
    """Raised when a conformance case file cannot be understood."""


class _SearchIndex:
    """The searchable text of an event, built the first time it is needed.

    A rule without a keyword selection never searches the event text, so the
    text is not rendered until a keyword actually asks for it. Once it is
    rendered it is reused for every keyword of the event.
    """

    __slots__ = ("_event", "_texts", "_lowered")

    def __init__(self, event: Event) -> None:
        self._event = event
        self._texts: list[str] | None = None
        self._lowered: list[str] | None = None

    @property
    def texts(self) -> list[str]:
        """Every field value rendered as a searchable string.

        :returns: One string per field, in insertion order.
        """
        if self._texts is None:
            self._texts = self._event.texts()
        return self._texts

    @property
    def lowered(self) -> list[str]:
        """Every field value rendered in lower case.

        :returns: One string per field, in insertion order.
        """
        if self._lowered is None:
            self._lowered = [text.lower() for text in self.texts]
        return self._lowered


@lru_cache(maxsize=1024)
def _keyword_regex(keyword: str) -> re.Pattern[str]:
    """Compile the regular expression a keyword wildcard expands to.

    :param keyword: The keyword.
    :returns: The compiled expression.
    """
    return re.compile(wildcard_regex(keyword), re.IGNORECASE)


def _keyword_present(keyword: str, index: _SearchIndex) -> bool:
    """Report whether a keyword appears anywhere in the event.

    :param keyword: The keyword to look for.
    :param index: The searchable text of the event.
    :returns: True when the keyword is present.
    """
    if has_wildcard(keyword):
        expression = _keyword_regex(keyword)
        return any(expression.search(text) for text in index.texts)
    needle = keyword.lower()
    return any(needle in text for text in index.lowered)


def _match_keywords(
    keywords: list[str],
    index: _SearchIndex,
    require_all: bool = False,
) -> bool:
    """Match keyword strings against the whole event.

    :param keywords: The keywords to look for.
    :param index: The searchable text of the event.
    :param require_all: Whether every keyword must be present.
    :returns: True when the keyword requirement holds.
    """
    if not keywords:
        return False
    results = [_keyword_present(keyword, index) for keyword in keywords]
    return all(results) if require_all else any(results)


def _match_selection(selection: Any, event: Event, index: _SearchIndex) -> bool:
    """Evaluate one search identifier block against an event.

    :param selection: The selection: a mapping of field specifications to
        values, a list of alternative blocks, or a keyword string.
    :param event: The event to test.
    :param index: The searchable text of the event.
    :returns: True when the selection matches.
    :raises EvaluationError: When the selection is structurally invalid.
    """
    if isinstance(selection, Mapping):
        keywords: list[str] | None = None
        constraints: dict[str, Any] = {}
        for key, value in selection.items():
            if str(key) == "|all":
                if not isinstance(value, (list, tuple)):
                    raise EvaluationError("the '|all' selection must hold a list of keywords")
                keywords = [str(keyword) for keyword in value]
            else:
                constraints[str(key)] = value
        if keywords is not None and not _match_keywords(keywords, index, require_all=True):
            return False
        for field, value in constraints.items():
            spec = parse_field_spec(field)
            if not match_field(event, spec, value):
                return False
        return True
    if isinstance(selection, (list, tuple)):
        results = []
        for item in selection:
            if isinstance(item, Mapping):
                results.append(_match_selection(item, event, index))
            elif isinstance(item, str):
                results.append(_match_keywords([item], index))
            else:
                results.append(False)
        return any(results)
    if isinstance(selection, str):
        return _match_keywords([selection], index)
    return False


def match_selection(selection: Any, event: Event) -> bool:
    """Evaluate one search identifier block against an event.

    :param selection: The selection: a mapping of field specifications to
        values, a list of alternative blocks, or a keyword string.
    :param event: The event to test.
    :returns: True when the selection matches.
    :raises EvaluationError: When the selection is structurally invalid.
    """
    return _match_selection(selection, event, _SearchIndex(event))


class _Context:
    """Resolves search identifiers while a condition is evaluated."""

    def __init__(self, identifiers: Mapping[str, Any], event: Event, path: Any) -> None:
        self.identifiers = identifiers
        self.event = event
        self.path = path
        self._index = _SearchIndex(event)

    def identifier_matches(self, name: str) -> bool:
        """Evaluate one named search identifier.

        :param name: The search identifier name.
        :returns: True when the identifier matches the event.
        :raises EvaluationError: When the identifier is not defined.
        """
        if name not in self.identifiers:
            raise EvaluationError(
                f"condition in {self.path} refers to unknown search identifier {name!r}"
            )
        return _match_selection(self.identifiers[name], self.event, self._index)

    def matching_identifiers(self, pattern: str) -> list[str]:
        """Resolve a search identifier pattern to concrete names.

        ``them`` covers every search identifier whose name does not start with
        an underscore, exactly as the specification states.

        :param pattern: The pattern, or the literal ``them``.
        :returns: The matching search identifier names.
        """
        if pattern == "them":
            return [name for name in self.identifiers if not name.startswith("_")]
        return [name for name in self.identifiers if pattern_matches(pattern, name)]


def evaluate_rule(rule: Rule, event: Event) -> bool:
    """Evaluate a rule against an event.

    :param rule: The rule to evaluate.
    :param event: The event to test.
    :returns: True when the rule matches the event.
    :raises EvaluationError: When the rule has no condition or the condition
        refers to an identifier the rule does not define.
    """
    if rule.condition is None:
        raise EvaluationError(f"rule {rule.path} has no condition")
    context = _Context(rule.selections, event, rule.path)
    nodes = parse_condition(rule.condition)
    return evaluate_condition(nodes, context)


@dataclass(frozen=True)
class Case:
    """One conformance case: an event and the outcome a rule must produce."""

    name: str
    rule: str
    expect: str
    event: Mapping[str, Any] | None = None
    event_name: str | None = None


@dataclass(frozen=True)
class CaseResult:
    """The outcome of running one conformance case."""

    name: str
    rule: str
    expected: str
    actual: str
    passed: bool
    message: str = ""
    path: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Render the result as a plain dictionary.

        :returns: The result as a dictionary.
        """
        return {
            "name": self.name,
            "rule": self.rule,
            "expected": self.expected,
            "actual": self.actual,
            "passed": self.passed,
            "message": self.message,
            "path": self.path,
        }


def load_cases(path: str | Path) -> list[Case]:
    """Load conformance cases from a YAML file.

    The file holds a ``cases`` list, or a bare list of cases. Each case names
    the rule it exercises, the event to feed it (inline as ``event`` or by name
    as ``event_name``) and the expected outcome.

    :param path: Path to the case file.
    :returns: The loaded cases.
    :raises CaseError: When the file is missing, malformed, or holds a case
        without a rule or with an unknown expectation.
    """
    target = Path(path)
    try:
        raw = target.read_text(encoding="utf-8")
    except OSError as error:
        raise CaseError(f"could not read case file {target}: {error}") from error
    try:
        document = yaml.safe_load(raw)
    except yaml.YAMLError as error:
        raise CaseError(f"case file {target} is not valid YAML: {error}") from error
    if isinstance(document, Mapping):
        document = document.get("cases")
    if not isinstance(document, list):
        raise CaseError(f"case file {target} must contain a list of cases")

    cases: list[Case] = []
    for index, item in enumerate(document):
        if not isinstance(item, Mapping):
            raise CaseError(f"case {index} in {target} is not a mapping")
        rule = item.get("rule")
        if not rule:
            raise CaseError(f"case {index} in {target} does not name a rule")
        expect = str(item.get("expect", "match"))
        if expect not in EXPECTATIONS:
            raise CaseError(
                f"case {index} in {target} has an unknown expectation {expect!r}; "
                f"expected one of {', '.join(EXPECTATIONS)}"
            )
        event = item.get("event")
        if event is not None and not isinstance(event, Mapping):
            raise CaseError(f"case {index} in {target} has a non-mapping event")
        cases.append(
            Case(
                name=str(item.get("name", f"case-{index + 1}")),
                rule=str(rule),
                expect=expect,
                event=event,
                event_name=str(item["event_name"]) if item.get("event_name") else None,
            )
        )
    return cases


class _RuleIndex:
    """Resolves a case's ``rule`` reference to a loaded rule."""

    def __init__(self, rules: Sequence[Rule], errors: Sequence[RuleError]) -> None:
        self._rules: dict[str, Rule] = {}
        for rule in rules:
            for key in (rule.id, rule.name, rule.title):
                if key:
                    self._rules.setdefault(key.casefold(), rule)
        self._broken: dict[str, RuleError] = {}
        for error in errors:
            self._broken[error.path.stem.casefold()] = error

    def lookup(self, reference: str) -> tuple[Rule | None, RuleError | None]:
        """Find the rule a case refers to.

        :param reference: The rule id, file stem or title.
        :returns: The rule and/or the parse error for the reference.
        """
        key = reference.casefold()
        rule = self._rules.get(key)
        if rule is not None:
            return rule, None
        return None, self._broken.get(key)


def run_cases(
    cases: Sequence[Case],
    rules: Sequence[Rule],
    errors: Sequence[RuleError],
    events: Sequence[Event] | None = None,
) -> list[CaseResult]:
    """Run every conformance case and report the outcome.

    :param cases: The cases to run.
    :param rules: The rules that loaded.
    :param errors: The rules that failed to parse.
    :param events: An optional event corpus a case may reference by name.
    :returns: One result per case, in case order.
    """
    index = _RuleIndex(rules, errors)
    corpus = {event.name: event for event in (events or []) if event.name}
    results: list[CaseResult] = []

    for case in cases:
        rule, broken = index.lookup(case.rule)
        if rule is None and broken is None:
            results.append(
                CaseResult(
                    name=case.name,
                    rule=case.rule,
                    expected=case.expect,
                    actual="error",
                    passed=False,
                    message=f"no rule named {case.rule!r} was found",
                )
            )
            continue

        if broken is not None:
            actual = "error"
            message = broken.message
            path = str(broken.path)
        else:
            event = None
            if case.event is not None:
                event = event_from_mapping(case.event)
            elif case.event_name is not None:
                event = corpus.get(case.event_name)
                if event is None:
                    results.append(
                        CaseResult(
                            name=case.name,
                            rule=case.rule,
                            expected=case.expect,
                            actual="error",
                            passed=False,
                            message=f"the event corpus has no event named {case.event_name!r}",
                            path=str(rule.path),
                        )
                    )
                    continue
            if event is None:
                event = Event(fields={})
            try:
                matched = evaluate_rule(rule, event)
                actual = "match" if matched else "no-match"
                message = ""
            except (ConditionError, EvaluationError, ModifierError) as error:
                actual = "error"
                message = str(error)
            path = str(rule.path)

        results.append(
            CaseResult(
                name=case.name,
                rule=case.rule,
                expected=case.expect,
                actual=actual,
                passed=actual == case.expect,
                message=message,
                path=path,
            )
        )
    return results


def untested_rules(cases: Sequence[Case], rules: Sequence[Rule]) -> list[str]:
    """List the rules that no conformance case exercises.

    :param cases: The cases that were run.
    :param rules: The loaded rules.
    :returns: The identifiers of the rules with no case.
    """
    covered = {case.rule.casefold() for case in cases}
    untested: list[str] = []
    for rule in rules:
        keys = {key.casefold() for key in (rule.id, rule.name, rule.title) if key}
        if not keys & covered:
            untested.append(rule.identifier)
    return untested
