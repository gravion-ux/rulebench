"""Tests for rule evaluation and the conformance case engine."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from rulebench.evaluate import (
    CaseError,
    EvaluationError,
    evaluate_rule,
    load_cases,
    match_selection,
    run_cases,
    untested_rules,
)
from rulebench.events import Event
from rulebench.rules import load_rule, load_rules_with_errors


def load_cases_from_text(body: str):
    """Load cases from a YAML string.

    :param body: The YAML body.
    :returns: The loaded cases.
    """
    with tempfile.TemporaryDirectory() as raw:
        path = Path(raw) / "cases.yaml"
        path.write_text(body, encoding="utf-8")
        return load_cases(path)

RULE = """\
title: Process Creation
id: 22222222-2222-4222-8222-222222222222
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\cmd.exe'
    CommandLine|contains: 'whoami'
  filter:
    User: 'SYSTEM'
  condition: selection and not filter
"""


def build_rule(tmp_path, name: str = "process_creation", body: str = RULE):
    """Write a rule and load it.

    :param tmp_path: The directory to write into.
    :param name: The file stem.
    :param body: The YAML body.
    :returns: The loaded rule.
    """
    path = tmp_path / f"{name}.yml"
    path.write_text(body, encoding="utf-8")
    return load_rule(path)


def test_a_mapping_selection_is_a_conjunction() -> None:
    """Every field of a mapping selection has to match."""
    event = Event(fields={"Image": "C:\\Windows\\cmd.exe", "CommandLine": "cmd.exe /c whoami"})
    assert match_selection({"Image": "C:\\Windows\\cmd.exe", "CommandLine": "cmd.exe /c whoami"}, event)
    assert not match_selection({"Image": "C:\\Windows\\cmd.exe", "CommandLine": "net user"}, event)


def test_a_list_selection_is_a_disjunction() -> None:
    """Any alternative of a list selection may match."""
    event = Event(fields={"CommandLine": "cmd.exe /c whoami"})
    alternatives = [
        {"CommandLine|contains": "net user"},
        {"CommandLine|contains": "whoami"},
    ]
    assert match_selection(alternatives, event)
    assert not match_selection([{"CommandLine|contains": "net user"}], event)


def test_a_list_of_maps_holds_field_tests() -> None:
    """A map inside a list selection is a field test, not a keyword search."""
    event = Event(fields={"CommandLine": "cmd.exe /c whoami"})
    assert match_selection([{"CommandLine": "whoami"}], event) is False
    assert match_selection([{"CommandLine": "cmd.exe /c whoami"}], event) is True


def test_a_string_selection_is_a_keyword_search() -> None:
    """A bare string is looked for anywhere in the event."""
    event = Event(fields={"CommandLine": "cmd.exe /c whoami"})
    assert match_selection("whoami", event)
    assert not match_selection("net user", event)


def test_the_all_key_requires_every_keyword() -> None:
    """The '|all' key form is a conjunction of keywords."""
    event = Event(fields={"CommandLine": "cmd.exe /c whoami /all"})
    assert match_selection({"|all": ["whoami", "/all"]}, event)
    assert not match_selection({"|all": ["whoami", "net user"]}, event)


def test_the_all_key_can_appear_beside_a_field() -> None:
    """The '|all' key does not stop the other fields from being checked."""
    event = Event(fields={"CommandLine": "cmd.exe /c whoami", "Image": "cmd.exe"})
    assert match_selection({"|all": ["whoami"], "Image": "cmd.exe"}, event)
    assert not match_selection({"|all": ["whoami"], "Image": "powershell.exe"}, event)


def test_an_all_key_that_is_not_a_list_is_an_error() -> None:
    """The '|all' key has to hold a list."""
    event = Event(fields={"CommandLine": "whoami"})
    with pytest.raises(EvaluationError):
        match_selection({"|all": "whoami"}, event)


def test_evaluate_rule_matches_an_event(tmp_path) -> None:
    """A rule that matches the event returns true."""
    rule = build_rule(tmp_path)
    event = Event(fields={"Image": "C:\\Windows\\cmd.exe", "CommandLine": "cmd.exe /c whoami"})
    assert evaluate_rule(rule, event) is True


def test_evaluate_rule_honours_a_filter(tmp_path) -> None:
    """A filtered event does not match."""
    rule = build_rule(tmp_path)
    event = Event(
        fields={
            "Image": "C:\\Windows\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "User": "SYSTEM",
        }
    )
    assert evaluate_rule(rule, event) is False


def test_evaluate_rule_needs_a_condition(tmp_path) -> None:
    """A rule without a condition cannot be evaluated."""
    rule = build_rule(tmp_path, "no_condition", "title: No Condition\ndetection:\n  selection: {}\n")
    with pytest.raises(EvaluationError):
        evaluate_rule(rule, Event(fields={}))


def test_evaluate_rule_rejects_an_unknown_identifier(tmp_path) -> None:
    """A condition that names an undefined identifier is an error."""
    body = (
        "title: Unknown Identifier\n"
        "logsource:\n  product: windows\n"
        "detection:\n  selection:\n    EventID: 1\n  condition: missing\n"
    )
    rule = build_rule(tmp_path, "unknown_identifier", body)
    with pytest.raises(EvaluationError):
        evaluate_rule(rule, Event(fields={"EventID": 1}))


def test_load_cases_reads_a_cases_key(tmp_path) -> None:
    """A case file with a cases key is accepted."""
    path = tmp_path / "cases.yaml"
    path.write_text(
        "cases:\n"
        "  - name: first\n"
        "    rule: process_creation\n"
        "    expect: match\n"
        "    event:\n"
        "      EventID: 1\n",
        encoding="utf-8",
    )
    cases = load_cases(path)
    assert len(cases) == 1
    assert cases[0].name == "first"
    assert cases[0].rule == "process_creation"
    assert cases[0].expect == "match"
    assert cases[0].event == {"EventID": 1}


def test_load_cases_reads_a_bare_list(tmp_path) -> None:
    """A case file that is a bare list is accepted."""
    path = tmp_path / "cases.yaml"
    path.write_text("- name: first\n  rule: process_creation\n", encoding="utf-8")
    cases = load_cases(path)
    assert len(cases) == 1


def test_load_cases_defaults_the_expectation_to_match(tmp_path) -> None:
    """A case without an expectation expects a match."""
    path = tmp_path / "cases.yaml"
    path.write_text("cases:\n  - name: first\n    rule: process_creation\n", encoding="utf-8")
    assert load_cases(path)[0].expect == "match"


def test_load_cases_reads_an_event_name(tmp_path) -> None:
    """A case can point at a named event."""
    path = tmp_path / "cases.yaml"
    path.write_text(
        "cases:\n  - name: first\n    rule: process_creation\n    event_name: corpus\n",
        encoding="utf-8",
    )
    assert load_cases(path)[0].event_name == "corpus"


def test_load_cases_rejects_a_missing_file(tmp_path) -> None:
    """A missing case file is an error."""
    with pytest.raises(CaseError):
        load_cases(tmp_path / "nope.yaml")


def test_load_cases_rejects_invalid_yaml(tmp_path) -> None:
    """A case file that is not YAML is an error."""
    path = tmp_path / "cases.yaml"
    path.write_text("cases: [unclosed\n", encoding="utf-8")
    with pytest.raises(CaseError):
        load_cases(path)


def test_load_cases_rejects_a_document_without_a_list(tmp_path) -> None:
    """A case file that does not hold a list is an error."""
    path = tmp_path / "cases.yaml"
    path.write_text("cases:\n  key: value\n", encoding="utf-8")
    with pytest.raises(CaseError):
        load_cases(path)


def test_load_cases_rejects_a_case_without_a_rule(tmp_path) -> None:
    """A case that does not name a rule is an error."""
    path = tmp_path / "cases.yaml"
    path.write_text("cases:\n  - name: first\n", encoding="utf-8")
    with pytest.raises(CaseError):
        load_cases(path)


def test_load_cases_rejects_an_unknown_expectation(tmp_path) -> None:
    """A case with an expectation rulebench does not know is an error."""
    path = tmp_path / "cases.yaml"
    path.write_text("cases:\n  - name: first\n    rule: r\n    expect: maybe\n", encoding="utf-8")
    with pytest.raises(CaseError):
        load_cases(path)


def test_load_cases_rejects_a_non_mapping_event(tmp_path) -> None:
    """A case whose event is not a mapping is an error."""
    path = tmp_path / "cases.yaml"
    path.write_text("cases:\n  - name: first\n    rule: r\n    event: nope\n", encoding="utf-8")
    with pytest.raises(CaseError):
        load_cases(path)


def test_run_cases_reports_a_match(tmp_path) -> None:
    """A case that expects a match passes when the rule matches."""
    rule = build_rule(tmp_path)
    cases = load_cases_from_text(
        "cases:\n"
        "  - name: matches\n"
        "    rule: process_creation\n"
        "    expect: match\n"
        "    event:\n"
        "      Image: 'C:\\Windows\\cmd.exe'\n"
        "      CommandLine: 'cmd.exe /c whoami'\n"
    )
    results = run_cases(cases, [rule], [])
    assert results[0].passed is True
    assert results[0].actual == "match"


def test_run_cases_reports_a_no_match(tmp_path) -> None:
    """A case that expects no match passes when the rule does not match."""
    rule = build_rule(tmp_path)
    cases = load_cases_from_text(
        "cases:\n"
        "  - name: does not match\n"
        "    rule: process_creation\n"
        "    expect: no-match\n"
        "    event:\n"
        "      Image: 'C:\\Windows\\notepad.exe'\n"
    )
    results = run_cases(cases, [rule], [])
    assert results[0].passed is True
    assert results[0].actual == "no-match"


def test_run_cases_fails_when_the_outcome_differs(tmp_path) -> None:
    """A case whose outcome differs fails."""
    rule = build_rule(tmp_path)
    cases = load_cases_from_text(
        "cases:\n"
        "  - name: wrong\n"
        "    rule: process_creation\n"
        "    expect: match\n"
        "    event:\n"
        "      Image: 'C:\\Windows\\notepad.exe'\n"
    )
    results = run_cases(cases, [rule], [])
    assert results[0].passed is False
    assert results[0].expected == "match"
    assert results[0].actual == "no-match"


def test_run_cases_finds_a_rule_by_its_id(tmp_path) -> None:
    """A case can name a rule by its id."""
    rule = build_rule(tmp_path)
    cases = load_cases_from_text(
        "cases:\n"
        "  - name: by id\n"
        "    rule: 22222222-2222-4222-8222-222222222222\n"
        "    expect: no-match\n"
        "    event:\n"
        "      Image: 'C:\\Windows\\notepad.exe'\n"
    )
    results = run_cases(cases, [rule], [])
    assert results[0].passed is True


def test_run_cases_finds_a_rule_by_its_title(tmp_path) -> None:
    """A case can name a rule by its title."""
    rule = build_rule(tmp_path)
    cases = load_cases_from_text(
        "cases:\n"
        "  - name: by title\n"
        "    rule: Process Creation\n"
        "    expect: no-match\n"
        "    event:\n"
        "      Image: 'C:\\Windows\\notepad.exe'\n"
    )
    results = run_cases(cases, [rule], [])
    assert results[0].passed is True


def test_run_cases_reports_an_unknown_rule(tmp_path) -> None:
    """A case that names a rule nobody loaded fails."""
    rule = build_rule(tmp_path)
    cases = load_cases_from_text(
        "cases:\n  - name: missing\n    rule: nowhere\n    expect: match\n    event:\n      a: b\n"
    )
    results = run_cases(cases, [rule], [])
    assert results[0].passed is False
    assert results[0].actual == "error"
    assert "no rule named" in results[0].message


def test_run_cases_reports_a_broken_rule(tmp_path) -> None:
    """A rule that does not parse produces an error outcome."""
    (tmp_path / "broken.yml").write_text("title: [unclosed\n", encoding="utf-8")
    _rules, errors = load_rules_with_errors(tmp_path)
    cases = load_cases_from_text(
        "cases:\n  - name: broken\n    rule: broken\n    expect: error\n    event:\n      a: b\n"
    )
    results = run_cases(cases, [], errors)
    assert results[0].actual == "error"
    assert results[0].passed is True


def test_run_cases_uses_the_event_corpus(tmp_path) -> None:
    """A case can name an event from the corpus."""
    rule = build_rule(tmp_path)
    corpus = [Event(fields={"Image": "C:\\Windows\\cmd.exe"}, name="hit")]
    cases = load_cases_from_text(
        "cases:\n"
        "  - name: from corpus\n"
        "    rule: process_creation\n"
        "    expect: no-match\n"
        "    event_name: hit\n"
    )
    results = run_cases(cases, [rule], [], corpus)
    assert results[0].actual == "no-match"


def test_run_cases_reports_an_unknown_corpus_event(tmp_path) -> None:
    """A case that names an event nobody supplied fails."""
    rule = build_rule(tmp_path)
    cases = load_cases_from_text(
        "cases:\n  - name: missing event\n    rule: process_creation\n    event_name: nowhere\n"
    )
    results = run_cases(cases, [rule], [], [])
    assert results[0].passed is False
    assert "no event named" in results[0].message


def test_untested_rules_lists_the_rules_without_a_case(tmp_path) -> None:
    """A rule that no case exercises is reported."""
    rule = build_rule(tmp_path)
    cases = load_cases_from_text("cases:\n  - name: other\n    rule: somewhere_else\n")
    assert untested_rules(cases, [rule]) == [rule.identifier]
