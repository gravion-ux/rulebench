"""Tests for the rule loader and the rule model."""

from __future__ import annotations

import pytest

from rulebench.rules import RuleParseError, load_rule, load_rules, load_rules_with_errors

VALID_RULE = """\
title: Test Rule
id: 11111111-1111-4111-8111-111111111111
status: test
description: A rule used by the tests.
author: rulebench tests
level: high
logsource:
  product: windows
  category: process_creation
tags:
  - attack.t1059
  - attack.execution
fields:
  - Image
falsepositives:
  - A test
detection:
  selection:
    EventID: 4624
  condition: selection
"""


def test_load_rule_reads_every_field(tmp_path) -> None:
    """A valid rule is parsed into the rule model."""
    path = tmp_path / "test_rule.yml"
    path.write_text(VALID_RULE, encoding="utf-8")
    rule = load_rule(path)
    assert rule.title == "Test Rule"
    assert rule.id == "11111111-1111-4111-8111-111111111111"
    assert rule.status == "test"
    assert rule.level == "high"
    assert rule.logsource == {"product": "windows", "category": "process_creation"}
    assert rule.tags == ("attack.t1059", "attack.execution")
    assert rule.fields == ("Image",)
    assert rule.falsepositives == ("A test",)
    assert rule.condition == "selection"
    assert rule.name == "test_rule"


def test_selections_leave_out_the_condition(tmp_path) -> None:
    """The condition is not a search identifier."""
    path = tmp_path / "test_rule.yml"
    path.write_text(VALID_RULE, encoding="utf-8")
    rule = load_rule(path)
    assert rule.selections == {"selection": {"EventID": 4624}}


def test_identifier_prefers_the_rule_id(tmp_path) -> None:
    """A rule with an id is identified by it."""
    path = tmp_path / "test_rule.yml"
    path.write_text(VALID_RULE, encoding="utf-8")
    assert load_rule(path).identifier == "11111111-1111-4111-8111-111111111111"


def test_identifier_falls_back_to_the_file_stem(tmp_path) -> None:
    """A rule without an id is identified by its file name."""
    path = tmp_path / "test_rule.yml"
    path.write_text("title: No Id\ndetection:\n  condition: selection\n", encoding="utf-8")
    assert load_rule(path).identifier == "test_rule"


def test_a_missing_rule_is_an_error(tmp_path) -> None:
    """A rule file that does not exist is an error."""
    with pytest.raises(RuleParseError):
        load_rule(tmp_path / "nope.yml")


def test_invalid_yaml_is_an_error(tmp_path) -> None:
    """A rule file that is not YAML is an error."""
    path = tmp_path / "broken.yml"
    path.write_text("title: [unclosed\n", encoding="utf-8")
    with pytest.raises(RuleParseError):
        load_rule(path)


def test_a_rule_that_is_not_a_mapping_is_an_error(tmp_path) -> None:
    """A rule file that is not a mapping is an error."""
    path = tmp_path / "broken.yml"
    path.write_text("- just\n- a\n- list\n", encoding="utf-8")
    with pytest.raises(RuleParseError):
        load_rule(path)


def test_a_rule_without_a_title_is_an_error(tmp_path) -> None:
    """A rule file without a title is an error."""
    path = tmp_path / "broken.yml"
    path.write_text("detection:\n  condition: selection\n", encoding="utf-8")
    with pytest.raises(RuleParseError):
        load_rule(path)


def test_a_rule_without_a_detection_is_an_error(tmp_path) -> None:
    """A rule file without a detection block is an error."""
    path = tmp_path / "broken.yml"
    path.write_text("title: No Detection\n", encoding="utf-8")
    with pytest.raises(RuleParseError):
        load_rule(path)


def test_a_detection_block_that_is_not_a_mapping_is_an_error(tmp_path) -> None:
    """A detection block that is not a mapping is an error."""
    path = tmp_path / "broken.yml"
    path.write_text("title: Bad Detection\ndetection: nope\n", encoding="utf-8")
    with pytest.raises(RuleParseError):
        load_rule(path)


def test_a_logsource_that_is_not_a_mapping_is_an_error(tmp_path) -> None:
    """A logsource that is not a mapping is an error."""
    path = tmp_path / "broken.yml"
    path.write_text("title: Bad Logsource\nlogsource: nope\ndetection:\n  condition: s\n", encoding="utf-8")
    with pytest.raises(RuleParseError):
        load_rule(path)


def test_a_condition_that_is_neither_a_string_nor_a_list_is_an_error(tmp_path) -> None:
    """A condition of the wrong type is an error."""
    path = tmp_path / "broken.yml"
    path.write_text("title: Bad Condition\ndetection:\n  condition: 42\n", encoding="utf-8")
    with pytest.raises(RuleParseError):
        load_rule(path)


def test_load_rules_with_errors_collects_both_outcomes(tmp_path) -> None:
    """A directory with a good and a broken rule reports both."""
    (tmp_path / "good.yml").write_text(VALID_RULE, encoding="utf-8")
    (tmp_path / "broken.yml").write_text("title: [unclosed\n", encoding="utf-8")
    rules, errors = load_rules_with_errors(tmp_path)
    assert len(rules) == 1
    assert len(errors) == 1
    assert errors[0].path.name == "broken.yml"


def test_load_rules_with_errors_ignores_other_file_types(tmp_path) -> None:
    """Files that are not rules are skipped."""
    (tmp_path / "good.yml").write_text(VALID_RULE, encoding="utf-8")
    (tmp_path / "notes.md").write_text("not a rule", encoding="utf-8")
    rules, errors = load_rules_with_errors(tmp_path)
    assert len(rules) == 1
    assert errors == []


def test_load_rules_with_errors_rejects_a_missing_directory(tmp_path) -> None:
    """A directory that does not exist is an error."""
    with pytest.raises(RuleParseError):
        load_rules_with_errors(tmp_path / "nope")


def test_load_rules_raises_on_a_broken_rule(tmp_path) -> None:
    """The strict loader refuses to return a partial collection."""
    (tmp_path / "good.yml").write_text(VALID_RULE, encoding="utf-8")
    (tmp_path / "broken.yml").write_text("title: [unclosed\n", encoding="utf-8")
    with pytest.raises(RuleParseError):
        load_rules(tmp_path)
