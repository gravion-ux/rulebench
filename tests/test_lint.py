"""Tests for the rule linter."""

from __future__ import annotations

from pathlib import Path

from rulebench.lint import lint_rules
from rulebench.rules import load_rule


def make_rule(tmp_path: Path, name: str, body: str):
    """Write a rule and load it.

    :param tmp_path: The directory to write into.
    :param name: The file stem.
    :param body: The YAML body.
    :returns: The loaded rule.
    """
    path = tmp_path / f"{name}.yml"
    path.write_text(body, encoding="utf-8")
    return load_rule(path)


CLEAN_RULE = """\
title: Clean Rule
id: 33333333-3333-4333-8333-333333333333
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    EventID: 4624
  condition: selection
"""


def codes(findings) -> list[str]:
    """Return the codes of the findings.

    :param findings: The findings.
    :returns: The codes.
    """
    return [finding.code for finding in findings]


def test_a_clean_rule_produces_no_findings(tmp_path) -> None:
    """A well formed rule is not reported."""
    rule = make_rule(tmp_path, "clean", CLEAN_RULE)
    assert lint_rules([rule]) == []


def test_duplicate_ids_are_an_error(tmp_path) -> None:
    """Two rules that share an id are both reported."""
    first = make_rule(tmp_path, "first", CLEAN_RULE)
    second_body = CLEAN_RULE.replace("title: Clean Rule", "title: Clean Rule With Another Name")
    second = make_rule(tmp_path, "second", second_body)
    findings = lint_rules([first, second])
    assert codes(findings) == ["duplicate-id", "duplicate-id"]
    assert all(finding.severity == "error" for finding in findings)


def test_duplicate_titles_are_a_warning(tmp_path) -> None:
    """Two rules that share a title are both reported."""
    body = CLEAN_RULE.replace("33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444")
    first = make_rule(tmp_path, "first", CLEAN_RULE)
    second = make_rule(tmp_path, "second", body)
    findings = lint_rules([first, second])
    assert codes(findings) == ["duplicate-title", "duplicate-title"]
    assert all(finding.severity == "warning" for finding in findings)


def test_a_missing_condition_is_an_error(tmp_path) -> None:
    """A rule without a condition is reported."""
    body = "title: No Condition\nlogsource:\n  product: windows\ndetection:\n  selection:\n    a: b\n"
    rule = make_rule(tmp_path, "no_condition", body)
    assert codes(lint_rules([rule])) == ["missing-condition"]


def test_a_missing_logsource_is_an_error(tmp_path) -> None:
    """A rule without a logsource is reported."""
    body = "title: No Logsource\ndetection:\n  selection:\n    a: b\n  condition: selection\n"
    rule = make_rule(tmp_path, "no_logsource", body)
    assert codes(lint_rules([rule])) == ["missing-logsource"]


def test_an_invalid_condition_is_an_error(tmp_path) -> None:
    """A condition that does not parse is reported."""
    body = (
        "title: Bad Condition\n"
        "logsource:\n  product: windows\n"
        "detection:\n  selection:\n    a: b\n  condition: selection and\n"
    )
    rule = make_rule(tmp_path, "bad_condition", body)
    assert codes(lint_rules([rule])) == ["invalid-condition"]


def test_a_filter_that_can_never_exclude_anything_is_an_error(tmp_path) -> None:
    """A filter whose values are disjoint from the selection is reported."""
    body = (
        "title: Disjoint Filter\n"
        "logsource:\n  product: windows\n"
        "detection:\n"
        "  selection:\n    Image: 'cmd.exe'\n"
        "  filter:\n    Image: 'powershell.exe'\n"
        "  condition: selection and not filter\n"
    )
    rule = make_rule(tmp_path, "disjoint", body)
    findings = lint_rules([rule])
    assert codes(findings) == ["contradictory-filter"]
    assert "can never exclude" in findings[0].message


def test_a_filter_that_excludes_everything_is_an_error(tmp_path) -> None:
    """A filter that covers the whole selection is reported."""
    body = (
        "title: Covering Filter\n"
        "logsource:\n  product: windows\n"
        "detection:\n"
        "  selection:\n    Image: 'cmd.exe'\n"
        "  filter:\n    Image: 'cmd.exe'\n"
        "  condition: selection and not filter\n"
    )
    rule = make_rule(tmp_path, "covering", body)
    findings = lint_rules([rule])
    assert codes(findings) == ["contradictory-filter"]
    assert "excludes every event" in findings[0].message


def test_of_them_with_a_filter_is_a_warning(tmp_path) -> None:
    """The 'of them' footgun is reported as a warning."""
    body = (
        "title: Them With Filter\n"
        "logsource:\n  product: windows\n"
        "detection:\n"
        "  selection_cmd:\n    CommandLine: 'whoami'\n"
        "  filter:\n    User: 'SYSTEM'\n"
        "  condition: 1 of them\n"
    )
    rule = make_rule(tmp_path, "them", body)
    findings = lint_rules([rule])
    assert codes(findings) == ["them-includes-filter"]
    assert findings[0].severity == "warning"


def test_the_expand_modifier_is_an_error(tmp_path) -> None:
    """A rule that needs placeholder expansion is reported."""
    body = (
        "title: Expand\n"
        "logsource:\n  product: windows\n"
        "detection:\n"
        "  selection:\n    Image|expand: '%COMPUTERNAME%'\n"
        "  condition: selection\n"
    )
    rule = make_rule(tmp_path, "expand", body)
    findings = lint_rules([rule])
    assert codes(findings) == ["unsupported-modifier"]
    assert "expand" in findings[0].message


def test_an_unknown_modifier_is_an_error(tmp_path) -> None:
    """A modifier the specification does not define is reported."""
    body = (
        "title: Unknown Modifier\n"
        "logsource:\n  product: windows\n"
        "detection:\n"
        "  selection:\n    Image|nonsense: 'cmd.exe'\n"
        "  condition: selection\n"
    )
    rule = make_rule(tmp_path, "unknown_modifier", body)
    findings = lint_rules([rule])
    assert codes(findings) == ["unsupported-modifier"]
    assert "unknown modifier" in findings[0].message


def test_a_shadowed_rule_is_a_warning(tmp_path) -> None:
    """A rule that a broader rule always wins is reported."""
    broad_body = (
        "title: Broad Rule\n"
        "logsource:\n  product: windows\n"
        "detection:\n"
        "  selection:\n    Image: 'cmd.exe'\n"
        "  condition: selection\n"
    )
    narrow_body = (
        "title: Narrow Rule\n"
        "logsource:\n  product: windows\n"
        "detection:\n"
        "  selection:\n    Image: 'cmd.exe'\n    CommandLine: 'whoami'\n"
        "  condition: selection\n"
    )
    broad = make_rule(tmp_path, "broad", broad_body)
    narrow = make_rule(tmp_path, "narrow", narrow_body)
    findings = lint_rules([broad, narrow])
    assert codes(findings) == ["shadowed-rule"]
    assert findings[0].rule == narrow.identifier


def test_rules_with_different_logsources_do_not_shadow_each_other(tmp_path) -> None:
    """Two rules from different products are never compared."""
    broad_body = (
        "title: Windows Broad\n"
        "logsource:\n  product: windows\n"
        "detection:\n"
        "  selection:\n    Image: 'cmd.exe'\n"
        "  condition: selection\n"
    )
    narrow_body = (
        "title: Linux Narrow\n"
        "logsource:\n  product: linux\n"
        "detection:\n"
        "  selection:\n    Image: 'cmd.exe'\n    CommandLine: 'whoami'\n"
        "  condition: selection\n"
    )
    broad = make_rule(tmp_path, "broad", broad_body)
    narrow = make_rule(tmp_path, "narrow", narrow_body)
    assert lint_rules([broad, narrow]) == []


def test_findings_carry_the_rule_and_the_path(tmp_path) -> None:
    """A finding says which rule and which file it is about."""
    body = "title: No Logsource\ndetection:\n  selection:\n    a: b\n  condition: selection\n"
    rule = make_rule(tmp_path, "no_logsource", body)
    finding = lint_rules([rule])[0]
    assert finding.rule == rule.identifier
    assert finding.path.endswith("no_logsource.yml")
