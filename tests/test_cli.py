"""Tests for the command line interface."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ElementTree
from pathlib import Path

from rulebench.cli import EXIT_FINDINGS, EXIT_OK, EXIT_USAGE, main

RULE = """\
title: Process Creation
id: 55555555-5555-4555-8555-555555555555
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\cmd.exe'
  condition: selection
"""

RULE_WITH_WARNING = """\
title: Rule With A Warning
id: 66666666-6666-4666-8666-666666666666
logsource:
  product: windows
  category: process_creation
detection:
  selection_cmd:
    CommandLine: 'whoami'
  filter:
    User: 'SYSTEM'
  condition: 1 of them
"""

RULE_WITHOUT_LOGSOURCE = """\
title: Rule Without A Logsource
id: 77777777-7777-4777-8777-777777777777
detection:
  selection:
    EventID: 4624
  condition: selection
"""


def build_corpus(root: Path) -> tuple[Path, Path]:
    """Write a small rule collection and a case file.

    :param root: The directory to write into.
    :returns: The rules directory and the case file.
    """
    rules = root / "rules"
    rules.mkdir(parents=True, exist_ok=True)
    (rules / "process_creation.yml").write_text(RULE, encoding="utf-8")
    cases = root / "cases.yaml"
    cases.write_text(
        "cases:\n"
        "  - name: matches\n"
        "    rule: process_creation\n"
        "    expect: match\n"
        "    event:\n"
        "      Image: 'C:\\Windows\\cmd.exe'\n"
        "  - name: does not match\n"
        "    rule: process_creation\n"
        "    expect: no-match\n"
        "    event:\n"
        "      Image: 'C:\\Windows\\notepad.exe'\n",
        encoding="utf-8",
    )
    return rules, cases


def test_no_command_prints_the_help(tmp_path, capsys) -> None:
    """Running without a command shows the help and exits with a usage error."""
    assert main([]) == EXIT_USAGE
    assert "rulebench" in capsys.readouterr().out


def test_the_test_command_passes_on_a_good_corpus(tmp_path, capsys) -> None:
    """A corpus whose cases all pass exits successfully."""
    rules, cases = build_corpus(tmp_path)
    code = main(["test", "--rules", str(rules), "--cases", str(cases)])
    assert code == EXIT_OK
    assert "2 case(s), 2 passed, 0 failed" in capsys.readouterr().out


def test_the_test_command_fails_on_a_failing_case(tmp_path, capsys) -> None:
    """A corpus with a failing case exits with a findings error."""
    rules, cases = build_corpus(tmp_path)
    cases.write_text(
        "cases:\n"
        "  - name: wrong\n"
        "    rule: process_creation\n"
        "    expect: match\n"
        "    event:\n"
        "      Image: 'C:\\Windows\\notepad.exe'\n",
        encoding="utf-8",
    )
    assert main(["test", "--rules", str(rules), "--cases", str(cases)]) == EXIT_FINDINGS
    assert "FAIL" in capsys.readouterr().out


def test_the_test_command_reports_the_untested_rules(tmp_path, capsys) -> None:
    """A rule without a case is listed."""
    rules, cases = build_corpus(tmp_path)
    (rules / "extra.yml").write_text(RULE_WITH_WARNING, encoding="utf-8")
    assert main(["test", "--rules", str(rules), "--cases", str(cases)]) == EXIT_OK
    assert "Rules with no conformance case" in capsys.readouterr().out


def test_an_uncovered_broken_rule_fails_the_run(tmp_path, capsys) -> None:
    """A rule that does not parse and is not covered by a case fails the run."""
    rules, cases = build_corpus(tmp_path)
    (rules / "broken.yml").write_text("title: [unclosed\n", encoding="utf-8")
    code = main(["test", "--rules", str(rules), "--cases", str(cases)])
    assert code == EXIT_FINDINGS
    assert "failed to parse" in capsys.readouterr().out


def test_a_broken_rule_covered_by_an_error_case_passes(tmp_path, capsys) -> None:
    """A broken rule that a case documents as an error is accepted."""
    rules, cases = build_corpus(tmp_path)
    (rules / "broken.yml").write_text("title: [unclosed\n", encoding="utf-8")
    cases.write_text(
        "cases:\n"
        "  - name: broken\n"
        "    rule: broken\n"
        "    expect: error\n"
        "    event:\n"
        "      a: b\n",
        encoding="utf-8",
    )
    assert main(["test", "--rules", str(rules), "--cases", str(cases)]) == EXIT_OK


def test_the_test_command_writes_json(tmp_path, capsys) -> None:
    """The JSON format produces a parsable document."""
    rules, cases = build_corpus(tmp_path)
    assert main(["test", "--rules", str(rules), "--cases", str(cases), "--format", "json"]) == EXIT_OK
    document = json.loads(capsys.readouterr().out)
    assert document["tool"] == "rulebench"
    assert document["summary"]["passed"] == 2


def test_the_test_command_writes_junit(tmp_path, capsys) -> None:
    """The JUnit format produces a parsable document."""
    rules, cases = build_corpus(tmp_path)
    assert main(["test", "--rules", str(rules), "--cases", str(cases), "--format", "junit"]) == EXIT_OK
    root = ElementTree.fromstring(capsys.readouterr().out)
    assert root.attrib["tests"] == "2"


def test_the_test_command_writes_to_a_file(tmp_path) -> None:
    """The output option writes the report to disk."""
    rules, cases = build_corpus(tmp_path)
    destination = tmp_path / "report.json"
    main(
        [
            "test",
            "--rules",
            str(rules),
            "--cases",
            str(cases),
            "--format",
            "json",
            "--output",
            str(destination),
        ]
    )
    document = json.loads(destination.read_text(encoding="utf-8"))
    assert document["summary"]["cases"] == 2


def test_a_missing_rules_directory_is_a_usage_error(tmp_path, capsys) -> None:
    """A rules directory that does not exist is a usage error."""
    _rules, cases = build_corpus(tmp_path)
    code = main(["test", "--rules", str(tmp_path / "nope"), "--cases", str(cases)])
    assert code == EXIT_USAGE
    assert "rules directory not found" in capsys.readouterr().err


def test_a_missing_case_file_is_a_usage_error(tmp_path, capsys) -> None:
    """A case file that does not exist is a usage error."""
    rules, _cases = build_corpus(tmp_path)
    code = main(["test", "--rules", str(rules), "--cases", str(tmp_path / "nope.yaml")])
    assert code == EXIT_USAGE
    assert "could not read case file" in capsys.readouterr().err


def test_the_lint_command_fails_on_an_error(tmp_path, capsys) -> None:
    """A rule without a logsource makes the linter fail."""
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "no_logsource.yml").write_text(RULE_WITHOUT_LOGSOURCE, encoding="utf-8")
    assert main(["lint", "--rules", str(rules)]) == EXIT_FINDINGS
    assert "missing-logsource" in capsys.readouterr().out


def test_the_lint_command_passes_on_a_warning(tmp_path, capsys) -> None:
    """A warning alone does not fail the linter."""
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "warning.yml").write_text(RULE_WITH_WARNING, encoding="utf-8")
    assert main(["lint", "--rules", str(rules)]) == EXIT_OK
    assert "them-includes-filter" in capsys.readouterr().out


def test_the_lint_command_passes_on_a_clean_corpus(tmp_path, capsys) -> None:
    """A clean corpus produces no findings."""
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "clean.yml").write_text(RULE, encoding="utf-8")
    assert main(["lint", "--rules", str(rules)]) == EXIT_OK
    assert "no findings" in capsys.readouterr().out


def test_the_lint_command_writes_json(tmp_path, capsys) -> None:
    """The JSON lint report is parsable."""
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "no_logsource.yml").write_text(RULE_WITHOUT_LOGSOURCE, encoding="utf-8")
    main(["lint", "--rules", str(rules), "--format", "json"])
    document = json.loads(capsys.readouterr().out)
    assert document["summary"]["errors"] == 1


def test_the_coverage_command_reports(tmp_path, capsys) -> None:
    """The coverage command reports the covered techniques."""
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "clean.yml").write_text(RULE, encoding="utf-8")
    techniques = tmp_path / "techniques.json"
    techniques.write_text(json.dumps(["T1059", "T1112"]), encoding="utf-8")
    assert main(["coverage", "--rules", str(rules), "--techniques", str(techniques)]) == EXIT_OK
    assert "MISSING  T1059" in capsys.readouterr().out


def test_a_missing_technique_list_is_a_usage_error(tmp_path, capsys) -> None:
    """A technique list that does not exist is a usage error."""
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "clean.yml").write_text(RULE, encoding="utf-8")
    code = main(["coverage", "--rules", str(rules), "--techniques", str(tmp_path / "nope.json")])
    assert code == EXIT_USAGE
    assert "could not read technique list" in capsys.readouterr().err


def test_the_demo_runs(capsys) -> None:
    """The demo runs all three stages and succeeds."""
    assert main(["demo"]) == EXIT_OK
    output = capsys.readouterr().out
    assert "=== conformance ===" in output
    assert "=== lint ===" in output
    assert "=== coverage ===" in output
    assert "MISSING  T1112" in output
