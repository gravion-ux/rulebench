"""Tests for the report emitters."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ElementTree

from rulebench.evaluate import CaseResult
from rulebench.lint import LintFinding
from rulebench.report import (
    coverage_to_json,
    coverage_to_text,
    lint_to_json,
    lint_to_text,
    to_json,
    to_junit,
    to_text,
)


def results() -> list[CaseResult]:
    """Return one passing and one failing result.

    :returns: The results.
    """
    return [
        CaseResult(
            name="passes",
            rule="process_creation",
            expected="match",
            actual="match",
            passed=True,
            path="rules/process_creation.yml",
        ),
        CaseResult(
            name="fails",
            rule="certutil_download",
            expected="match",
            actual="no-match",
            passed=False,
            message="the rule did not fire",
            path="rules/certutil_download.yml",
        ),
    ]


def test_to_json_summarises_the_results() -> None:
    """The JSON report holds a summary and the cases."""
    document = json.loads(to_json(results(), {"rules": 4}))
    assert document["tool"] == "rulebench"
    assert document["summary"]["cases"] == 2
    assert document["summary"]["passed"] == 1
    assert document["summary"]["failed"] == 1
    assert document["summary"]["rules"] == 4
    assert len(document["cases"]) == 2


def test_to_text_reports_each_case() -> None:
    """The text report shows the outcome of every case."""
    report = to_text(results())
    assert "2 case(s), 1 passed, 1 failed" in report
    assert "PASS  process_creation  passes" in report
    assert "FAIL  certutil_download  fails" in report
    assert "expected match, got no-match" in report


def test_to_text_handles_an_empty_run() -> None:
    """A run with no cases still produces a report."""
    assert "no cases were run" in to_text([])


def test_to_junit_is_well_formed_xml() -> None:
    """The JUnit report parses as XML."""
    root = ElementTree.fromstring(to_junit(results()))
    assert root.tag == "testsuites"
    assert root.attrib["tests"] == "2"
    assert root.attrib["failures"] == "1"
    cases = root.findall(".//testcase")
    assert len(cases) == 2
    failures = root.findall(".//failure")
    assert len(failures) == 1
    assert "expected match, got no-match" in failures[0].attrib["message"]


def test_to_junit_escapes_the_failure_detail() -> None:
    """A failure detail with markup stays well formed."""
    broken = [
        CaseResult(
            name="escaped",
            rule="rule<one>",
            expected="match",
            actual="no-match",
            passed=False,
            message="a < b & c > d",
        )
    ]
    root = ElementTree.fromstring(to_junit(broken))
    failure = root.find(".//failure")
    assert failure is not None
    assert failure.text == "a < b & c > d"


def test_to_junit_carries_the_metadata() -> None:
    """Extra metadata becomes a properties block."""
    root = ElementTree.fromstring(to_junit(results(), {"rules": 4}))
    properties = root.findall(".//property")
    assert any(item.attrib["name"] == "rules" for item in properties)


def test_lint_to_json_summarises_the_findings() -> None:
    """The JSON lint report counts errors and warnings."""
    findings = [
        LintFinding(code="duplicate-id", severity="error", message="m", path="p", rule="r"),
        LintFinding(code="duplicate-title", severity="warning", message="m", path="p", rule="r"),
    ]
    document = json.loads(lint_to_json(findings))
    assert document["summary"]["findings"] == 2
    assert document["summary"]["errors"] == 1
    assert document["summary"]["warnings"] == 1


def test_lint_to_text_lists_the_findings() -> None:
    """The text lint report shows every finding."""
    findings = [
        LintFinding(code="duplicate-id", severity="error", message="shared id", path="p.yml", rule="r")
    ]
    report = lint_to_text(findings)
    assert "1 finding(s)" in report
    assert "ERROR" in report
    assert "duplicate-id" in report
    assert "shared id" in report


def test_lint_to_text_handles_no_findings() -> None:
    """A clean run says so."""
    assert "no findings" in lint_to_text([])


def test_coverage_to_json_wraps_the_report() -> None:
    """The JSON coverage report holds the coverage document."""
    report = {"expected": ["T1059"], "covered": [], "missing": ["T1059"], "extra": [], "coverageRatio": 0.0}
    document = json.loads(coverage_to_json(report))
    assert document["tool"] == "rulebench"
    assert document["coverage"]["missing"] == ["T1059"]


def test_coverage_to_text_lists_the_missing_techniques() -> None:
    """The text coverage report names what is missing."""
    report = {
        "expected": ["T1059", "T1112"],
        "covered": ["T1059"],
        "missing": ["T1112"],
        "extra": [],
        "coverageRatio": 0.5,
    }
    text = coverage_to_text(report)
    assert "1/2 techniques covered" in text
    assert "MISSING  T1112" in text
