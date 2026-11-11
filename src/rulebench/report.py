"""JSON, text and JUnit XML report emitters."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any
from xml.sax.saxutils import escape

from rulebench.evaluate import CaseResult
from rulebench.lint import LintFinding

__all__ = [
    "coverage_to_json",
    "coverage_to_text",
    "lint_to_json",
    "lint_to_text",
    "to_json",
    "to_junit",
    "to_text",
]


def to_json(results: Sequence[CaseResult], meta: dict[str, Any] | None = None) -> str:
    """Render conformance results as JSON.

    :param results: The case results.
    :param meta: Extra metadata to merge into the document.
    :returns: Pretty-printed JSON.
    """
    document: dict[str, Any] = {
        "tool": "rulebench",
        "summary": {
            "cases": len(results),
            "passed": sum(1 for result in results if result.passed),
            "failed": sum(1 for result in results if not result.passed),
        },
        "cases": [result.to_dict() for result in results],
    }
    if meta:
        document["summary"].update(meta)
    return json.dumps(document, indent=2, default=str)


def to_text(results: Sequence[CaseResult], meta: dict[str, Any] | None = None) -> str:
    """Render conformance results as plain text.

    :param results: The case results.
    :param meta: Extra metadata rendered next to the summary line.
    :returns: The text report.
    """
    passed = sum(1 for result in results if result.passed)
    failed = len(results) - passed
    header = f"rulebench — {len(results)} case(s), {passed} passed, {failed} failed"
    if meta:
        extras = ", ".join(f"{key}={value}" for key, value in meta.items())
        header = f"{header} ({extras})"
    lines = [header, ""]
    if not results:
        lines.append("  no cases were run")
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        lines.append(f"  {status}  {result.rule}  {result.name}")
        if not result.passed:
            lines.append(f"          expected {result.expected}, got {result.actual}")
            if result.message:
                lines.append(f"          {result.message}")
    return "\n".join(lines) + "\n"


def to_junit(results: Sequence[CaseResult], meta: dict[str, Any] | None = None) -> str:
    """Render conformance results as a JUnit XML document.

    :param results: The case results.
    :param meta: Extra metadata, rendered as a properties block.
    :returns: The XML document.
    """
    failures = sum(1 for result in results if not result.passed)
    lines = ['<?xml version="1.0" encoding="UTF-8"?>']
    lines.append(
        f'<testsuites name="rulebench" tests="{len(results)}" failures="{failures}" errors="0">'
    )
    lines.append(
        f'  <testsuite name="rulebench conformance" tests="{len(results)}" '
        f'failures="{failures}" errors="0">'
    )
    if meta:
        lines.append("    <properties>")
        for key, value in meta.items():
            if isinstance(value, (list, tuple)):
                value = ", ".join(str(item) for item in value)
            lines.append(
                f'      <property name="{escape(str(key))}" value="{escape(str(value))}"/>'
            )
        lines.append("    </properties>")
    for result in results:
        classname = result.rule or "rulebench"
        lines.append(
            f'    <testcase name="{escape(result.name)}" classname="{escape(classname)}">'
        )
        if not result.passed:
            message = f"expected {result.expected}, got {result.actual}"
            detail = result.message or message
            lines.append(f'      <failure message="{escape(message)}">{escape(detail)}</failure>')
        lines.append("    </testcase>")
    lines.append("  </testsuite>")
    lines.append("</testsuites>")
    return "\n".join(lines)


def lint_to_json(findings: Sequence[LintFinding], meta: dict[str, Any] | None = None) -> str:
    """Render lint findings as JSON.

    :param findings: The findings.
    :param meta: Extra metadata to merge into the document.
    :returns: Pretty-printed JSON.
    """
    document: dict[str, Any] = {
        "tool": "rulebench",
        "summary": {
            "findings": len(findings),
            "errors": sum(1 for finding in findings if finding.severity == "error"),
            "warnings": sum(1 for finding in findings if finding.severity == "warning"),
        },
        "findings": [finding.to_dict() for finding in findings],
    }
    if meta:
        document["summary"].update(meta)
    return json.dumps(document, indent=2, default=str)


def lint_to_text(findings: Sequence[LintFinding]) -> str:
    """Render lint findings as plain text.

    :param findings: The findings.
    :returns: The text report.
    """
    if not findings:
        return "rulebench lint — no findings\n"
    lines = [f"rulebench lint — {len(findings)} finding(s)"]
    for finding in findings:
        lines.append(f"  {finding.severity.upper():7} {finding.code:24} {finding.path}")
        lines.append(f"          {finding.message}")
    return "\n".join(lines) + "\n"


def coverage_to_json(report: dict[str, Any], meta: dict[str, Any] | None = None) -> str:
    """Render a coverage report as JSON.

    :param report: The coverage report.
    :param meta: Extra metadata to merge into the document.
    :returns: Pretty-printed JSON.
    """
    document: dict[str, Any] = {"tool": "rulebench", "coverage": report}
    if meta:
        document.update(meta)
    return json.dumps(document, indent=2, default=str)


def coverage_to_text(report: dict[str, Any]) -> str:
    """Render a coverage report as plain text.

    :param report: The coverage report.
    :returns: The text report.
    """
    expected = report.get("expected", [])
    covered = report.get("covered", [])
    missing = report.get("missing", [])
    lines = [
        f"rulebench coverage — {len(covered)}/{len(expected)} techniques covered "
        f"({report.get('coverageRatio', 0) * 100:.1f}%)"
    ]
    for technique in missing:
        lines.append(f"  MISSING  {technique}")
    if not missing:
        lines.append("  every expected technique has at least one rule")
    return "\n".join(lines) + "\n"
