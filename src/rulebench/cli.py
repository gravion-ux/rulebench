"""The rulebench command line interface.

Four subcommands:

``test``
    Run conformance cases against a directory of Sigma rules.
``lint``
    Report rules that are wrong, untrustworthy or duplicated.
``coverage``
    Report which ATT&CK techniques the rules cover.
``demo``
    Run all three against a small built-in corpus so the tool can be seen
    working without a checkout.

Exit codes are uniform: ``0`` success, ``1`` findings or failing cases, ``2``
a usage or input error.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from rulebench.coverage import coverage_report, load_techniques
from rulebench.evaluate import CaseError, load_cases, run_cases, untested_rules
from rulebench.events import EventLoadError, load_events
from rulebench.lint import ERROR, lint_rules
from rulebench.report import (
    coverage_to_json,
    coverage_to_text,
    lint_to_json,
    lint_to_text,
    to_json,
    to_junit,
    to_text,
)
from rulebench.rules import RuleError, RuleParseError, load_rules_with_errors

__all__ = ["main"]

#: Everything went as expected.
EXIT_OK = 0

#: Cases failed, or the linter found an error.
EXIT_FINDINGS = 1

#: The command line or an input file was wrong.
EXIT_USAGE = 2

_DEMO_RULE = """\
title: Suspicious PowerShell Encoded Command
id: 8f1b2c44-0d3e-4a51-9c77-2b6e5d4a1c90
status: test
description: Detects PowerShell invoked with an encoded command payload.
author: rulebench demo
level: high
logsource:
  product: windows
  category: process_creation
tags:
  - attack.t1059.001
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - '-enc'
      - '-EncodedCommand'
  condition: selection
"""

_DEMO_RULE_WITHOUT_LOGSOURCE = """\
title: Demo Rule Without A Logsource
id: 2c9d5e70-8b41-4f2a-9d63-7e0c3b5a2f18
status: test
description: A rule that omits its logsource so the linter has something to report.
author: rulebench demo
level: low
detection:
  keywords:
    - 'mimikatz'
  condition: keywords
"""

_DEMO_BROKEN_RULE = """\
title: Broken Demo Rule
id: 6b1f0a92-4d7e-4c83-b5a1-9e2d8c6f0a37
detection:
  selection:
    EventID: 4624
  condition: selection
  status: [this is not valid yaml
"""

_DEMO_CASES = """\
cases:
  - name: encoded command matches
    rule: process_creation
    expect: match
    event:
      Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
      CommandLine: 'powershell.exe -enc SQBFAFgA'
  - name: plain command does not match
    rule: process_creation
    expect: no-match
    event:
      Image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
      CommandLine: 'powershell.exe Get-Process'
  - name: broken rule is rejected
    rule: broken_rule
    expect: error
"""

_DEMO_EVENTS = {
    "events": [
        {
            "name": "encoded-powershell",
            "event": {
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -enc SQBFAFgA",
            },
        },
        {
            "name": "plain-powershell",
            "event": {
                "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe Get-Process",
            },
        },
    ]
}

_DEMO_TECHNIQUES = {"techniques": ["T1059", "T1059.001", "T1112"]}


def _emit(payload: str, output: str | None) -> None:
    """Print a report or write it to a file.

    :param payload: The rendered report.
    :param output: The destination path, or None to print to stdout.
    """
    if output:
        Path(output).write_text(payload, encoding="utf-8")
        return
    sys.stdout.write(payload)


def _load_corpus(rules_dir: str) -> tuple[list[Any], list[RuleError]]:
    """Load the rules of a directory.

    :param rules_dir: The rules directory.
    :returns: The rules that loaded and the errors for the ones that did not.
    """
    return load_rules_with_errors(rules_dir)


def _uncovered_parse_errors(
    errors: Sequence[RuleError],
    cases: Sequence[Any],
    results: Sequence[Any],
) -> list[RuleError]:
    """Find the broken rules that no case accounted for.

    A rule that fails to parse is only acceptable when a conformance case
    declares ``expect: error`` for it, because that documents the breakage as
    intended behaviour rather than an accident.

    :param errors: The rules that failed to parse.
    :param cases: The cases that were run.
    :param results: The results of the run.
    :returns: The broken rules that no case covered.
    """
    covered: set[str] = set()
    for case, result in zip(cases, results, strict=True):
        if result.passed and case.expect == "error":
            covered.add(case.rule.casefold())
    uncovered: list[RuleError] = []
    for error in errors:
        if error.path.stem.casefold() not in covered:
            uncovered.append(error)
    return uncovered


def cmd_test(args: argparse.Namespace) -> int:
    """Run the conformance cases.

    :param args: The parsed arguments.
    :returns: The process exit code.
    """
    try:
        rules, errors = _load_corpus(args.rules)
    except RuleParseError as error:
        sys.stderr.write(f"rulebench: {error}\n")
        return EXIT_USAGE

    cases = []
    for path in args.cases:
        try:
            cases.extend(load_cases(path))
        except CaseError as error:
            sys.stderr.write(f"rulebench: {error}\n")
            return EXIT_USAGE

    events = []
    for path in args.events or []:
        try:
            events.extend(load_events(path))
        except EventLoadError as error:
            sys.stderr.write(f"rulebench: {error}\n")
            return EXIT_USAGE

    results = run_cases(cases, rules, errors, events)
    failed = sum(1 for result in results if not result.passed)
    uncovered = _uncovered_parse_errors(errors, cases, results)
    untested = untested_rules(cases, rules)

    meta: dict[str, Any] = {
        "rules": len(rules),
        "brokenRules": len(errors),
        "untestedRules": len(untested),
    }
    if args.format == "json":
        payload = to_json(results, meta)
    elif args.format == "junit":
        payload = to_junit(results, meta)
    else:
        payload = to_text(results, meta)
        if untested:
            payload += "\nRules with no conformance case:\n"
            for name in untested:
                payload += f"  - {name}\n"
        if uncovered:
            payload += "\nRules that failed to parse and are not covered by a case:\n"
            for error in uncovered:
                payload += f"  - {error.path}: {error.message}\n"
    _emit(payload, args.output)

    if failed or uncovered:
        return EXIT_FINDINGS
    return EXIT_OK


def cmd_lint(args: argparse.Namespace) -> int:
    """Run the linter.

    :param args: The parsed arguments.
    :returns: The process exit code.
    """
    try:
        rules, errors = _load_corpus(args.rules)
    except RuleParseError as error:
        sys.stderr.write(f"rulebench: {error}\n")
        return EXIT_USAGE

    findings = lint_rules(rules)
    for error in errors:
        sys.stderr.write(f"rulebench: rule did not parse: {error.path}: {error.message}\n")

    meta = {"rules": len(rules), "brokenRules": len(errors)}
    payload = lint_to_json(findings, meta) if args.format == "json" else lint_to_text(findings)
    _emit(payload, args.output)

    if any(finding.severity == ERROR for finding in findings) or errors:
        return EXIT_FINDINGS
    return EXIT_OK


def cmd_coverage(args: argparse.Namespace) -> int:
    """Report the ATT&CK coverage of a rule collection.

    :param args: The parsed arguments.
    :returns: The process exit code.
    """
    try:
        rules, _errors = _load_corpus(args.rules)
    except RuleParseError as error:
        sys.stderr.write(f"rulebench: {error}\n")
        return EXIT_USAGE

    try:
        techniques = load_techniques(args.techniques)
    except ValueError as error:
        sys.stderr.write(f"rulebench: {error}\n")
        return EXIT_USAGE

    report = coverage_report(rules, techniques)
    if args.format == "json":
        payload = coverage_to_json(report, {"rules": len(rules)})
    else:
        payload = coverage_to_text(report)
    _emit(payload, args.output)
    return EXIT_OK


def _write_demo_corpus(root: Path) -> tuple[Path, Path, Path, Path]:
    """Write the demo corpus to disk.

    :param root: The directory to write into.
    :returns: The rules directory, the case file, the event file and the
        technique file.
    """
    rules_dir = root / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / "process_creation.yml").write_text(_DEMO_RULE, encoding="utf-8")
    (rules_dir / "no_logsource.yml").write_text(_DEMO_RULE_WITHOUT_LOGSOURCE, encoding="utf-8")
    (rules_dir / "broken_rule.yml").write_text(_DEMO_BROKEN_RULE, encoding="utf-8")
    cases_file = root / "cases.yml"
    cases_file.write_text(_DEMO_CASES, encoding="utf-8")
    events_file = root / "events.json"
    events_file.write_text(json.dumps(_DEMO_EVENTS, indent=2), encoding="utf-8")
    techniques_file = root / "techniques.json"
    techniques_file.write_text(json.dumps(_DEMO_TECHNIQUES, indent=2), encoding="utf-8")
    return rules_dir, cases_file, events_file, techniques_file


def cmd_demo(args: argparse.Namespace) -> int:
    """Run the tool against a small built-in corpus.

    :param args: The parsed arguments.
    :returns: The process exit code.
    """
    with tempfile.TemporaryDirectory(prefix="rulebench-demo-") as raw:
        root = Path(raw)
        rules_dir, cases_file, events_file, techniques_file = _write_demo_corpus(root)

        sys.stdout.write("=== conformance ===\n")
        test_args = argparse.Namespace(
            rules=str(rules_dir),
            cases=[str(cases_file)],
            events=[str(events_file)],
            format="text",
            output=None,
        )
        test_code = cmd_test(test_args)

        sys.stdout.flush()
        sys.stdout.write("\n=== lint ===\n")
        lint_args = argparse.Namespace(rules=str(rules_dir), format="text", output=None)
        lint_code = cmd_lint(lint_args)

        sys.stdout.flush()
        sys.stdout.write("\n=== coverage ===\n")
        coverage_args = argparse.Namespace(
            rules=str(rules_dir),
            techniques=str(techniques_file),
            format="text",
            output=None,
        )
        coverage_code = cmd_coverage(coverage_args)

        sys.stdout.flush()
        sys.stdout.write("\n=== exit codes ===\n")
        sys.stdout.write(f"  test     {test_code}\n")
        sys.stdout.write(f"  lint     {lint_code}\n")
        sys.stdout.write(f"  coverage {coverage_code}\n")

    # The demo corpus deliberately contains a rule with a missing logsource and a
    # rule that does not parse, so the lint stage is expected to report findings.
    # Only the conformance stage decides whether the demo itself worked.
    return test_code


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser.

    :returns: The parser.
    """
    parser = argparse.ArgumentParser(
        prog="rulebench",
        description="Behavioral conformance harness for Sigma detection rules.",
    )
    parser.add_argument("--version", action="version", version="rulebench 0.1.0")
    subparsers = parser.add_subparsers(dest="command")

    test = subparsers.add_parser("test", help="run conformance cases against Sigma rules")
    test.add_argument("--rules", required=True, help="directory holding the Sigma rules")
    test.add_argument(
        "--cases",
        action="append",
        required=True,
        metavar="FILE",
        help="conformance case file in YAML; may be given more than once",
    )
    test.add_argument(
        "--events",
        action="append",
        metavar="FILE",
        help="event corpus in JSON; may be given more than once",
    )
    test.add_argument(
        "--format",
        choices=("text", "json", "junit"),
        default="text",
        help="report format (default: text)",
    )
    test.add_argument("--output", metavar="FILE", help="write the report to a file")
    test.set_defaults(handler=cmd_test)

    lint = subparsers.add_parser("lint", help="report rules that are wrong or duplicated")
    lint.add_argument("--rules", required=True, help="directory holding the Sigma rules")
    lint.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="report format (default: text)",
    )
    lint.add_argument("--output", metavar="FILE", help="write the report to a file")
    lint.set_defaults(handler=cmd_lint)

    coverage = subparsers.add_parser("coverage", help="report ATT&CK technique coverage")
    coverage.add_argument("--rules", required=True, help="directory holding the Sigma rules")
    coverage.add_argument("--techniques", required=True, help="JSON file listing expected techniques")
    coverage.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="report format (default: text)",
    )
    coverage.add_argument("--output", metavar="FILE", help="write the report to a file")
    coverage.set_defaults(handler=cmd_coverage)

    demo = subparsers.add_parser("demo", help="run the tool against a built-in corpus")
    demo.set_defaults(handler=cmd_demo)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command line interface.

    :param argv: The argument list, or None to use ``sys.argv``.
    :returns: The process exit code.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "handler", None):
        parser.print_help()
        return EXIT_USAGE
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
