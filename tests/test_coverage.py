"""Tests for the ATT&CK coverage analysis."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from rulebench.coverage import coverage_report, extract_techniques, load_techniques
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


def test_extract_techniques_reads_a_tag() -> None:
    """A tag yields its technique identifier."""
    assert extract_techniques(["attack.t1059"]) == {"T1059"}


def test_extract_techniques_reads_a_sub_technique() -> None:
    """A sub-technique tag yields both identifiers."""
    assert extract_techniques(["attack.t1059.001"]) == {"T1059", "T1059.001"}


def test_extract_techniques_ignores_other_tags() -> None:
    """Tags that are not ATT&CK identifiers are ignored."""
    assert extract_techniques(["attack.execution", "car.2013-05-004", "t1059"]) == set()


def test_load_techniques_reads_a_list(tmp_path) -> None:
    """A JSON list of identifiers is accepted."""
    path = tmp_path / "techniques.json"
    path.write_text(json.dumps(["T1059", "t1105"]), encoding="utf-8")
    assert load_techniques(path) == {"T1059", "T1105"}


def test_load_techniques_reads_a_techniques_key(tmp_path) -> None:
    """A JSON object with a techniques key is accepted."""
    path = tmp_path / "techniques.json"
    path.write_text(json.dumps({"techniques": ["T1059"]}), encoding="utf-8")
    assert load_techniques(path) == {"T1059"}


def test_load_techniques_reads_a_list_of_objects(tmp_path) -> None:
    """A list of objects carrying an identifier is accepted."""
    path = tmp_path / "techniques.json"
    path.write_text(json.dumps([{"id": "T1059"}, {"technique": "T1105"}]), encoding="utf-8")
    assert load_techniques(path) == {"T1059", "T1105"}


def test_load_techniques_rejects_a_missing_file(tmp_path) -> None:
    """A missing technique list is an error."""
    with pytest.raises(ValueError):
        load_techniques(tmp_path / "nope.json")


def test_load_techniques_rejects_invalid_json(tmp_path) -> None:
    """A technique list that is not JSON is an error."""
    path = tmp_path / "techniques.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        load_techniques(path)


def test_load_techniques_rejects_an_unsupported_shape(tmp_path) -> None:
    """A technique list that is not a list is an error."""
    path = tmp_path / "techniques.json"
    path.write_text(json.dumps({"techniques": "T1059"}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_techniques(path)


def test_coverage_report_lists_what_is_covered(tmp_path) -> None:
    """The report separates covered from missing techniques."""
    body = (
        "title: Covered\n"
        "logsource:\n  product: windows\n"
        "tags:\n  - attack.t1059.001\n"
        "detection:\n  selection:\n    a: b\n  condition: selection\n"
    )
    rule = make_rule(tmp_path, "covered", body)
    report = coverage_report([rule], ["T1059", "T1059.001", "T1112"])
    assert report["expected"] == ["T1059", "T1059.001", "T1112"]
    assert report["covered"] == ["T1059", "T1059.001"]
    assert report["missing"] == ["T1112"]
    assert report["coverageRatio"] == pytest.approx(2 / 3, abs=1e-4)
    assert report["rules"]["T1059"] == [rule.identifier]


def test_coverage_report_lists_extra_techniques(tmp_path) -> None:
    """A technique nobody expected is reported as extra."""
    body = (
        "title: Extra\n"
        "logsource:\n  product: windows\n"
        "tags:\n  - attack.t9999\n"
        "detection:\n  selection:\n    a: b\n  condition: selection\n"
    )
    rule = make_rule(tmp_path, "extra", body)
    report = coverage_report([rule], ["T1059"])
    assert report["extra"] == ["T9999"]
    assert report["missing"] == ["T1059"]


def test_coverage_of_an_empty_expectation_is_zero(tmp_path) -> None:
    """With nothing expected, nothing is covered."""
    report = coverage_report([], [])
    assert report["coverageRatio"] == 0.0
    assert report["covered"] == []
