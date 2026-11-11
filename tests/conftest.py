"""Shared test helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from rulebench.events import Event


def write_rule(directory: Path, name: str, body: str) -> Path:
    """Write a Sigma rule file into a directory.

    :param directory: The directory to write into.
    :param name: The file stem.
    :param body: The YAML body.
    :returns: The path of the written file.
    """
    path = Path(directory) / f"{name}.yml"
    path.write_text(body, encoding="utf-8")
    return path


def write_cases(directory: Path, name: str, body: str) -> Path:
    """Write a conformance case file into a directory.

    :param directory: The directory to write into.
    :param name: The file stem.
    :param body: The YAML body.
    :returns: The path of the written file.
    """
    path = Path(directory) / f"{name}.yaml"
    path.write_text(body, encoding="utf-8")
    return path


@pytest.fixture
def windows_event() -> Event:
    """Return a Windows process creation event.

    :returns: The event.
    """
    return Event(
        fields={
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
            "User": "CONTOSO\\analyst",
        }
    )
