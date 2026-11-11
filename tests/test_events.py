"""Tests for the event corpus loader and field access."""

from __future__ import annotations

import json

import pytest

from rulebench.events import Event, EventLoadError, event_from_mapping, load_events


def test_get_finds_an_exact_field() -> None:
    """An exact field name is found."""
    event = Event(fields={"Image": "cmd.exe"})
    assert event.get("Image") == (True, "cmd.exe")


def test_get_falls_back_to_a_case_insensitive_match() -> None:
    """A field name that differs only in case is still found."""
    event = Event(fields={"image": "cmd.exe"})
    assert event.get("Image") == (True, "cmd.exe")


def test_get_reports_a_missing_field() -> None:
    """A field that is not present is reported as missing."""
    event = Event(fields={"Image": "cmd.exe"})
    assert event.get("CommandLine") == (False, None)


def test_texts_renders_every_value_kind() -> None:
    """Every field value becomes a searchable string."""
    event = Event(fields={"a": "text", "b": None, "c": {"x": 1}, "d": [1, 2], "e": 7})
    texts = event.texts()
    assert "text" in texts
    assert "" in texts
    assert '{"x": 1}' in texts
    assert "[1, 2]" in texts
    assert "7" in texts


def test_event_from_mapping_flattens_nested_objects() -> None:
    """Nested objects are addressed with dotted paths."""
    event = event_from_mapping({"process": {"name": "cmd.exe"}, "id": 1})
    assert event.get("process.name") == (True, "cmd.exe")
    assert event.get("id") == (True, 1)


def test_event_from_mapping_keeps_a_name() -> None:
    """An event can carry a name."""
    event = event_from_mapping({"a": "b"}, name="first")
    assert event.name == "first"


def test_load_events_reads_a_bare_list(tmp_path) -> None:
    """A bare JSON list of events is accepted."""
    path = tmp_path / "events.json"
    path.write_text(json.dumps([{"CommandLine": "whoami"}]), encoding="utf-8")
    events = load_events(path)
    assert len(events) == 1
    assert events[0].get("CommandLine") == (True, "whoami")


def test_load_events_reads_named_events(tmp_path) -> None:
    """A list of named event objects is accepted."""
    path = tmp_path / "events.json"
    body = json.dumps({"events": [{"name": "first", "event": {"a": "b"}}]})
    path.write_text(body, encoding="utf-8")
    events = load_events(path)
    assert events[0].name == "first"
    assert events[0].get("a") == (True, "b")


def test_load_events_reads_an_unnamed_list(tmp_path) -> None:
    """A list of named event objects without an events key is accepted."""
    path = tmp_path / "events.json"
    path.write_text(json.dumps([{"name": "first", "event": {"a": "b"}}]), encoding="utf-8")
    events = load_events(path)
    assert events[0].name == "first"


def test_load_events_rejects_a_missing_file(tmp_path) -> None:
    """A missing corpus is an error."""
    with pytest.raises(EventLoadError):
        load_events(tmp_path / "nope.json")


def test_load_events_rejects_invalid_json(tmp_path) -> None:
    """A corpus that is not JSON is an error."""
    path = tmp_path / "events.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(EventLoadError):
        load_events(path)


def test_load_events_rejects_a_document_without_events(tmp_path) -> None:
    """An object without an events key is an error."""
    path = tmp_path / "events.json"
    path.write_text(json.dumps({"records": []}), encoding="utf-8")
    with pytest.raises(EventLoadError):
        load_events(path)


def test_load_events_rejects_a_non_list_document(tmp_path) -> None:
    """An events value that is not a list is an error."""
    path = tmp_path / "events.json"
    path.write_text(json.dumps({"events": {"a": 1}}), encoding="utf-8")
    with pytest.raises(EventLoadError):
        load_events(path)


def test_load_events_rejects_a_non_object_event(tmp_path) -> None:
    """An event that is not an object is an error."""
    path = tmp_path / "events.json"
    path.write_text(json.dumps(["not an object"]), encoding="utf-8")
    with pytest.raises(EventLoadError):
        load_events(path)
