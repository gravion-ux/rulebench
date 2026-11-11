"""Event corpus loading and field access.

A Sigma event is a flat mapping of field names to values. Nested mappings are
flattened with dotted paths so that a rule can address ``a.b`` style fields.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = ["Event", "EventLoadError", "load_events", "event_from_mapping"]


class EventLoadError(ValueError):
    """Raised when an event corpus file cannot be understood."""


@dataclass(frozen=True)
class Event:
    """A single log event."""

    fields: Mapping[str, Any]
    name: str | None = None

    def get(self, field: str) -> tuple[bool, Any]:
        """Look up a field.

        The lookup is exact first and case-insensitive second, because Sigma
        field names are written in the case the log source uses but log
        pipelines are not always consistent about it.

        :param field: The field name to look up.
        :returns: A ``(found, value)`` pair.
        """
        if field in self.fields:
            return True, self.fields[field]
        lowered = field.lower()
        for key, value in self.fields.items():
            if isinstance(key, str) and key.lower() == lowered:
                return True, value
        return False, None

    def texts(self) -> list[str]:
        """Return every field value rendered as a searchable string.

        :returns: One string per field, in insertion order.
        """
        rendered = []
        for value in self.fields.values():
            if isinstance(value, str):
                rendered.append(value)
            elif value is None:
                rendered.append("")
            elif isinstance(value, (Mapping, list, tuple)):
                rendered.append(json.dumps(value, sort_keys=True, default=str))
            else:
                rendered.append(str(value))
        return rendered

    def to_dict(self) -> dict[str, Any]:
        """Return the event as a plain dictionary."""
        return dict(self.fields)


def _flatten(mapping: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    flattened: dict[str, Any] = {}
    for key, value in mapping.items():
        name = f"{prefix}{key}"
        if isinstance(value, Mapping):
            flattened.update(_flatten(value, f"{name}."))
        else:
            flattened[name] = value
    return flattened


def event_from_mapping(mapping: Mapping[str, Any], name: str | None = None) -> Event:
    """Build an event from a mapping, flattening nested dictionaries.

    :param mapping: The raw event mapping.
    :param name: An optional name for the event.
    :returns: The constructed event.
    """
    return Event(fields=_flatten(mapping), name=name)


def load_events(path: str | Path) -> list[Event]:
    """Load an event corpus from a JSON file.

    Accepted shapes are a bare list of events, a list of ``{"name", "event"}``
    objects, and an object with an ``events`` key holding either of those.

    :param path: Path to the JSON corpus.
    :returns: The loaded events.
    :raises EventLoadError: When the file is missing, malformed or has an
        unsupported shape.
    """
    target = Path(path)
    try:
        raw = target.read_text(encoding="utf-8")
    except OSError as error:
        raise EventLoadError(f"could not read event corpus {target}: {error}") from error
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as error:
        raise EventLoadError(f"event corpus {target} is not valid JSON: {error}") from error

    if isinstance(document, Mapping):
        if "events" not in document:
            raise EventLoadError(f"event corpus {target} has no 'events' key")
        document = document["events"]

    if not isinstance(document, list):
        raise EventLoadError(f"event corpus {target} must contain a list of events")

    events: list[Event] = []
    for index, item in enumerate(document):
        if not isinstance(item, Mapping):
            raise EventLoadError(f"event {index} in {target} is not an object")
        if "event" in item and isinstance(item["event"], Mapping):
            events.append(event_from_mapping(item["event"], name=item.get("name")))
        else:
            events.append(event_from_mapping(item, name=item.get("name")))
    return events
