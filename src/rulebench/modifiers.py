"""Sigma field modifiers and value matching.

The semantics implemented here follow the Sigma specification v2.1.0
(``SigmaHQ/sigma-specification``): values are case-insensitive by default,
``*`` and ``?`` are wildcards, ``\\`` escapes wildcards and itself, regular
expressions are case-sensitive by default, and modifiers are applied left to
right.
"""

from __future__ import annotations

import base64
import ipaddress
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any

from rulebench.events import Event

__all__ = [
    "KNOWN_MODIFIERS",
    "FieldSpec",
    "ModifierError",
    "UnsupportedModifierError",
    "has_wildcard",
    "match_field",
    "parse_field_spec",
    "wildcard_regex",
]

#: Modifiers that apply to every field type.
GENERIC_MODIFIERS = frozenset({"all", "startswith", "endswith", "contains", "exists", "cased", "neq"})

#: Modifiers that apply to string values only.
STRING_MODIFIERS = frozenset(
    {"windash", "re", "base64", "base64offset", "utf16le", "utf16be", "utf16", "wide"}
)

#: Modifiers that apply to numeric values only.
NUMERIC_MODIFIERS = frozenset({"lt", "lte", "gt", "gte"})

#: Modifiers that apply to date values only.
TIME_MODIFIERS = frozenset({"minute", "hour", "day", "week", "month", "year"})

#: Modifiers that apply to IP values only.
IP_MODIFIERS = frozenset({"cidr"})

#: Modifiers with a specific behaviour.
SPECIFIC_MODIFIERS = frozenset({"expand", "fieldref"})

#: Sub-modifiers that only apply after the ``re`` modifier.
REGEX_SUBMODIFIERS = frozenset({"i", "m", "s"})

#: Every modifier name the specification defines.
KNOWN_MODIFIERS = (
    GENERIC_MODIFIERS
    | STRING_MODIFIERS
    | NUMERIC_MODIFIERS
    | TIME_MODIFIERS
    | IP_MODIFIERS
    | SPECIFIC_MODIFIERS
    | REGEX_SUBMODIFIERS
)

#: The dash-like characters the ``windash`` modifier treats as interchangeable.
WINDASH_CHARACTERS = "-/–—―"

#: An unambiguous decimal literal. Anything else is compared as text.
_DECIMAL_RE = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)")


class ModifierError(ValueError):
    """Raised when a modifier is malformed or applied to an incompatible value."""


class UnsupportedModifierError(ModifierError):
    """Raised when a modifier cannot be evaluated faithfully.

    The Sigma specification requires a tool to reject a rule it cannot evaluate
    faithfully, so this error propagates rather than degrading to a false match.
    """


@dataclass(frozen=True)
class FieldSpec:
    """A field name together with its ordered modifier chain."""

    name: str
    modifiers: tuple[str, ...] = ()

    def has(self, modifier: str) -> bool:
        """Report whether the modifier chain contains a modifier.

        :param modifier: The modifier name to look for.
        :returns: True when the modifier is present.
        """
        return modifier in self.modifiers


def parse_field_spec(text: str) -> FieldSpec:
    """Parse a field specification such as ``Image|endswith``.

    :param text: The raw specification.
    :returns: The parsed specification.
    :raises ModifierError: When the specification is not a string or has an
        empty field name.
    """
    if not isinstance(text, str):
        raise ModifierError(f"field specification must be a string, got {type(text).__name__}")
    parts = text.split("|")
    name = parts[0].strip()
    modifiers = tuple(part.strip() for part in parts[1:] if part.strip())
    if not name:
        raise ModifierError(f"field specification has an empty field name: {text!r}")
    return FieldSpec(name=name, modifiers=modifiers)


@dataclass(frozen=True)
class _Candidate:
    """One way of interpreting a rule value against a field."""

    pattern: str | None
    views: tuple[str, ...] = ("raw",)


@dataclass
class _State:
    """Mutable state accumulated while walking a modifier chain."""

    original: list[Any]
    values: list[_Candidate]
    case_sensitive: bool = False
    regex: bool = False
    regex_flags: int = 0
    windash: bool = False
    mode: str = "equals"
    negated: bool = False
    numeric_op: str | None = None
    cidr: str | None = None
    exists: bool | None = None
    require_all: bool = False
    fieldref: str | None = None
    time_component: str | None = None


def _to_text(value: Any) -> str:
    """Render a value as text.

    :param value: The value to render.
    :returns: The rendered text.
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _normalise(pattern: Any) -> list[Any]:
    """Turn a rule value into a list of values.

    :param pattern: The raw value.
    :returns: A list holding the value or the values.
    """
    if isinstance(pattern, list):
        return list(pattern)
    return [pattern]


def _as_number(text: str) -> float | None:
    """Parse a value as a finite number.

    Only an unambiguous decimal literal counts as a number. Python's ``float``
    would also accept ``1_000``, ``" 12 "`` and ``1e5``, and none of those is a
    number in a Sigma rule, so they are compared as text instead.

    :param text: The text to parse.
    :returns: The number, or None when the text is not numeric.
    """
    if not isinstance(text, str) or not _DECIMAL_RE.fullmatch(text):
        return None
    try:
        number = float(text)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(number):
        return None
    return number


def _field_number(text: str) -> float | None:
    """Parse a field value as a number, ignoring surrounding whitespace.

    A rule value has to be an unambiguous number, but a field value may carry
    padding that came from the log it was read from.

    :param text: The field text to parse.
    :returns: The number, or None when the text is not numeric.
    """
    if not isinstance(text, str):
        return None
    return _as_number(text.strip())


def has_wildcard(pattern: str) -> bool:
    """Report whether a value contains an unescaped wildcard.

    :param pattern: The value to inspect.
    :returns: True when ``*`` or ``?`` appears outside a backslash escape.
    """
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "\\" and index + 1 < len(pattern):
            index += 2
            continue
        if character in "*?":
            return True
        index += 1
    return False


def wildcard_regex(pattern: str) -> str:
    """Translate a Sigma wildcard value into a regular expression.

    ``*`` matches any number of characters, ``?`` matches exactly one, and a
    backslash escapes ``*``, ``?`` and itself.

    :param pattern: The value to translate.
    :returns: The regular expression source.
    """
    parts: list[str] = []
    index = 0
    while index < len(pattern):
        character = pattern[index]
        if character == "\\" and index + 1 < len(pattern):
            following = pattern[index + 1]
            if following in "*?\\":
                parts.append(re.escape(following))
                index += 2
                continue
            parts.append(re.escape(character))
            index += 1
            continue
        if character == "*":
            parts.append(".*")
        elif character == "?":
            parts.append(".")
        else:
            parts.append(re.escape(character))
        index += 1
    return "".join(parts)


def _windash_regex(pattern: str) -> str:
    """Translate a value into a regular expression with interchangeable dashes.

    :param pattern: The value to translate.
    :returns: The regular expression source.
    """
    parts: list[str] = []
    for character in pattern:
        if character in WINDASH_CHARACTERS:
            parts.append(f"[{re.escape(WINDASH_CHARACTERS)}]")
        else:
            parts.append(re.escape(character))
    return "".join(parts)


def _base64_variants(payload: bytes) -> list[str]:
    """Produce the base64 encodings of a value at the three byte offsets.

    :param payload: The raw value bytes.
    :returns: One encoded string per offset.
    """
    encoded = base64.b64encode(payload).decode("ascii")
    padded_one = base64.b64encode(b"\x00" + payload).decode("ascii")
    padded_two = base64.b64encode(b"\x00\x00" + payload).decode("ascii")
    return [encoded, padded_one[2:], padded_two[3:]]


def _utf16_variants(text: str) -> dict[str, str]:
    """Render a value in the three UTF-16 encodings.

    The bytes are decoded as latin-1 so that the result is a plain string that
    can be compared with a field value the same way.

    :param text: The value to encode.
    :returns: A mapping of view name to encoded text.
    """
    return {
        "utf16le": text.encode("utf-16-le").decode("latin-1"),
        "utf16be": text.encode("utf-16-be").decode("latin-1"),
        "utf16": text.encode("utf-16").decode("latin-1"),
    }


def _exists_flag(values: list[Any]) -> bool:
    """Read the boolean flag carried by the ``exists`` modifier.

    A rule file may write the flag as a YAML boolean or as a quoted string, so
    ``true`` and ``false`` are accepted as text. Any other value makes the rule
    impossible to evaluate faithfully, so it is rejected.

    :param values: The rule values the modifier was given.
    :returns: True when the field has to be present.
    :raises ModifierError: When the value is not a boolean.
    """
    if not values:
        raise ModifierError("the 'exists' modifier requires a boolean value")
    value = values[0]
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text == "true":
            return True
        if text == "false":
            return False
    raise ModifierError(
        f"the 'exists' modifier requires a boolean value, got {value!r}"
    )


def _apply_modifier(state: _State, modifier: str) -> None:
    """Apply one modifier to the matching state.

    :param state: The state to update.
    :param modifier: The modifier name.
    :raises UnsupportedModifierError: When the modifier is unknown or cannot
        be evaluated faithfully.
    :raises ModifierError: When the modifier is used incorrectly.
    """
    if modifier == "cased":
        state.case_sensitive = True
    elif modifier == "all":
        state.require_all = True
    elif modifier == "contains":
        state.mode = "contains"
    elif modifier == "startswith":
        state.mode = "startswith"
    elif modifier == "endswith":
        state.mode = "endswith"
    elif modifier == "neq":
        state.negated = True
    elif modifier == "exists":
        state.exists = _exists_flag(state.original)
    elif modifier == "re":
        state.regex = True
    elif modifier in REGEX_SUBMODIFIERS:
        if not state.regex:
            raise ModifierError(f"regex sub-modifier {modifier!r} used without the 're' modifier")
        state.regex_flags |= {
            "i": re.IGNORECASE,
            "m": re.MULTILINE,
            "s": re.DOTALL,
        }[modifier]
    elif modifier == "base64":
        state.values = _transform_base64(state.values)
    elif modifier == "base64offset":
        state.values = _transform_base64offset(state.values)
    elif modifier in {"utf16le", "wide"}:
        state.values = _transform_utf16(state.values, ("raw", "utf16le"))
    elif modifier == "utf16be":
        state.values = _transform_utf16(state.values, ("raw", "utf16be"))
    elif modifier == "utf16":
        state.values = _transform_utf16(state.values, ("raw", "utf16"))
    elif modifier == "windash":
        state.windash = True
        state.values = [
            _Candidate(None, candidate.views) if candidate.pattern is None
            else _Candidate(_windash_regex(candidate.pattern), candidate.views)
            for candidate in state.values
        ]
    elif modifier in NUMERIC_MODIFIERS:
        state.numeric_op = modifier
    elif modifier == "cidr":
        state.cidr = _to_text(state.original[0]) if state.original else ""
    elif modifier == "expand":
        raise UnsupportedModifierError(
            "the 'expand' modifier requires placeholder expansion, which rulebench does not "
            "perform; the rule must be rejected"
        )
    elif modifier == "fieldref":
        state.fieldref = _to_text(state.original[0]) if state.original else ""
    elif modifier in TIME_MODIFIERS:
        state.time_component = modifier
    else:
        raise UnsupportedModifierError(f"unknown field modifier: {modifier!r}")


def _transform_base64(candidates: list[_Candidate]) -> list[_Candidate]:
    """Apply the ``base64`` modifier to the candidates.

    The specification states that the *value* is encoded with Base64, so the
    encoded form is compared against the raw field content.

    :param candidates: The current candidates.
    :returns: The transformed candidates.
    """
    transformed: list[_Candidate] = []
    for candidate in candidates:
        if candidate.pattern is None:
            transformed.append(candidate)
            continue
        encoded = base64.b64encode(candidate.pattern.encode("utf-8")).decode("ascii")
        transformed.append(_Candidate(encoded, ("raw",)))
    return transformed


def _transform_base64offset(candidates: list[_Candidate]) -> list[_Candidate]:
    """Apply the ``base64offset`` modifier to the candidates.

    The specification describes three variants, for the value sitting at an
    offset of zero, one or two bytes inside the encoded string.

    :param candidates: The current candidates.
    :returns: The transformed candidates.
    """
    transformed: list[_Candidate] = []
    for candidate in candidates:
        if candidate.pattern is None:
            transformed.append(candidate)
            continue
        for variant in _base64_variants(candidate.pattern.encode("utf-8")):
            transformed.append(_Candidate(variant, ("raw",)))
    return transformed


def _transform_utf16(candidates: list[_Candidate], views: tuple[str, ...]) -> list[_Candidate]:
    """Apply a UTF-16 modifier to the candidates.

    The specification states that the *value* is transformed into the UTF-16
    encoding, so the encoded form is compared against the raw field content.

    :param candidates: The current candidates.
    :param views: The field views the encoded value may be compared against.
    :returns: The transformed candidates.
    """
    transformed: list[_Candidate] = []
    for candidate in candidates:
        if candidate.pattern is None:
            transformed.append(candidate)
            continue
        encoded = _utf16_variants(candidate.pattern)
        key = "utf16" if "utf16" in views else views[-1]
        transformed.append(_Candidate(encoded[key], ("raw",)))
    return transformed


def _build_views(field_value: Any, candidates: list[_Candidate]) -> dict[str, str]:
    """Build every field view the candidates ask for.

    :param field_value: The raw field value.
    :param candidates: The candidates that will be compared.
    :returns: A mapping of view name to rendered text.
    """
    return {"raw": _to_text(field_value)}


def _casefold(text: str, case_sensitive: bool) -> str:
    """Fold a string for comparison.

    :param text: The text to fold.
    :param case_sensitive: Whether case must be preserved.
    :returns: The folded text.
    """
    return text if case_sensitive else text.lower()


def _text_equals(state: _State, pattern: str, field_text: str) -> bool:
    """Compare a pattern and a field value for equality.

    :param state: The matching state.
    :param pattern: The pattern text.
    :param field_text: The field text.
    :returns: True when the values are equal.
    """
    if has_wildcard(pattern):
        flags = 0 if state.case_sensitive else re.IGNORECASE
        return re.fullmatch(wildcard_regex(pattern), field_text, flags) is not None
    pattern_number = _as_number(pattern)
    field_number = _field_number(field_text)
    if pattern_number is not None and field_number is not None:
        return pattern_number == field_number
    return _casefold(pattern, state.case_sensitive) == _casefold(field_text, state.case_sensitive)


def _literal_equals(state: _State, left: str, right: str) -> bool:
    """Compare two values as text, without wildcards or numeric semantics.

    The ``fieldref`` modifier compares one field with another. Neither side is
    a rule value there, so a wildcard must not expand and a number must not be
    compared numerically.

    :param state: The matching state.
    :param left: The first value.
    :param right: The second value.
    :returns: True when the values are equal.
    """
    return _casefold(left, state.case_sensitive) == _casefold(right, state.case_sensitive)


def _search_flags(state: _State) -> int:
    """Return the regular expression flags for a comparison.

    :param state: The matching state.
    :returns: The flags.
    """
    return 0 if state.case_sensitive else re.IGNORECASE


def _contains_matches(state: _State, pattern: str, field_text: str) -> bool:
    """Check whether a field contains a value.

    :param state: The matching state.
    :param pattern: The value pattern.
    :param field_text: The field content.
    :returns: True when the field contains the value.
    """
    if has_wildcard(pattern):
        return re.search(wildcard_regex(pattern), field_text, _search_flags(state)) is not None
    return _casefold(pattern, state.case_sensitive) in _casefold(field_text, state.case_sensitive)


def _startswith_matches(state: _State, pattern: str, field_text: str) -> bool:
    """Check whether a field starts with a value.

    :param state: The matching state.
    :param pattern: The value pattern.
    :param field_text: The field content.
    :returns: True when the field starts with the value.
    """
    if has_wildcard(pattern):
        return re.match(wildcard_regex(pattern), field_text, _search_flags(state)) is not None
    return _casefold(field_text, state.case_sensitive).startswith(
        _casefold(pattern, state.case_sensitive)
    )


def _endswith_matches(state: _State, pattern: str, field_text: str) -> bool:
    """Check whether a field ends with a value.

    :param state: The matching state.
    :param pattern: The value pattern.
    :param field_text: The field content.
    :returns: True when the field ends with the value.
    """
    if has_wildcard(pattern):
        expression = re.compile(wildcard_regex(pattern) + r"\Z", _search_flags(state))
        return expression.search(field_text) is not None
    return _casefold(field_text, state.case_sensitive).endswith(
        _casefold(pattern, state.case_sensitive)
    )


def _windash_matches(state: _State, pattern: str, field_text: str, mode: str) -> bool:
    """Check a value whose dash characters are interchangeable.

    :param state: The matching state.
    :param pattern: The dash-insensitive regular expression.
    :param field_text: The field content.
    :param mode: The comparison mode.
    :returns: True when the field satisfies the value.
    """
    flags = _search_flags(state)
    expression = re.compile(pattern, flags)
    if mode == "contains":
        return expression.search(field_text) is not None
    if mode == "startswith":
        return expression.match(field_text) is not None
    if mode == "endswith":
        anchored = re.compile(pattern + r"\Z", flags)
        return anchored.search(field_text) is not None
    return expression.fullmatch(field_text) is not None


def _regex_matches(state: _State, pattern: str, field_text: str) -> bool:
    """Match a regular expression against a field value.

    :param state: The matching state.
    :param pattern: The regular expression source.
    :param field_text: The field text.
    :returns: True when the expression matches.
    :raises ModifierError: When the expression does not compile.
    """
    try:
        compiled = re.compile(pattern, state.regex_flags)
    except re.error as error:
        raise ModifierError(f"invalid regular expression {pattern!r}: {error}") from error
    return compiled.search(field_text) is not None


def _numeric_matches(operation: str, pattern: str, field_text: str) -> bool:
    """Compare a field value against a number.

    :param operation: One of ``lt``, ``lte``, ``gt`` or ``gte``.
    :param pattern: The numeric pattern.
    :param field_text: The field text.
    :returns: True when the comparison holds.
    """
    pattern_number = _as_number(pattern)
    field_number = _field_number(field_text)
    if pattern_number is None or field_number is None:
        return False
    if operation == "lt":
        return field_number < pattern_number
    if operation == "lte":
        return field_number <= pattern_number
    if operation == "gt":
        return field_number > pattern_number
    if operation == "gte":
        return field_number >= pattern_number
    return False


def _cidr_matches(cidr: str, field_text: str) -> bool:
    """Test whether an address falls inside a CIDR range.

    :param cidr: The CIDR range.
    :param field_text: The field text holding an address.
    :returns: True when the address is inside the range.
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        address = ipaddress.ip_address(field_text.strip())
    except ValueError:
        return False
    return address in network


def _coerce_datetime(value: Any) -> datetime | None:
    """Coerce a value into a datetime.

    :param value: The value to coerce.
    :returns: The datetime, or None when the value is not a date.
    """
    if isinstance(value, datetime):
        return value
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day)
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            return None
    return None


def _time_matches(component: str, pattern: str, field_value: Any) -> bool:
    """Compare one component of a date against a number.

    The field value is used as it was read from the event, because a timestamp
    may be an epoch number and rendering it as text first would lose that.

    :param component: The date component to extract.
    :param pattern: The expected value.
    :param field_value: The field value holding a date.
    :returns: True when the component matches.
    """
    moment = _coerce_datetime(field_value)
    if moment is None:
        return False
    expected = _as_number(pattern)
    if expected is None:
        return False
    actual = {
        "minute": moment.minute,
        "hour": moment.hour,
        "day": moment.day,
        "week": moment.isocalendar()[1],
        "month": moment.month,
        "year": moment.year,
    }[component]
    return int(actual) == int(expected)


def _candidate_matches(
    state: _State,
    candidate: _Candidate,
    views: Mapping[str, str],
    field_value: Any,
) -> bool:
    """Test one candidate against a field value.

    :param state: The matching state.
    :param candidate: The candidate to test.
    :param views: The rendered field views.
    :param field_value: The field value as it was read from the event.
    :returns: True when the candidate matches.
    """
    if candidate.pattern is None:
        return views.get("raw", "") == ""
    effective_mode = state.mode
    for kind in candidate.views:
        field_text = views.get(kind)
        if field_text is None:
            continue
        if state.regex:
            if _regex_matches(state, candidate.pattern, field_text):
                return True
        elif state.windash:
            if _windash_matches(state, candidate.pattern, field_text, effective_mode):
                return True
        elif state.numeric_op is not None:
            if _numeric_matches(state.numeric_op, candidate.pattern, field_text):
                return True
        elif state.cidr is not None:
            if _cidr_matches(state.cidr, field_text):
                return True
        elif state.time_component is not None:
            if _time_matches(state.time_component, candidate.pattern, field_value):
                return True
        else:
            if effective_mode == "contains":
                if _contains_matches(state, candidate.pattern, field_text):
                    return True
            elif effective_mode == "startswith":
                if _startswith_matches(state, candidate.pattern, field_text):
                    return True
            elif effective_mode == "endswith":
                if _endswith_matches(state, candidate.pattern, field_text):
                    return True
            elif _text_equals(state, candidate.pattern, field_text):
                return True
    return False


def match_field(event: Event, spec: FieldSpec, pattern: Any) -> bool:
    """Test whether a field of an event satisfies a rule value.

    :param event: The event to test.
    :param spec: The parsed field specification.
    :param pattern: The raw rule value.
    :returns: True when the field satisfies the value.
    :raises UnsupportedModifierError: When the rule uses a modifier that cannot
        be evaluated faithfully.
    :raises ModifierError: When a modifier is malformed.
    """
    original = _normalise(pattern)
    state = _State(
        original=original,
        values=[
            _Candidate(None) if value is None else _Candidate(_to_text(value))
            for value in original
        ],
    )
    for modifier in spec.modifiers:
        _apply_modifier(state, modifier)

    if state.exists is not None:
        found, _ = event.get(spec.name)
        return found == state.exists

    found, field_value = event.get(spec.name)
    if not found:
        return False

    if state.fieldref is not None:
        reference_found, reference_value = event.get(state.fieldref)
        if not reference_found:
            return False
        equal = _literal_equals(state, _to_text(field_value), _to_text(reference_value))
        return not equal if state.negated else equal

    views = _build_views(field_value, state.values)

    if state.negated:
        # The field must not satisfy any of the specified values.
        return not any(
            _candidate_matches(state, candidate, views, field_value)
            for candidate in state.values
        )

    results = [
        _candidate_matches(state, candidate, views, field_value)
        for candidate in state.values
    ]
    if state.require_all:
        return all(results)
    return any(results)
