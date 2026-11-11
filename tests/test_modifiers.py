"""Tests for the field modifiers and value matching."""

from __future__ import annotations

import base64

import pytest

from rulebench.events import Event
from rulebench.modifiers import (
    ModifierError,
    UnsupportedModifierError,
    has_wildcard,
    match_field,
    parse_field_spec,
    wildcard_regex,
)


def event_with(**fields: object) -> Event:
    """Build an event from keyword arguments.

    :param fields: The field values.
    :returns: The event.
    """
    return Event(fields=fields)


def test_parse_field_spec_reads_a_plain_field() -> None:
    """A field without modifiers parses to an empty chain."""
    spec = parse_field_spec("Image")
    assert spec.name == "Image"
    assert spec.modifiers == ()
    assert spec.has("endswith") is False


def test_parse_field_spec_reads_a_modifier_chain() -> None:
    """Modifiers are kept in the order they were written."""
    spec = parse_field_spec("CommandLine|base64|contains")
    assert spec.name == "CommandLine"
    assert spec.modifiers == ("base64", "contains")
    assert spec.has("contains") is True


def test_parse_field_spec_rejects_an_empty_field_name() -> None:
    """A specification with no field name is an error."""
    with pytest.raises(ModifierError):
        parse_field_spec("|endswith")


def test_parse_field_spec_rejects_a_non_string() -> None:
    """A specification that is not a string is an error."""
    with pytest.raises(ModifierError):
        parse_field_spec(42)


def test_has_wildcard_ignores_escaped_characters() -> None:
    """An escaped wildcard is a literal character."""
    assert has_wildcard("a*b") is True
    assert has_wildcard("a?b") is True
    assert has_wildcard(r"a\*b") is False
    assert has_wildcard(r"a\\*b") is True


def test_wildcard_regex_translates_the_wildcards() -> None:
    """The star and the question mark become regular expressions."""
    assert wildcard_regex("a*b") == "a.*b"
    assert wildcard_regex("a?b") == "a.b"
    assert wildcard_regex(r"a\*b") == r"a\*b"


def test_equality_is_case_insensitive_by_default() -> None:
    """Values are matched without regard to case."""
    event = event_with(Image="cmd.exe")
    assert match_field(event, parse_field_spec("Image"), "CMD.EXE") is True


def test_equality_requires_the_whole_value() -> None:
    """A value without a wildcard is not a substring match."""
    event = event_with(Image="C:\\Windows\\System32\\cmd.exe")
    assert match_field(event, parse_field_spec("Image"), "cmd.exe") is False


def test_a_wildcard_matches_the_whole_value() -> None:
    """A wildcard value is matched against the whole field."""
    event = event_with(Image="powershell.exe")
    assert match_field(event, parse_field_spec("Image"), "*.exe") is True


def test_startswith() -> None:
    """The startswith modifier anchors the value at the front."""
    event = event_with(Image="C:\\Windows\\System32\\cmd.exe")
    spec = parse_field_spec("Image|startswith")
    assert match_field(event, spec, "C:\\Windows") is True
    assert match_field(event, spec, "System32") is False


def test_endswith() -> None:
    """The endswith modifier anchors the value at the end."""
    event = event_with(Image="C:\\Windows\\System32\\cmd.exe")
    spec = parse_field_spec("Image|endswith")
    assert match_field(event, spec, "\\cmd.exe") is True
    assert match_field(event, spec, "\\powershell.exe") is False


def test_contains() -> None:
    """The contains modifier looks for the value anywhere in the field."""
    event = event_with(CommandLine="cmd.exe /c whoami")
    spec = parse_field_spec("CommandLine|contains")
    assert match_field(event, spec, "whoami") is True
    assert match_field(event, spec, "net user") is False


def test_contains_honours_wildcards() -> None:
    """A wildcard inside a contains value still matches."""
    event = event_with(CommandLine="cmd.exe /c whoami")
    spec = parse_field_spec("CommandLine|contains")
    assert match_field(event, spec, "who*ami") is True


def test_cased_makes_the_comparison_case_sensitive() -> None:
    """The cased modifier turns off case folding."""
    event = event_with(Image="CMD.EXE")
    assert match_field(event, parse_field_spec("Image"), "cmd.exe") is True
    assert match_field(event, parse_field_spec("Image|cased"), "cmd.exe") is False
    assert match_field(event, parse_field_spec("Image|cased"), "CMD.EXE") is True


def test_neq_requires_every_value_to_differ() -> None:
    """The neq modifier fails when any listed value matches."""
    event = event_with(Image="cmd.exe")
    spec = parse_field_spec("Image|neq")
    assert match_field(event, spec, "powershell.exe") is True
    assert match_field(event, spec, ["powershell.exe", "cmd.exe"]) is False
    assert match_field(event, spec, ["powershell.exe", "rundll32.exe"]) is True


def test_all_requires_every_value_to_match() -> None:
    """The all modifier turns the value list into a conjunction."""
    event = event_with(Image="cmd.exe")
    spec = parse_field_spec("Image|all")
    assert match_field(event, spec, ["cmd.exe", "cmd.exe"]) is True
    assert match_field(event, spec, ["cmd.exe", "powershell.exe"]) is False


def test_a_value_list_is_or_ed_by_default() -> None:
    """Without the all modifier, any listed value matches."""
    event = event_with(Image="cmd.exe")
    assert match_field(event, parse_field_spec("Image"), ["powershell.exe", "cmd.exe"]) is True


def test_exists_checks_presence_only() -> None:
    """The exists modifier checks that a field is present or absent."""
    event = event_with(Image="cmd.exe")
    assert match_field(event, parse_field_spec("Image|exists"), True) is True
    assert match_field(event, parse_field_spec("Image|exists"), False) is False
    assert match_field(event, parse_field_spec("CommandLine|exists"), True) is False
    assert match_field(event, parse_field_spec("CommandLine|exists"), False) is True


def test_exists_ignores_the_field_value() -> None:
    """An empty field still exists."""
    event = event_with(Image="")
    assert match_field(event, parse_field_spec("Image|exists"), True) is True


def test_re_matches_a_regular_expression() -> None:
    """The re modifier treats the value as a regular expression."""
    event = event_with(CommandLine="cmd.exe /c whoami")
    assert match_field(event, parse_field_spec("CommandLine|re"), "^cmd") is True


def test_re_is_case_sensitive_by_default() -> None:
    """Regular expressions do not fold case unless asked to."""
    event = event_with(CommandLine="cmd.exe /c whoami")
    assert match_field(event, parse_field_spec("CommandLine|re"), "^CMD") is False
    assert match_field(event, parse_field_spec("CommandLine|re|i"), "^CMD") is True


def test_a_regex_sub_modifier_needs_the_re_modifier() -> None:
    """A sub-modifier on its own is an error."""
    event = event_with(CommandLine="cmd.exe")
    with pytest.raises(ModifierError):
        match_field(event, parse_field_spec("CommandLine|i"), "cmd")


def test_an_invalid_regular_expression_is_an_error() -> None:
    """A regular expression that does not compile is an error."""
    event = event_with(CommandLine="cmd.exe")
    with pytest.raises(ModifierError):
        match_field(event, parse_field_spec("CommandLine|re"), "[")


def test_base64_compares_the_encoded_value() -> None:
    """The base64 modifier encodes the value and compares it with the field."""
    encoded = base64.b64encode(b"whoami").decode("ascii")
    event = event_with(CommandLine=encoded)
    assert match_field(event, parse_field_spec("CommandLine|base64"), "whoami") is True


def test_base64_does_not_match_plain_text() -> None:
    """A plain text field is not a base64 match."""
    event = event_with(CommandLine="whoami")
    assert match_field(event, parse_field_spec("CommandLine|base64"), "whoami") is False


def test_base64offset_covers_the_three_byte_offsets() -> None:
    """The base64offset modifier matches the shifted encodings too."""
    payload = b"whoami"
    shifted = base64.b64encode(b"\x00" + payload).decode("ascii")[2:]
    event = event_with(CommandLine=shifted)
    assert match_field(event, parse_field_spec("CommandLine|base64offset"), "whoami") is True


def test_utf16le_compares_the_encoded_value() -> None:
    """The utf16le modifier encodes the value and compares it with the field."""
    encoded = "whoami".encode("utf-16-le").decode("latin-1")
    event = event_with(CommandLine=encoded)
    assert match_field(event, parse_field_spec("CommandLine|utf16le"), "whoami") is True


def test_utf16le_does_not_match_plain_text() -> None:
    """A plain text field is not a UTF-16 match."""
    event = event_with(CommandLine="whoami")
    assert match_field(event, parse_field_spec("CommandLine|utf16le"), "whoami") is False


def test_wide_is_an_alias_for_utf16le() -> None:
    """The wide modifier behaves like utf16le."""
    encoded = "whoami".encode("utf-16-le").decode("latin-1")
    event = event_with(CommandLine=encoded)
    assert match_field(event, parse_field_spec("CommandLine|wide"), "whoami") is True


def test_utf16be_compares_the_encoded_value() -> None:
    """The utf16be modifier encodes the value and compares it with the field."""
    encoded = "whoami".encode("utf-16-be").decode("latin-1")
    event = event_with(CommandLine=encoded)
    assert match_field(event, parse_field_spec("CommandLine|utf16be"), "whoami") is True


def test_utf16_carries_a_byte_order_mark() -> None:
    """The utf16 modifier encodes the value with a byte order mark."""
    encoded = "whoami".encode("utf-16").decode("latin-1")
    event = event_with(CommandLine=encoded)
    assert match_field(event, parse_field_spec("CommandLine|utf16"), "whoami") is True


def test_windash_treats_dashes_as_interchangeable() -> None:
    """The windash modifier matches any of the dash characters."""
    spec = parse_field_spec("CommandLine|windash")
    assert match_field(event_with(CommandLine="-enc"), spec, "-enc") is True
    assert match_field(event_with(CommandLine="/enc"), spec, "-enc") is True
    assert match_field(event_with(CommandLine="enc"), spec, "-enc") is False


def test_windash_keeps_equality_semantics() -> None:
    """A windash value still has to match the whole field."""
    spec = parse_field_spec("CommandLine|windash")
    assert match_field(event_with(CommandLine="cmd /c -enc x"), spec, "-enc") is False


def test_numeric_comparisons() -> None:
    """The numeric modifiers compare numbers."""
    event = event_with(Port=42)
    assert match_field(event, parse_field_spec("Port|lt"), 50) is True
    assert match_field(event, parse_field_spec("Port|lt"), 42) is False
    assert match_field(event, parse_field_spec("Port|lte"), 42) is True
    assert match_field(event, parse_field_spec("Port|gt"), 50) is False
    assert match_field(event, parse_field_spec("Port|gte"), 42) is True


def test_a_numeric_comparison_against_a_non_number_fails() -> None:
    """A field that is not a number never satisfies a numeric modifier."""
    event = event_with(Port="not a number")
    assert match_field(event, parse_field_spec("Port|lt"), 50) is False


def test_cidr() -> None:
    """The cidr modifier tests membership of a network range."""
    event = event_with(IpAddress="10.1.2.3")
    assert match_field(event, parse_field_spec("IpAddress|cidr"), "10.0.0.0/8") is True
    assert match_field(event, parse_field_spec("IpAddress|cidr"), "192.168.0.0/16") is False


def test_a_cidr_that_does_not_parse_fails() -> None:
    """An invalid network range never matches."""
    event = event_with(IpAddress="10.1.2.3")
    assert match_field(event, parse_field_spec("IpAddress|cidr"), "not a range") is False


def test_time_comparisons() -> None:
    """The time modifiers extract a component from a date."""
    event = event_with(Timestamp="2026-11-04T13:45:00Z")
    assert match_field(event, parse_field_spec("Timestamp|hour"), 13) is True
    assert match_field(event, parse_field_spec("Timestamp|hour"), 14) is False
    assert match_field(event, parse_field_spec("Timestamp|day"), 4) is True
    assert match_field(event, parse_field_spec("Timestamp|month"), 11) is True
    assert match_field(event, parse_field_spec("Timestamp|year"), 2026) is True


def test_fieldref_compares_two_fields() -> None:
    """The fieldref modifier compares a field with another field."""
    event = event_with(Source="10.0.0.1", Destination="10.0.0.1")
    assert match_field(event, parse_field_spec("Source|fieldref"), "Destination") is True


def test_fieldref_fails_when_the_fields_differ() -> None:
    """Two different fields do not satisfy a fieldref."""
    event = event_with(Source="10.0.0.1", Destination="10.0.0.2")
    assert match_field(event, parse_field_spec("Source|fieldref"), "Destination") is False


def test_fieldref_can_be_combined_with_neq() -> None:
    """A fieldref with neq succeeds when the fields differ."""
    spec = parse_field_spec("Source|fieldref|neq")
    assert match_field(event_with(Source="a", Destination="b"), spec, "Destination") is True
    assert match_field(event_with(Source="a", Destination="a"), spec, "Destination") is False


def test_a_null_value_matches_an_empty_field() -> None:
    """A null value matches a field that holds nothing."""
    assert match_field(event_with(Image=None), parse_field_spec("Image"), None) is True
    assert match_field(event_with(Image="cmd.exe"), parse_field_spec("Image"), None) is False


def test_the_expand_modifier_is_rejected() -> None:
    """A rule that needs placeholder expansion must be rejected."""
    event = event_with(Image="cmd.exe")
    with pytest.raises(UnsupportedModifierError):
        match_field(event, parse_field_spec("Image|expand"), "%COMPUTERNAME%")


def test_an_unknown_modifier_is_rejected() -> None:
    """A modifier the specification does not define is rejected."""
    event = event_with(Image="cmd.exe")
    with pytest.raises(UnsupportedModifierError):
        match_field(event, parse_field_spec("Image|nonsense"), "cmd.exe")


def test_a_missing_field_never_matches() -> None:
    """A field that is not in the event cannot match."""
    assert match_field(event_with(Image="cmd.exe"), parse_field_spec("CommandLine"), "x") is False
