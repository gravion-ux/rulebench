"""Tests for the condition grammar."""

from __future__ import annotations

import pytest

from rulebench.conditions import (
    And,
    ConditionError,
    Identifier,
    Not,
    OneOf,
    Or,
    evaluate_condition,
    evaluate_node,
    parse_condition,
    pattern_matches,
    tokenize,
)


class FakeContext:
    """A condition context backed by plain sets."""

    def __init__(self, matched: set[str], identifiers: list[str]) -> None:
        self.matched = matched
        self.identifiers = identifiers

    def identifier_matches(self, name: str) -> bool:
        """Report whether an identifier matches.

        :param name: The identifier name.
        :returns: True when the identifier matches.
        """
        return name in self.matched

    def matching_identifiers(self, pattern: str) -> list[str]:
        """Resolve a pattern to identifier names.

        :param pattern: The pattern.
        :returns: The matching names.
        """
        if pattern == "them":
            return [name for name in self.identifiers if not name.startswith("_")]
        return [name for name in self.identifiers if pattern_matches(pattern, name)]


def test_tokenize_splits_parentheses() -> None:
    """Parentheses are separate tokens."""
    assert tokenize("(selection and filter) or other") == [
        "(",
        "selection",
        "and",
        "filter",
        ")",
        "or",
        "other",
    ]


def test_pattern_matches_an_exact_name() -> None:
    """A pattern without a wildcard matches only itself."""
    assert pattern_matches("selection", "selection") is True
    assert pattern_matches("selection", "selection_two") is False


def test_pattern_matches_a_wildcard() -> None:
    """A star matches any run of characters."""
    assert pattern_matches("selection*", "selection_one") is True
    assert pattern_matches("*filter", "my_filter") is True
    assert pattern_matches("sel*ion", "selection") is True


def test_pattern_does_not_treat_a_question_mark_as_a_wildcard() -> None:
    """Only the star is special in a search identifier pattern."""
    assert pattern_matches("selection?", "selectionX") is False


def test_parse_condition_builds_an_identifier() -> None:
    """A bare name becomes an identifier node."""
    (node,) = parse_condition("selection")
    assert node == Identifier("selection")


def test_parse_condition_uses_the_specified_precedence() -> None:
    """'or' binds least tightly and 'not' binds more tightly than 'and'."""
    (node,) = parse_condition("selection and not filter or other")
    assert node == Or((And((Identifier("selection"), Not(Identifier("filter")))), Identifier("other")))


def test_parentheses_override_precedence() -> None:
    """Parentheses bind more tightly than any operator."""
    (node,) = parse_condition("(selection or other) and filter")
    assert node == And((Or((Identifier("selection"), Identifier("other"))), Identifier("filter")))


def test_parse_condition_reads_one_of_them() -> None:
    """'1 of them' becomes a counted expression."""
    (node,) = parse_condition("1 of them")
    assert node == OneOf(pattern="them", count=1)


def test_parse_condition_reads_all_of_them() -> None:
    """'all of them' becomes an uncounted expression."""
    (node,) = parse_condition("all of them")
    assert node == OneOf(pattern="them", count=None)


def test_parse_condition_reads_a_wildcard_pattern() -> None:
    """'1 of selection*' keeps its pattern."""
    (node,) = parse_condition("1 of selection*")
    assert node == OneOf(pattern="selection*", count=1)


def test_parse_condition_reads_a_list_of_conditions() -> None:
    """A condition list produces one expression tree per element."""
    nodes = parse_condition(["selection", "other"])
    assert nodes == (Identifier("selection"), Identifier("other"))


def test_parse_condition_rejects_an_empty_condition() -> None:
    """An empty condition is an error."""
    with pytest.raises(ConditionError):
        parse_condition("")


def test_parse_condition_rejects_an_empty_list() -> None:
    """An empty condition list is an error."""
    with pytest.raises(ConditionError):
        parse_condition([])


def test_parse_condition_rejects_a_dangling_operator() -> None:
    """A condition that ends with an operator is an error."""
    with pytest.raises(ConditionError):
        parse_condition("selection and")


def test_parse_condition_rejects_an_unclosed_parenthesis() -> None:
    """A missing closing parenthesis is an error."""
    with pytest.raises(ConditionError):
        parse_condition("(selection")


def test_parse_condition_rejects_a_trailing_token() -> None:
    """A token after a complete expression is an error."""
    with pytest.raises(ConditionError):
        parse_condition("selection extra")


def test_parse_condition_rejects_a_leading_keyword() -> None:
    """A condition that starts with an operator is an error."""
    with pytest.raises(ConditionError):
        parse_condition("and selection")


def test_parse_condition_rejects_of_without_a_pattern() -> None:
    """'of' with nothing after it is an error."""
    with pytest.raises(ConditionError):
        parse_condition("all of")


def test_parse_condition_rejects_a_keyword_after_of() -> None:
    """'of and' is an error."""
    with pytest.raises(ConditionError):
        parse_condition("1 of and")


def test_evaluate_node_resolves_an_identifier() -> None:
    """An identifier reports whether it matches."""
    context = FakeContext({"selection"}, ["selection", "filter"])
    assert evaluate_node(Identifier("selection"), context) is True
    assert evaluate_node(Identifier("filter"), context) is False


def test_evaluate_node_handles_one_of() -> None:
    """'1 of' is satisfied by a single matching identifier."""
    context = FakeContext({"a"}, ["a", "b"])
    assert evaluate_node(OneOf(pattern="them", count=1), context) is True
    assert evaluate_node(OneOf(pattern="them", count=1), FakeContext(set(), ["a", "b"])) is False


def test_evaluate_node_handles_all_of() -> None:
    """'all of' needs every identifier to match."""
    assert evaluate_node(OneOf(pattern="them", count=None), FakeContext({"a", "b"}, ["a", "b"])) is True
    assert evaluate_node(OneOf(pattern="them", count=None), FakeContext({"a"}, ["a", "b"])) is False


def test_evaluate_node_handles_all_of_with_no_identifiers() -> None:
    """'all of' with nothing to match is false."""
    assert evaluate_node(OneOf(pattern="them", count=None), FakeContext(set(), [])) is False


def test_them_skips_underscore_prefixed_identifiers() -> None:
    """'them' leaves out identifiers that start with an underscore."""
    context = FakeContext({"_internal"}, ["_internal", "selection"])
    assert evaluate_node(OneOf(pattern="them", count=1), context) is False


def test_evaluate_node_handles_not() -> None:
    """A negation inverts its operand."""
    context = FakeContext(set(), ["filter"])
    assert evaluate_node(Not(Identifier("filter")), context) is True


def test_evaluate_condition_ors_a_condition_list() -> None:
    """A condition list is logically OR'd."""
    nodes = parse_condition(["selection", "other"])
    assert evaluate_condition(nodes, FakeContext({"other"}, ["selection", "other"])) is True
    assert evaluate_condition(nodes, FakeContext(set(), ["selection", "other"])) is False
