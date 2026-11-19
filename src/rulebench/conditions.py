"""Condition expression parsing and evaluation.

The condition grammar follows the Sigma specification v2.1.0. Operator
precedence, from least to most binding, is ``or``, ``and``, ``not``,
``x of search-identifier``, ``( expression )``.

``1 of them`` and ``all of them`` cover every search identifier whose name does
**not** start with an underscore. A filter named ``filter`` is therefore part of
``them`` — the specification warns against ``all of them`` for exactly this
reason.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Protocol

__all__ = [
    "And",
    "ConditionContext",
    "ConditionError",
    "Identifier",
    "Not",
    "OneOf",
    "Or",
    "evaluate_condition",
    "evaluate_node",
    "parse_condition",
    "pattern_matches",
    "tokenize",
]


class ConditionError(ValueError):
    """Raised when a condition cannot be parsed or evaluated."""


@dataclass(frozen=True)
class Identifier:
    """A reference to a named search identifier."""

    name: str


@dataclass(frozen=True)
class OneOf:
    """An ``x of <pattern>`` expression.

    ``count`` is ``None`` for ``all of`` and ``1`` for ``1 of``.
    """

    pattern: str
    count: int | None


@dataclass(frozen=True)
class Not:
    """A negation of another expression."""

    operand: Node


@dataclass(frozen=True)
class And:
    """A conjunction of expressions."""

    operands: tuple[Node, ...]


@dataclass(frozen=True)
class Or:
    """A disjunction of expressions."""

    operands: tuple[Node, ...]


Node = Identifier | OneOf | Not | And | Or


class ConditionContext(Protocol):
    """What a condition needs from the evaluation engine."""

    def identifier_matches(self, name: str) -> bool:
        """Evaluate one named search identifier.

        :param name: The search identifier name.
        :returns: True when the identifier matches the event.
        """

    def matching_identifiers(self, pattern: str) -> list[str]:
        """Resolve a search identifier pattern to concrete names.

        :param pattern: The pattern, or the literal ``them``.
        :returns: The matching search identifier names.
        """


_TOKEN_RE = re.compile(r"\(|\)|[^\s()]+")

_KEYWORDS = frozenset({"and", "or", "not", "of", "all", "them"})


def tokenize(text: str) -> list[str]:
    """Split a condition into tokens.

    :param text: The condition text.
    :returns: The token list.
    """
    return _TOKEN_RE.findall(text)


def pattern_matches(pattern: str, name: str) -> bool:
    """Match a search identifier name against a wildcard pattern.

    Only ``*`` is special and matches any number of characters at any position,
    which is what the specification describes.

    :param pattern: The pattern.
    :param name: The candidate name.
    :returns: True when the name matches.
    """
    expression = "^" + ".*".join(re.escape(part) for part in pattern.split("*")) + "$"
    return re.match(expression, name) is not None


class _Parser:
    """A recursive-descent parser for the condition grammar."""

    def __init__(self, tokens: list[str], source: str) -> None:
        self.tokens = tokens
        self.source = source
        self.position = 0

    def _peek(self, offset: int = 0) -> str | None:
        index = self.position + offset
        if index >= len(self.tokens):
            return None
        return self.tokens[index]

    def _advance(self) -> str:
        token = self._peek()
        if token is None:
            raise ConditionError(f"unexpected end of condition: {self.source!r}")
        self.position += 1
        return token

    def parse(self) -> Node:
        """Parse the whole condition.

        :returns: The expression tree.
        """
        node = self._parse_or()
        if self.position != len(self.tokens):
            raise ConditionError(
                f"unexpected token {self.tokens[self.position]!r} in condition {self.source!r}"
            )
        return node

    def _parse_or(self) -> Node:
        operands = [self._parse_and()]
        while self._peek() == "or":
            self._advance()
            operands.append(self._parse_and())
        if len(operands) == 1:
            return operands[0]
        return Or(tuple(operands))

    def _parse_and(self) -> Node:
        operands = [self._parse_not()]
        while self._peek() == "and":
            self._advance()
            operands.append(self._parse_not())
        if len(operands) == 1:
            return operands[0]
        return And(tuple(operands))

    def _parse_not(self) -> Node:
        if self._peek() == "not":
            self._advance()
            return Not(self._parse_not())
        return self._parse_primary()

    def _parse_primary(self) -> Node:
        token = self._peek()
        if token is None:
            raise ConditionError(f"unexpected end of condition: {self.source!r}")
        if token == "(":
            self._advance()
            node = self._parse_or()
            if self._peek() != ")":
                raise ConditionError(f"missing closing parenthesis in condition {self.source!r}")
            self._advance()
            return node
        if token in {"all", "1"}:
            if self._peek(1) != "of":
                raise ConditionError(
                    f"expected 'of' after {token!r} in condition {self.source!r}"
                )
            self._advance()
            self._advance()
            pattern = self._peek()
            if pattern is None:
                raise ConditionError(f"missing search identifier after 'of' in {self.source!r}")
            if pattern in _KEYWORDS and pattern != "them":
                raise ConditionError(
                    f"unexpected keyword {pattern!r} after 'of' in condition {self.source!r}"
                )
            self._advance()
            return OneOf(pattern=pattern, count=None if token == "all" else 1)
        if token in {"and", "or", "not", "of"}:
            raise ConditionError(f"unexpected keyword {token!r} in condition {self.source!r}")
        self._advance()
        return Identifier(token)


@lru_cache(maxsize=1024)
def _parse_single_cached(text: str) -> Node:
    """Parse one condition expression and remember the result.

    A rule carries the same condition for every event it is tested against, so
    the expression tree is worth keeping.

    :param text: The condition text.
    :returns: The expression tree.
    :raises ConditionError: When the condition does not parse.
    """
    tokens = tokenize(text)
    if not tokens:
        raise ConditionError("condition is empty")
    return _Parser(tokens, text).parse()


def _parse_single(text: str) -> Node:
    """Parse one condition expression.

    :param text: The condition text.
    :returns: The expression tree.
    :raises ConditionError: When the condition does not parse.
    """
    return _parse_single_cached(text)


def parse_condition(condition: str | list[str]) -> tuple[Node, ...]:
    """Parse a rule condition into one or more expression trees.

    A condition may be a list; the specification states that each element then
    generates a separate query, logically linked with OR.

    :param condition: The condition, as a string or a list of strings.
    :returns: One expression tree per condition.
    :raises ConditionError: When any condition does not parse.
    """
    if isinstance(condition, (list, tuple)):
        if not condition:
            raise ConditionError("condition list is empty")
        return tuple(_parse_single(str(item)) for item in condition)
    if not isinstance(condition, str):
        raise ConditionError(f"condition must be a string or list, got {type(condition).__name__}")
    return (_parse_single(condition),)


def evaluate_node(node: Node, context: ConditionContext) -> bool:
    """Evaluate one expression tree.

    :param node: The expression tree.
    :param context: The evaluation context.
    :returns: The boolean result.
    """
    if isinstance(node, Identifier):
        return context.identifier_matches(node.name)
    if isinstance(node, OneOf):
        names = context.matching_identifiers(node.pattern)
        if node.count is None:
            if not names:
                return False
            return all(context.identifier_matches(name) for name in names)
        matched = 0
        for name in names:
            if context.identifier_matches(name):
                matched += 1
                if matched >= node.count:
                    return True
        return False
    if isinstance(node, Not):
        return not evaluate_node(node.operand, context)
    if isinstance(node, And):
        return all(evaluate_node(operand, context) for operand in node.operands)
    if isinstance(node, Or):
        return any(evaluate_node(operand, context) for operand in node.operands)
    raise ConditionError(f"unsupported condition node: {node!r}")


def evaluate_condition(nodes: tuple[Node, ...], context: ConditionContext) -> bool:
    """Evaluate a parsed condition.

    :param nodes: The expression trees.
    :param context: The evaluation context.
    :returns: True when any expression tree evaluates true.
    """
    return any(evaluate_node(node, context) for node in nodes)
