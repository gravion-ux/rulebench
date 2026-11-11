"""rulebench — behavioral conformance harness for Sigma detection rules.

The package answers one question: does a Sigma rule actually match the events it
is supposed to match? Schema validation cannot answer it, because a rule can
satisfy every validator and still never fire.
"""

from __future__ import annotations

from rulebench.conditions import ConditionError, parse_condition
from rulebench.evaluate import evaluate_rule, match_selection
from rulebench.events import Event, load_events
from rulebench.modifiers import (
    ModifierError,
    UnsupportedModifierError,
    parse_field_spec,
)
from rulebench.rules import Rule, RuleParseError, load_rule, load_rules

__version__ = "0.1.0"

__all__ = [
    "ConditionError",
    "Event",
    "ModifierError",
    "Rule",
    "RuleParseError",
    "UnsupportedModifierError",
    "evaluate_rule",
    "load_events",
    "load_rule",
    "load_rules",
    "match_selection",
    "parse_condition",
    "parse_field_spec",
]
