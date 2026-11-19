# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- The `fieldref` modifier now compares two field values literally. A wildcard in one field no
  longer matches another field, and two numeric-looking strings are no longer compared as numbers.
- A rule value is only treated as a number when it is an unambiguous decimal. `1_000`, `1e5` and a
  padded value are no longer silently equal to the number they resemble.
- The `neq` modifier no longer discards the mode another modifier selected, so `contains|neq` and
  `startswith|neq` now mean "does not contain" and "does not start with".
- The `exists` modifier reads its flag as a boolean, accepting the strings `true` and `false`, and
  rejects a value that is not a boolean instead of guessing.
- An epoch timestamp is read in UTC, so the same event now gives the same answer on every machine.
- The time modifiers receive the field value as it was read, so an epoch number is no longer
  rendered as text before it is parsed.

### Changed

- The evaluation hot paths no longer reparse what a rule already states. A condition, a field
  specification and a wildcard expression are parsed once and reused, and the searchable text of an
  event is rendered once per event rather than once per keyword. Measured against the previous
  revision on the same machine, a corpus of 2000 process creation events evaluates 1.43 times
  faster, a field selection 1.34 times faster and a keyword selection 1.95 times faster.

### Added

- `bench/benchmark.py`, which times the three evaluation hot paths against a built-in corpus, so
  the numbers above can be reproduced with `python bench/benchmark.py`.

## [0.1.0] - 2026-11-05

### Added

- Sigma rule loader that reads `.yml` and `.yaml` rule files and reports a broken rule without
  hiding the rules that did load.
- Condition parser for the Sigma v2.1.0 grammar, including `or`, `and`, `not`, `x of <pattern>`,
  parentheses, and the `them` pattern, which covers every search identifier that does not start
  with an underscore.
- Rule evaluation against events, with exact-then-case-insensitive field lookup, dotted paths for
  nested objects, and full-message keyword search.
- Modifier support for the generic (`all`, `startswith`, `endswith`, `contains`, `exists`,
  `cased`, `neq`), string (`windash`, `re` with `i`/`m`/`s`, `base64`, `base64offset`, `utf16le`,
  `utf16be`, `utf16`, `wide`), numeric (`lt`, `lte`, `gt`, `gte`), time (`minute`, `hour`, `day`,
  `week`, `month`, `year`), IP (`cidr`) and specific (`fieldref`) modifiers, applied left to right.
- Rejection of the `expand` modifier, because the specification requires a tool that cannot expand
  placeholders to refuse the rule.
- Conformance case engine with `match`, `no-match` and `error` expectations, rule lookup by id,
  file stem or title, and a report of the rules that no case exercises.
- Linter with nine checks: `duplicate-id`, `duplicate-title`, `missing-condition`,
  `missing-logsource`, `contradictory-filter`, `invalid-condition`, `unsupported-modifier`,
  `shadowed-rule` and `them-includes-filter`.
- ATT&CK coverage analysis derived from rule tags, with a report of expected, covered, missing
  and extra techniques.
- `test`, `lint`, `coverage` and `demo` CLI subcommands with exit codes 0, 1 and 2, and text,
  JSON and JUnit XML report formats.

[0.1.0]: https://github.com/gravion-ux/rulebench/releases/tag/v0.1.0
