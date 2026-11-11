# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
