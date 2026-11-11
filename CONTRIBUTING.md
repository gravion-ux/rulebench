# Contributing to rulebench

Thanks for taking the time to contribute.

## Getting set up

```bash
git clone https://github.com/gravion-ux/rulebench.git
cd rulebench
python -m venv .venv
.venv/Scripts/pip install -e ".[dev]"   # .venv/bin/pip on Linux and macOS
.venv/Scripts/pytest -q                 # .venv/bin/pytest on Linux and macOS
```

`rulebench` targets Python 3.11 or newer and has **one runtime dependency**, PyYAML. Sigma rules
and conformance cases are YAML, so a YAML parser is not optional. Please do not add a second one.

## Making a change

1. Open an issue first for anything larger than a bug fix, so the approach can be agreed on.
2. Create a branch from `main`.
3. Add or update tests. Every behavioural change needs a test that fails without your change.
4. Run `pytest -q` and `ruff check .` before opening a pull request.
5. Keep the commit history readable — one logical change per commit.

## Code style

- 4-space indentation, type hints on public functions, `from __future__ import annotations`.
- Every public function carries a docstring with `:param:` and `:returns:` lines.
- Line length is 100 characters; `ruff` enforces it with `E501` ignored for long prose.
- Line endings are LF. `.gitattributes` enforces this.

## Tests

```bash
pytest -q
```

The suite is organised per module: `tests/test_events.py`, `tests/test_modifiers.py`,
`tests/test_conditions.py`, `tests/test_rules.py`, `tests/test_evaluate.py`,
`tests/test_lint.py`, `tests/test_coverage.py`, `tests/test_report.py` and
`tests/test_cli.py`.

## Behaviour changes need a conformance case

This is the rule that matters most in this project. If you change how a rule is evaluated, add a
conformance case that demonstrates the change, in `examples/` or in the test suite. A behavioural
change without a case is a change nobody can check — which is the exact problem `rulebench`
exists to solve.

## Rule semantics

Behaviour must follow the
[Sigma specification v2.1.0](https://github.com/SigmaHQ/sigma-specification). If the
specification and an existing behaviour disagree, the specification wins, and the change needs a
note in `CHANGELOG.md` explaining why.

Do not soften a rule that `rulebench` cannot evaluate faithfully. Reject it instead. A tool that
guesses produces false confidence, which is worse than an error.

## Maintainer

Priyanshu Kumar Thakur (Gravion)

## Reporting security issues

Please follow [SECURITY.md](SECURITY.md) rather than opening a public issue.

## Code of conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
