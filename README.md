# rulebench

**Behavioral conformance harness for [Sigma](https://github.com/SigmaHQ/sigma) detection rules.**

`sigma-cli` checks that a rule is *well formed*. `pySigma` checks that a rule can be *converted*.
Neither checks that the rule *matches anything*. A rule can pass every validator, ship in a
content repository, be promoted to `stable` — and still never fire on a single real event.

`rulebench` answers the missing question: **given a rule and a set of events, does the rule
actually match what it is supposed to match?** You declare the outcome in a conformance case,
`rulebench` evaluates the rule against the event, and tells you whether the rule behaves as
claimed.

```text
$ rulebench test --rules rules/ --cases cases.yaml --events events.json

rulebench — 8 case(s), 8 passed, 0 failed (rules=4, brokenRules=0, untestedRules=0)

  PASS  powershell_encoded_command  encoded powershell matches
  PASS  powershell_encoded_command  plain powershell does not match
  ...
```

## Why this exists

Detection engineering has a tooling gap that is easy to miss because the tools around it are
good at something else:

| Tool | What it does | What it does not do |
| --- | --- | --- |
| `sigma-cli check` | Schema and validation-config check, JUnit output | Never matches an event |
| `pySigma` | Parses and converts rules to backends | `sigma/backends/test/` is a conversion-output stub |
| `SigmaHQ/sigma` test suite | Trademarks, file names, rule status | No behavioural evaluation |
| `sigmalint` | Lints rules against the specification | No behavioural evaluation |
| `elastic/detection-rules`, `splunk/security_content` | Ship detection content | No harness shipped with it |

Twelve different phrasings of "sigma rule test" returned zero relevant projects on GitHub.
This is a real gap, not a crowded space — and it is squarely a red-team / detection-engineering
problem, because the only way to know whether a detection works is to fire it at controlled
events and observe what happens.

`rulebench` implements the [Sigma specification v2.1.0](https://github.com/SigmaHQ/sigma-specification)
literally. It is not a Sigma-to-your-backend converter. It is a laboratory bench for rules.

## Install

```bash
pip install rulebench
```

From a checkout:

```bash
pip install -e ".[dev]"
```

Python 3.11 or newer. The only runtime dependency is PyYAML, because Sigma rules and
conformance cases are YAML.

## Quick start — 30 seconds

```bash
# See the whole thing work with no checkout and no setup
rulebench demo

# Test your own rules
rulebench test --rules ./rules --cases ./cases.yaml --events ./events.json

# Find rules that are wrong, contradictory or duplicated
rulebench lint --rules ./rules

# Find out which ATT&CK techniques your rules actually cover
rulebench coverage --rules ./rules --techniques ./techniques.json
```

`rulebench demo` builds a small corpus in a temporary directory — one working rule, one rule
missing its logsource, one rule that does not parse — and runs the conformance, lint and
coverage commands against it.

## Conformance cases

A case file is YAML. It holds a `cases` list, or a bare list of cases.

```yaml
cases:
  - name: encoded powershell matches
    rule: powershell_encoded_command      # rule id, file stem, or title
    expect: match                          # match | no-match | error
    event:                                 # inline event...
      Image: 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
      CommandLine: 'powershell.exe -enc SQBFAFgA'

  - name: encoded powershell from the corpus
    rule: powershell_encoded_command
    expect: no-match
    event_name: plain-powershell           # ...or a named event from --events
```

`expect: error` asserts that the rule **must fail** — that it uses a construct `rulebench`
cannot evaluate faithfully, or that it does not parse. A rule that does not parse is only
acceptable when a case documents it that way; otherwise `rulebench test` fails.

A rule with no case at all is reported as untested. Untested rules do not fail the run, but
they are the ones most likely to be wrong.

## Events

An event corpus is JSON. Three shapes are accepted:

```json
{ "events": [ { "name": "encoded-powershell", "event": { "CommandLine": "..." } } ] }
```

```json
[ { "name": "encoded-powershell", "event": { "CommandLine": "..." } } ]
```

```json
[ { "CommandLine": "..." } ]
```

Nested objects are flattened with dotted paths, so a rule can address `process.name` for an
event that carries `{"process": {"name": "cmd.exe"}}`. Field lookups are exact first and
case-insensitive second.

## Lint checks

| Code | Severity | Meaning |
| --- | --- | --- |
| `duplicate-id` | error | Two rules share a rule id |
| `missing-condition` | error | The detection block has no condition |
| `missing-logsource` | error | The rule has no logsource |
| `contradictory-filter` | error | A filter excludes everything the selection matches |
| `invalid-condition` | error | The condition does not parse |
| `unsupported-modifier` | error | The rule uses a modifier rulebench cannot evaluate faithfully |
| `duplicate-title` | warning | Two rules share a title |
| `shadowed-rule` | warning | A broader rule always wins, so this rule never fires alone |
| `them-includes-filter` | warning | `of them` also covers the filter selection |

The last one is worth reading twice. The specification states that `them` covers **every**
search identifier that does not start with an underscore — including `filter` selections — and
warns against `all of them` for exactly that reason. `rulebench` implements the specification
as written and then tells you, with a warning, when you have walked into that footgun.

`lint` exits non-zero only on **error** findings. Warnings are reported but do not fail a run.

## Coverage

`coverage` reads the ATT&CK technique identifiers out of rule tags (`attack.t1059.001`) and
compares them with the list you expect to cover.

```json
{ "techniques": ["T1059", "T1059.001", "T1105", "T1112"] }
```

A list of objects carrying an `id`, `technique` or `external_id` key is accepted too. The report
lists expected, covered, missing and extra techniques, with the rules that cover each one.

## Supported rule semantics

`rulebench` follows the specification v2.1.0:

- **Conditions** — `or`, `and`, `not`, `x of <pattern>`, and parentheses, in the precedence the
  specification defines. A condition may be a list, in which case each element is a separate
  query and the results are OR'd.
- **Search identifiers** — a mapping is a conjunction of field tests; a list is a disjunction of
  alternatives; a string is a keyword search over the whole event. The `|all` key form requires
  every keyword to be present.
- **Values** — case-insensitive by default, `*` and `?` wildcards, backslash escapes for `*`,
  `?` and itself, `null` for null, `''` for empty.
- **Modifiers** — generic (`all`, `startswith`, `endswith`, `contains`, `exists`, `cased`,
  `neq`), string (`windash`, `re` with `i`/`m`/`s`, `base64`, `base64offset`, `utf16le`,
  `utf16be`, `utf16`, `wide`), numeric (`lt`, `lte`, `gt`, `gte`), time (`minute`, `hour`, `day`,
  `week`, `month`, `year`), IP (`cidr`) and specific (`expand`, `fieldref`). Modifiers are
  applied left to right.

`expand` is the one modifier `rulebench` refuses. It requires placeholder expansion, and the
specification is explicit: *"If the tool isn't able to handle placeholders, it must reject the
rule."* `rulebench` raises `UnsupportedModifierError` rather than quietly guessing, and the
linter reports the rule as an error.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | A conformance case failed, a rule failed to parse without a case covering it, or the linter found an error |
| `2` | The command line or an input file was wrong |

## Reports

| Command | Formats |
| --- | --- |
| `test` | `text`, `json`, `junit` |
| `lint` | `text`, `json` |
| `coverage` | `text`, `json` |

`--output FILE` writes the report to disk instead of stdout. The JUnit format is meant to be
consumed by CI, so a rulebench run can be a required status check on a detection repository.

## Scope and legal use

`rulebench` evaluates detection rules against events you supply. It does not generate events,
does not execute payloads, does not touch a target, and has no network access. It is a
defensive detection-engineering tool.

Use it to test rules you wrote, rules you are reviewing, and rules you inherited. Use it on
your own infrastructure, on systems you are authorised to test, and inside the boundaries of
your engagement. Do not use it to build a detection-evasion loop against a third party's
monitoring.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Behaviour changes to rule evaluation need a
conformance case that demonstrates the change, because that is the whole point of the tool.

## Sponsors

Sponsorship pays for the maintenance, triage and release time behind this tool. Sponsors are
listed here by name, and name placement starts at the $25 a month tier.

- [Sponsor on GitHub](https://github.com/sponsors/gravion-ux)

## License

MIT — see [LICENSE](LICENSE).
