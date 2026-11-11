# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

## Reporting a vulnerability

Please report suspected vulnerabilities privately by opening a GitHub Security Advisory on the
repository rather than a public issue. Include the affected version, reproduction steps, and the
impact you observed.

You can expect an acknowledgement within a few days. Fixes are released as a new patch version.

Maintainer: Priyanshu Kumar Thakur (Gravion).

## Scope and authorized use

`rulebench` is a defensive detection-engineering tool. It evaluates Sigma rules against events
that you supply.

- `rulebench` never connects to the network. It reads local rules, local case files and local
  event corpora, and writes reports to stdout or to a file you name.
- `rulebench` does not execute rules, does not generate events, and does not touch a target.
- Event corpora can contain sensitive log data. Review them before sharing a workspace or a
  repository.
- A rule that uses the `expand` modifier is rejected rather than evaluated. The specification
  requires a tool that cannot expand placeholders to refuse the rule, and `rulebench` holds that
  line rather than guessing.

Only use `rulebench` on rules and events you own or are explicitly authorized to assess.
