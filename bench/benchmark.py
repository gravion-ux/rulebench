"""Measure the rule evaluation hot paths.

Run it from a checkout::

    python bench/benchmark.py

The workload is a realistic Sigma rule — four search identifiers, a negated
filter and a keyword selection — evaluated against a corpus of Windows process
creation events. Each workload is timed several times and the fastest run is
reported, because the slowest run is usually the one that caught a stray
background process rather than the one that measured the code.

The numbers are only comparable against each other on the same machine and the
same Python build. Use them to compare two revisions of this tool, not to
compare it with another machine.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from rulebench.evaluate import evaluate_rule, match_selection  # noqa: E402
from rulebench.events import Event  # noqa: E402
from rulebench.rules import Rule  # noqa: E402

#: How many events the corpus holds.
EVENT_COUNT = 2000

#: How many times each workload is timed. The fastest run wins.
TRIALS = 7

RULE = Rule(
    id="8f1b2c44-0d3e-4a51-9c77-2b6e5d4a1c90",
    title="Suspicious PowerShell Encoded Command",
    description="Detects PowerShell invoked with an encoded command payload.",
    status="test",
    level="high",
    logsource={"product": "windows", "category": "process_creation"},
    detection={
        "selection_img": {"Image|endswith": "\\powershell.exe"},
        "selection_cli": {"CommandLine|contains": ["-enc", "-EncodedCommand", "-ec "]},
        "selection_user": {"User|contains": "CORP"},
        "filter": {"User|startswith": "SYSTEM"},
        "keywords": ["mimikatz", "Invoke-Mimikatz", "sekurlsa::logonpasswords"],
        "condition": "selection_img and selection_cli and not filter",
    },
    condition="selection_img and selection_cli and not filter",
    tags=("attack.t1059.001",),
    fields=(),
    falsepositives=(),
    path=Path("process_creation.yml"),
    name="process_creation",
)


def build_events() -> list[Event]:
    """Build a corpus of Windows process creation events.

    :returns: The events.
    """
    events: list[Event] = []
    for index in range(EVENT_COUNT):
        events.append(
            Event(
                fields={
                    "EventID": str(4688 + (index % 3)),
                    "Channel": "Security",
                    "Computer": f"HOST-{index % 50:03d}.corp.example",
                    "TimeCreated": f"2026-11-19T{index % 24:02d}:{index % 60:02d}:00Z",
                    "Provider": "Microsoft-Windows-Security-Auditing",
                    "EventLevel": "Information",
                    "User": f"CORP\\svc-{index % 40:02d}",
                    "ProcessId": str(1000 + index),
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": "powershell.exe -enc SQBFAFgA " + ("A" * 120),
                    "ParentImage": "C:\\Windows\\explorer.exe",
                    "ParentCommandLine": "explorer.exe",
                    "Hashes": {"SHA256": "a" * 64},
                    "Account": "CORP\\Administrator",
                    "LogonId": f"0x{index % 90:x}",
                },
                name=f"event-{index}",
            )
        )
    return events


def measure(label: str, workload, trials: int = TRIALS) -> float:
    """Time a workload and report its fastest run.

    :param label: The workload name.
    :param workload: The callable to time.
    :param trials: How many times to run it.
    :returns: The fastest run, in seconds.
    """
    best = float("inf")
    result = 0
    for _ in range(trials):
        start = time.perf_counter()
        result = workload()
        elapsed = time.perf_counter() - start
        if elapsed < best:
            best = elapsed
    print(f"{label:46s} {best * 1000:8.1f} ms   -> {result}")
    return best


def main() -> int:
    """Run every workload and print the result.

    :returns: The process exit code.
    """
    events = build_events()
    print(f"rule: {RULE.identifier}")
    print(f"events: {len(events)}")
    print()

    measure(
        "evaluate_rule over the whole corpus",
        lambda: sum(1 for event in events if evaluate_rule(RULE, event)),
    )
    measure(
        "match_selection over a field selection",
        lambda: sum(
            1
            for event in events
            if match_selection(
                {
                    "Image|endswith": "\\powershell.exe",
                    "CommandLine|contains": ["-enc", "-EncodedCommand", "-ec "],
                    "User|contains": "CORP",
                },
                event,
            )
        ),
    )
    measure(
        "match_selection over a keyword selection",
        lambda: sum(
            1
            for event in events
            if match_selection(
                ["mimikatz", "Invoke-Mimikatz", "sekurlsa::logonpasswords"], event
            )
        ),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
