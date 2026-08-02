"""Human-review renderers for common detection formats."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from agentsim.detection.generator import CandidateDetection


FORMATS = ("sigma", "kql", "splunk", "crowdstrike", "elastic", "panther", "graylog")


def _quote(value: str) -> str:
    return json.dumps(value)


def _process_filter(candidate: CandidateDetection, field: str, separator: str = " OR ") -> str:
    if not candidate.process_names:
        return f"{field}:*"
    return separator.join(f"{field}={_quote(name)}" for name in candidate.process_names)


def _header(candidate: CandidateDetection, style: str = "#") -> str:
    return "\n".join(
        (
            f"{style} AGENTSIM STATUS: CANDIDATE - HUMAN REVIEW REQUIRED",
            f"{style} Ability: {candidate.ability_id}",
            f"{style} Confidence: {candidate.confidence}",
        )
    )


def _sigma(candidate: CandidateDetection) -> str:
    process_lines = "\n".join(f"      - {_quote(name)}" for name in candidate.process_names) or "      - '*'"
    mappings = "\n".join(f"  - {_quote(value)}" for value in candidate.rule.mappings) or "  - agentsim"
    false_positives = (
        "".join(f"  - {_quote(value)}\n" for value in candidate.benign_controls)
        or "  - Environment-specific administration\n"
    )
    return f"""title: {_quote(candidate.rule.name)}
id: {_quote(candidate.rule.rule_id)}
status: experimental
description: {_quote(candidate.rule.description)}
tags:
{mappings}
logsource:
  category: process_creation
detection:
  selection:
    Image|endswith:
{process_lines}
  condition: selection
falsepositives:
{false_positives}level: {candidate.rule.severity}
"""


def _kql(candidate: CandidateDetection) -> str:
    names = ", ".join(_quote(name) for name in candidate.process_names) or '"<review-required>"'
    return f"""{_header(candidate, '//')}
DeviceProcessEvents
| where tolower(FileName) in ({names})
| summarize event_count=count(), commands=make_set(ProcessCommandLine, 20)
    by DeviceId, AccountName, bin(Timestamp, 5m)
| where event_count >= 2
"""


def _splunk(candidate: CandidateDetection) -> str:
    names = " OR ".join(f"process_name={_quote(name)}" for name in candidate.process_names) or "process_name=*"
    return f"""{_header(candidate)}
index=* ({names})
| bin _time span=5m
| stats count values(process_name) as processes by _time host user
| where count >= 2
"""


def _crowdstrike(candidate: CandidateDetection) -> str:
    names = " OR ".join(f"FileName={_quote(name)}" for name in candidate.process_names) or "FileName=*"
    return f"""{_header(candidate, '//')}
#event_simpleName=ProcessRollup2
| {names}
| groupBy([aid, UserSid], function=[count(as=event_count), collect([FileName, CommandLine])])
| test(event_count >= 2)
"""


def _elastic(candidate: CandidateDetection) -> str:
    names = ", ".join(_quote(name) for name in candidate.process_names) or '"<review-required>"'
    return f"""{_header(candidate, '//')}
sequence by host.id, user.id with maxspan=5m
  [process where event.type == "start" and process.name in ({names})]
  [process where event.type == "start" and process.name in ({names})]
"""


def _panther(candidate: CandidateDetection) -> str:
    names = ", ".join(_quote(name) for name in candidate.process_names)
    return f'''{_header(candidate)}
from panther_base_helpers import deep_get

PROCESSES = {{{names}}}

def rule(event):
    process = str(deep_get(event, "process", "name", default="")).lower()
    return process in PROCESSES

def title(event):
    return "{candidate.rule.name} (candidate)"
'''


def _graylog(candidate: CandidateDetection) -> str:
    query = " OR ".join(f'process_name:{_quote(name)}' for name in candidate.process_names) or "process_name:*"
    return f"""{_header(candidate, '//')}
// Configure as an event definition with a 5-minute window and threshold >= 2.
{query}
"""


_RENDERERS: dict[str, Callable[[CandidateDetection], str]] = {
    "sigma": _sigma,
    "kql": _kql,
    "splunk": _splunk,
    "crowdstrike": _crowdstrike,
    "elastic": _elastic,
    "panther": _panther,
    "graylog": _graylog,
}


def render_candidate(candidate: CandidateDetection, format_name: str) -> str:
    try:
        return _RENDERERS[format_name.casefold()](candidate)
    except KeyError as exc:
        raise ValueError(f"Unsupported detection format: {format_name}") from exc


def write_candidate_bundle(candidate: CandidateDetection, destination: str | Path) -> Path:
    root = Path(destination)
    root.mkdir(parents=True, exist_ok=True)
    extensions = {
        "sigma": ".yml",
        "kql": ".kql",
        "splunk": ".spl",
        "crowdstrike": ".logscale",
        "elastic": ".eql",
        "panther": ".py",
        "graylog": ".query",
    }
    for format_name in FORMATS:
        (root / f"{candidate.rule.rule_id}{extensions[format_name]}").write_text(
            render_candidate(candidate, format_name), encoding="utf-8"
        )
    (root / "candidate.json").write_text(
        json.dumps(candidate.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return root
