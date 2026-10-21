"""
Detection rules over AI-security telemetry.

Each rule takes the full event list and returns alerts (session + rule + why).
Rules never read the ground-truth `malicious` label - that is only used to score
them. The craft here is coverage with few false positives; thresholds are chosen
to flag the attack sessions in events.py without firing on benign traffic.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass

_INJECTION = re.compile(
    r"ignore (all|your|previous).*instruction|disregard your rules|you are now|no restrictions|"
    r"reveal your (system )?prompt|repeat your instructions|print the api key",
    re.IGNORECASE,
)
_SECRET = re.compile(r"sk-[a-z0-9-]{8,}|api[_-]?key\s*[=:]\s*\S+", re.IGNORECASE)
_CANARY = re.compile(r"HR-CONFIDENTIAL-\w+|RAG-INJECT-CANARY-\w+|AGENT-RESTRICTED-CANARY-\w+", re.IGNORECASE)

INJECTION_THRESHOLD = 3     # repeated injection attempts in one session
RETRIEVAL_VOLUME = 30       # chunks retrieved in a single request


@dataclass
class Alert:
    session: str
    rule: str
    severity: str
    detail: str


def _by_session(events):
    g = defaultdict(list)
    for e in events:
        g[e["session"]].append(e)
    return g


def detect(events: list[dict]) -> list[Alert]:
    alerts: list[Alert] = []
    for session, evs in _by_session(events).items():
        inj = sum(1 for e in evs if e["kind"] == "prompt" and _INJECTION.search(e.get("text", "")))
        if inj >= INJECTION_THRESHOLD:
            alerts.append(Alert(session, "repeated-injection", "high",
                                f"{inj} injection/jailbreak prompts in one session"))
        for e in evs:
            if e["kind"] == "prompt" and _SECRET.search(e.get("text", "")):
                alerts.append(Alert(session, "secret-in-prompt", "high",
                                    "credential-shaped string submitted in a prompt"))
                break
        for e in evs:
            if e["kind"] == "retrieval" and int(e.get("meta", {}).get("count", 0)) >= RETRIEVAL_VOLUME:
                alerts.append(Alert(session, "anomalous-retrieval", "medium",
                                    f"retrieval of {e['meta']['count']} chunks (possible scraping)"))
                break
        for e in evs:
            if e["kind"] == "blocked" and e.get("meta", {}).get("tool"):
                alerts.append(Alert(session, "denied-tool-call", "high",
                                    f"blocked tool {e['meta']['tool']} ({e['meta'].get('reason','')})"))
                break
        for e in evs:
            if e["kind"] == "response" and _CANARY.search(e.get("text", "")):
                alerts.append(Alert(session, "exfil-in-output", "critical",
                                    "confidential canary present in model output"))
                break
    return alerts
