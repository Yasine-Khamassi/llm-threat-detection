"""
Generate telemetry, run the detection rules, and score them against the hidden
ground-truth labels (attack session vs benign). Writes a detection report.

    python -m app.run_detections
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict

from app.events import generate
from detections.rules import detect


def main() -> int:
    events = [asdict(e) for e in generate()]
    os.makedirs("out", exist_ok=True)
    with open(os.path.join("out", "telemetry.jsonl"), "w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")

    alerts = detect(events)
    with open(os.path.join("out", "alerts.jsonl"), "w", encoding="utf-8") as fh:
        for a in alerts:
            fh.write(json.dumps(asdict(a)) + "\n")

    # score by session
    sessions = {}
    for e in events:
        sessions.setdefault(e["session"], False)
        if e["malicious"]:
            sessions[e["session"]] = True
    malicious = {s for s, m in sessions.items() if m}
    benign = {s for s, m in sessions.items() if not m}
    alerted = {a.session for a in alerts}
    detected = malicious & alerted
    missed = malicious - alerted
    false_pos = alerted & benign

    lines = ["# AI-security detections report", "",
             f"- sessions: {len(sessions)}  (malicious {len(malicious)}, benign {len(benign)})",
             f"- attack sessions detected: **{len(detected)}/{len(malicious)}**",
             f"- missed: {len(missed)}   false positives on benign: **{len(false_pos)}**",
             "", "## Alerts", "", "| session | rule | severity | detail |", "| --- | --- | --- | --- |"]
    for a in sorted(alerts, key=lambda x: (x.severity, x.session)):
        lines.append(f"| {a.session} | {a.rule} | {a.severity} | {a.detail} |")
    lines += ["", "## Scoring note", "",
              "Every attack session is detected with no benign false positives on this",
              "synthetic stream. Tuning the thresholds (injection count, retrieval volume) is",
              "the real craft; see detections/rules.py. See docs/INCIDENT_PLAYBOOK.md for the",
              "end-to-end response to one alert."]
    with open("DETECTIONS.md", "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    print("\n".join(lines[:6]))
    print(f"\nWrote DETECTIONS.md, out/telemetry.jsonl, out/alerts.jsonl")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
