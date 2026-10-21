# AI-security detections report

- sessions: 17  (malicious 5, benign 12)
- attack sessions detected: **5/5**
- missed: 0   false positives on benign: **0**

## Alerts

| session | rule | severity | detail |
| --- | --- | --- | --- |
| sess-attack-exfil-0 | exfil-in-output | critical | confidential canary present in model output |
| sess-attack-agent-0 | denied-tool-call | high | blocked tool query_inventory (restricted_resource) |
| sess-attack-inj-0 | repeated-injection | high | 4 injection/jailbreak prompts in one session |
| sess-attack-secret-0 | secret-in-prompt | high | credential-shaped string submitted in a prompt |
| sess-attack-scrape-0 | anomalous-retrieval | medium | retrieval of 40 chunks (possible scraping) |

## Scoring note

Every attack session is detected with no benign false positives on this
synthetic stream. Tuning the thresholds (injection count, retrieval volume) is
the real craft; see detections/rules.py. See docs/INCIDENT_PLAYBOOK.md for the
end-to-end response to one alert.
