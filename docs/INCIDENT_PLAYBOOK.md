# Incident playbook — AI agent restricted-resource attempt

One alert, walked end to end. The triggering alert is `denied-tool-call` (high) on
`sess-attack-agent-0`: the IT-support agent attempted `query_inventory` on
`RESTRICTED-ASSET-9` after reading a poisoned onboarding document.

## 1. Validate the alert
- Pull the session's events from `out/telemetry.jsonl`. Confirm the sequence:
  `read_docs(vendor-onboarding)` → attempted `query_inventory(RESTRICTED-ASSET-9)`
  which the gateway **denied** (`reason=restricted_resource`).
- Confirm it is a true positive: the restricted call was attempted but **not
  executed** (the gateway log shows `allowed:false`). No restricted data left the
  system. This is an attempted, contained incident, not a breach.

## 2. Preserve evidence
- Snapshot the full session transcript and the gateway tool-call log (immutable copy).
- Record: the document that carried the injection (`vendor-onboarding`), the agent
  identity, the user on whose behalf it ran, and timestamps.

## 3. Contain / revoke
- Quarantine the poisoned document so it is not retrieved again.
- Rotate the agent's scoped credential and, if the agent identity is distinct and
  attributable (project 3 design), revoke its current token.
- Confirm the per-task allow-list still excludes `query_inventory` for this workflow.

## 4. Assess exposure
- Because the action was denied pre-execution, exposure is none for this attempt.
- Search telemetry for other sessions that read the same document or attempted the
  same tool/asset, to catch a wider campaign (the `denied-tool-call` and
  `anomalous-retrieval` rules help here).

## 5. Communicate
- Short factual note to the system owner: what was attempted, that it was blocked by
  the authorization gateway, what was rotated, and the fix (document quarantined).
- Log the finding into the risk register (project 5) and open a remediation ticket
  to add content provenance / injection screening on document ingestion.

## Mapping
- OWASP: LLM01 Prompt Injection → LLM06 Excessive Agency; detection is the LLM
  monitoring layer.
- MITRE ATLAS: AML.T0051 (prompt injection), AML.T0057 (data from the AI system).
