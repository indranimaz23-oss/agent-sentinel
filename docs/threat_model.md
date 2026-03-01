# Threat model (draft)

## In scope
- LLM agents with tool access proposing high-impact API calls
- Prompt injection or planner mistakes leading to unsafe actions
- Multi-step action chains (e.g., disable logging, escalate privileges, destructive cleanup)
- Time-based and environment-based enforcement (e.g., prod after-hours controls)

## Out of scope
- Replacing IAM / cloud-native permission systems
- A general “AI auditor” that judges intent or morality
- Post-hoc incident response and forensic tooling
- Defending against a fully privileged insider with unrestricted credentials

## Assumptions
- The enforcement boundary sees the structured request before execution
- Caller identity / principal context is available at evaluation time
- “Break-glass” is handled via an explicit override artifact with expiry and audit trail
