# Threat model (draft)

## In scope
- LLM agents with tool access proposing high-impact API calls
- Prompt injection or planner mistakes leading to unsafe actions
- Multi-step action chains (for example: disable logging → escalate privileges → destructive cleanup)
- Time-based and environment-based enforcement (e.g., prod after-hours controls)

The focus is on reducing risk at the moment of execution, particularly for actions that are irreversible or high-impact.


## Out of scope
- Replacing IAM or existing cloud-native permission systems
- Building a general-purpose “AI auditor” that evaluates intent
- Post-hoc incident response or forensic tooling
- Defending against a fully privileged insider with unrestricted credentials

This project assumes standard cloud security controls remain in place. The boundary described here is additive.
  

## Assumptions
- The enforcement layer receives a structured action request before execution
- Caller identity and principal context are available at evaluation time
- “Break-glass” overrides are explicit, time-bound, and auditable

These assumptions keep the scope constrained and testable.
