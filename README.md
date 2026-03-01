# Agent Sentinel
### Reference Implementation & Evaluation Harness

Agent Sentinel is a security primitive designed to sit between autonomous AI agents and tool-execution environments (cloud APIs, internal tools, operator scripts).

**The goal:** move agent safety from probabilistic prompt-layer “guardrails” to a deterministic, pre-execution enforcement boundary.

## The problem
Most agent safety today relies on system prompts. If an agent is compromised (prompt injection) or simply wrong, the safety layer often fails with it. Post-hoc auditing is too slow for fast-acting agents that can execute many actions quickly.

## The solution: pre-execution adjudication
This project implements a “firewall for actions.” Before a tool call executes, it is evaluated against versioned, deterministic policies.

Decisions:
- **ALLOW**: action meets policy criteria
- **BLOCK**: action violates a hard rule (e.g., “no destructive actions after hours”)
- **HUMAN_REQUIRED**: action is sensitive and requires out-of-band approval

## Components
1. **Deterministic policy engine**
   - evaluates structured action requests against Rego/OPA (or a small JSON-logic baseline)
   - returns a decision + machine-readable reason

2. **Action-sequence evaluation harness**
   - replays multi-step “destructive chains”
   - measures missed blocks, false blocks, and policy bypass attempts

## Repository layout
- `schema/` — action request schema (the “what”)
- `policies/` — baseline policies (the “how”)
- `harness/` — adversarial sequences and replay cases (the “stress test”)
- `docs/` — threat model and notes

## Roadmap
- **Month 1:** schema finalization + Rego vs JSON-logic benchmarking (latency + maintainability)
- **Month 2:** sequence replay engine + adversarial scenario generation
- **Month 3:** evaluation report + hardened reference implementation
