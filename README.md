# Agent Sentinel

### Pre-Execution Enforcement Boundary for Tool-Using AI Agents

Agent Sentinel is an experiment in building a hard execution boundary for autonomous AI systems that have tool access.

If an agent wants to execute a real action, delete a bucket, rotate credentials, stop logging, destroy infrastructure, that request should pass through a deterministic enforcement layer before anything runs.

This repository focuses on defining and testing that boundary.

## The problem

Most current agent "safety" mechanisms live in the system prompt. If the model is compromised (prompt injection), misconfigured, or simply wrong, that safety layer often fails with it.

Post-hoc auditing is also insufficient once agents can act quickly and repeatedly. By the time something is flagged, the action has already executed.

If agents are allowed to operate in real environments, enforcement needs to happen before execution — not after.

## The approach: pre-execution adjudication

This project implements a firewall for actions.

Before a tool call executes, it is evaluated against explicit, versioned policies and returns one of three decisions:

* **ALLOW** — the action satisfies policy constraints
* **BLOCK** — the action violates a hard rule
* **HUMAN_REQUIRED** — the action is sensitive and requires an explicit override

The system evaluates the structured action request itself, not the model’s reasoning about it.

This does not replace IAM. IAM defines static permissions. What this adds is a runtime adjudication layer capable of applying contextual rules (time of day, environment, break-glass overrides, sequence constraints) before execution.

## Current scope

The initial focus is on high-impact cloud actions and multi-step chains such as:

* Infrastructure destroy → disable logging → delete principal
* Data export → local staging → outbound network request

The dangerous cases are rarely single API calls. They are sequences.

This repository contains a minimal scaffold for:

* A structured action request schema
* A deterministic policy layer (Rego/OPA baseline)
* A sequence replay harness for adversarial testing
* A draft threat model

The implementation is intentionally small and testable.

## Design notes

The baseline policy layer is written in Rego (OPA). Rego is widely used in cloud-native security and provides a clear, declarative way to express deterministic rules.

It may ultimately prove heavier than necessary for simple agent schemas, but it is a useful starting point and benchmark. Early development will focus on measuring latency and operational overhead before committing to deeper integration.

The primary goal is not tool selection. It is defining a clean enforcement boundary that can be reasoned about, tested, and measured.

## Repository structure

* `schema/` — structured action request definition
* `policies/` — baseline deterministic rules
* `harness/` — adversarial sequence definitions
* `docs/` — threat model and implementation notes


## Roadmap

**Month 1**
Finalize the action schema and benchmark Rego against lighter alternatives with attention to latency and maintainability.

**Month 2**
Build the sequence replay harness and stress-test policies against destructive chains and bypass attempts.

**Month 3**
Tighten edge cases, document failure modes, and publish evaluation results alongside the reference implementation.



