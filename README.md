# Agent Sentinel

### Pre-Execution Enforcement Boundary for Tool-Using AI Agents

Agent Sentinel is an experiment in building a pre-execution enforcement boundary for tool-using AI agents.

If an agent wants to execute a real action in a live environment, that request should be evaluated deterministically before anything runs.

This repository defines and tests that boundary.

## The problem

Most current agent safety mechanisms live in the system prompt. If the agent is injected, misconfigured, or simply wrong, that safety layer often fails with it.

Auditing after the fact is not enough once agents can act quickly and repeatedly. The decision to allow or block an action has to happen before execution.

## The approach

This project implements a firewall for actions.

Before a tool call executes, it is evaluated against explicit, versioned policies and returns one of three decisions:

* **ALLOW** — the action satisfies policy constraints
* **BLOCK** — the action violates a hard rule
* **HUMAN_REQUIRED** — the action is sensitive and requires an explicit override

The system evaluates the structured action request itself, not the model’s reasoning about it.

This does not replace IAM. IAM defines static permissions. What this adds is a runtime adjudication layer capable of applying contextual rules (time of day, environment, break-glass overrides, sequence constraints) before execution.

The initial prototype uses deterministic policies as a baseline layer, with future work exploring risk scoring and sequence-aware evaluation for multi-step agent actions.

## Current scope

The initial focus is destructive cloud operations and multi-step chains such as:

* Infrastructure destroy → disable logging → delete principal
* Data export → local staging → outbound network request

The dangerous cases are rarely single API calls. They are sequences.

What is included here:

* A structured action request schema
* A baseline policy layer written in Rego (OPA)
* A small sequence replay harness for testing multi-step chains
* A draft threat model

The implementation is intentionally small and testable.

## Design notes

The baseline policy layer is written in Rego (OPA). Rego is widely used in cloud-native security and provides a clear, declarative way to express deterministic rules.

It may prove heavier than necessary for simple agent schemas. Latency and operational overhead will be measured before committing to deeper integration.

The primary goal is not tool selection. It is defining a clean enforcement boundary that can be reasoned about, tested, and measured.

## Repository structure

* `schema/` — structured action request definition
* `policies/` — baseline deterministic rules
* `harness/` — adversarial sequence definitions
* `docs/` — threat model and implementation notes


## Roadmap

**Month 1**
Finalize the schema and benchmark Rego for latency and maintainability.

**Month 2**
Expand the sequence replay harness and test for policy gaps across chained actions.

**Month 3**
Document failure modes and publish evaluation results alongside the reference implementation.


