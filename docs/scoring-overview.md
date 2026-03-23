# Agent Sentinel: Risk Scoring Overview

**Version:** 1.0
**Date:** 2026-03-23

---

## Overview

Agent Sentinel evaluates every AWS API action requested by an autonomous
agent before it reaches the AWS API. Each action receives a risk
assessment and a structured enforcement decision: ALLOW, BLOCK, or
HUMAN_REQUIRED.

---

## The Problem with Single-Engine Scoring

Existing cloud security tools treat AI agents like human users. They
apply a single threat model optimized for known attacker behavior.

This misses an entire class of danger unique to autonomous agents:
behavioral boundary violations. An agent acting outside its defined role
is dangerous regardless of whether its actions match known attack
patterns. A confused agent and a compromised agent can cause identical
damage through completely different paths.

---

## The Dual Engine Approach

Agent Sentinel uses two independent scoring engines running in parallel.

### Engine 1 -- Behavioral Boundary Engine

Evaluates whether the agent is acting within its defined role and
behavioral history. Does not reference attacker behavior. Focused
entirely on agent integrity and scope compliance.

Catches:
- Agents acting outside their defined purpose
- Irreversible actions with no prior behavioral precedent
- Actions anomalous given the agent's role and history

### Engine 2 -- Threat Intelligence Engine

Evaluates whether the action matches known adversarial patterns from
real cloud breaches. Grounded in MITRE ATT&CK for Cloud and real
incident data. Does not penalize legitimate agent behavior.

Catches:
- Known credential abuse patterns
- Privilege escalation chains
- Data exfiltration techniques
- Infrastructure reconnaissance sweeps

### Why Two Engines

The two engines are mathematically independent and catch fundamentally
different threat classes. An action that scores low on one engine may
score high on the other. Using an OR gate between the two engines
ensures neither class of danger escapes detection.

We call this stereoscopic vision. One engine sees the agent's internal
logic. The other sees the external battlefield.

---

## Decision Architecture

Agent Sentinel uses a three-tier decision architecture:

**BLOCK** -- High confidence threat or safety violation. Action is
stopped before reaching AWS. No human override at runtime.

**HUMAN_REQUIRED** -- Medium confidence signal from either engine, or
correlated medium signals from both engines together. Action is paused
and escalated to a human operator for review.

**ALLOW** -- Action is consistent with the agent's defined role and does
not match known threat patterns. Action proceeds to AWS.

Certain actions are hardcoded blocks regardless of score. No policy can
override them. These are actions where the potential for irreversible
harm is so high that no legitimate agent workflow should ever require
them.

---

## Scoring Factors

Both engines evaluate four factors for each AWS API action. The factors
are the same across both engines. The weights assigned to each factor
differ based on each engine's philosophy.

The four factors are:

- Impact -- how much damage if this action succeeds
- Prevalence -- how commonly real attackers use this technique
- Irreversibility -- whether the damage can be undone
- Legitimacy Inverse -- how unlikely a normal agent is to need this action

Weights were derived using the Analytic Hierarchy Process, a formal
multi-criteria decision analysis methodology developed by Thomas Saaty.
The full methodology including pairwise comparison matrices, derived
weights, and consistency ratios is available to verified researchers and
enterprise partners on request.

---

## MITRE ATT&CK Grounding

Every AWS API action in Agent Sentinel's enforcement layer is mapped to
one or more MITRE ATT&CK for Cloud techniques. This grounds every
enforcement decision in a publicly documented, industry-standard threat
taxonomy.

The full technique mapping is available in our research documentation.

---

## Validation

The dual engine scoring system will be validated against a synthetic
dataset of agent API call sequences spanning normal operations and
adversarial scenarios. Results will be published in our arXiv paper.

A sensitivity analysis comparing the AHP-derived weights against
alternative weight sets including the classical Risk = Likelihood x
Impact model will be included in the paper.

---

*Agent Sentinel -- AI enforcement gateway for autonomous agents*
*For research inquiries contact: agentsentinel.co*