# Agent Sentinel — MITRE ATT&CK for Cloud Mapping
**Day 1 Research Document | Agent Sentinel v0.1**  
Date: 2026-03-22  
Author: Agent Sentinel Research  
Framework: MITRE ATT&CK Enterprise v18 (October 2025)  
Scope: IaaS (AWS primary), SaaS-adjacent

---

## Purpose

This document maps the 15 highest-priority MITRE ATT&CK Cloud techniques to Agent Sentinel's enforcement architecture. For each technique, it defines:
- What the adversary does
- Which AWS API actions are implicated
- What Agent Sentinel's `/evaluate` endpoint should signal (ALLOW / BLOCK / HUMAN_REQUIRED)
- Risk score contribution to the weighted engine (0.0–1.0)
- Detection layer (pre-execution vs. post-execution vs. pattern)

This mapping forms the foundation of `actions.json` (Day 2) and the causal graph (Day 4).

---

## Tactic Coverage Summary

| Tactic | # Techniques Covered |
|---|---|
| Initial Access | 2 |
| Persistence | 2 |
| Privilege Escalation | 2 |
| Defense Evasion | 2 |
| Discovery | 3 |
| Exfiltration | 2 |
| Impact | 2 |

---

## Technique Mappings

---

### T1. T1078 — Valid Accounts (Cloud)
**Tactic:** Initial Access / Persistence / Defense Evasion  
**Platform:** IaaS, SaaS, Identity Provider

**What the adversary does:**  
Uses compromised credentials (IAM user keys, role tokens, SSO cookies) to authenticate as a legitimate principal. Extremely common — used by Scattered Spider, LAPSUS$, and most cloud ransomware campaigns. Blends with normal traffic.

**Implicated AWS API Actions:**
- `sts:AssumeRole`
- `iam:CreateAccessKey`
- `sts:GetCallerIdentity` (reconnaissance after login)
- `iam:ListUsers`, `iam:ListRoles`

**Agent Sentinel Enforcement:**
- Flag: Credential use from anomalous IP/geo, off-hours timing, unusual user-agent
- Decision: `HUMAN_REQUIRED` if new geography + off-hours; `BLOCK` if known revoked key
- Risk score contribution: **0.65–0.85** (context-dependent)

**Detection layer:** Behavioral baseline (Day 6) — deviation from established credential use patterns

---

### T2. T1190 — Exploit Public-Facing Application
**Tactic:** Initial Access  
**Platform:** IaaS

**What the adversary does:**  
Exploits vulnerabilities in externally accessible cloud services (APIs, web apps running on EC2/ECS, S3-hosted apps). Often the first step before lateral movement to IAM.

**Implicated AWS API Actions:**
- `ec2:DescribeInstances` (pre-exploit recon)
- Subsequent: `iam:GetInstanceProfile`, `sts:AssumeRole` (from compromised instance)

**Agent Sentinel Enforcement:**
- Flag: Rapid sequential describe + assume from a new EC2 instance profile
- Decision: `BLOCK` for role assumption immediately following new instance launch from unrecognized image
- Risk score contribution: **0.70**

**Detection layer:** Causal chain (Day 7) — new instance → immediate IAM enumeration pattern

---

### T3. T1136.003 — Create Cloud Account
**Tactic:** Persistence  
**Platform:** IaaS, Identity Provider

**What the adversary does:**  
Creates new IAM users, service accounts, or federated identities to maintain persistent access even after the initial compromise vector is remediated. A primary persistence technique — used in virtually every major cloud breach.

**Implicated AWS API Actions:**
- `iam:CreateUser`
- `iam:CreateAccessKey`
- `iam:AttachUserPolicy`
- `iam:AddUserToGroup`

**Agent Sentinel Enforcement:**
- Decision: `HUMAN_REQUIRED` for any `iam:CreateUser` outside approved provisioning workflows
- Decision: `BLOCK` for `iam:CreateUser` + `iam:AttachUserPolicy` (AdministratorAccess) in same session
- Risk score contribution: **0.80**

**Detection layer:** Pre-execution — this is exactly the enforcement gateway use case

---

### T4. T1098.001 — Additional Cloud Credentials
**Tactic:** Persistence  
**Platform:** IaaS

**What the adversary does:**  
Adds new access keys to existing IAM users or roles to maintain access while the legitimate user continues operating. Stealthy — no new accounts created, existing users just get extra keys.

**Implicated AWS API Actions:**
- `iam:CreateAccessKey` (on a user other than self)
- `iam:UpdateAccessKey`

**Agent Sentinel Enforcement:**
- Decision: `BLOCK` if agent creates access key for a user other than itself without human approval
- Decision: `HUMAN_REQUIRED` for any access key creation outside business hours
- Risk score contribution: **0.75**

**Detection layer:** Pre-execution policy enforcement

---

### T5. T1548.005 — Temporary Elevated Cloud Access
**Tactic:** Privilege Escalation  
**Platform:** IaaS

**What the adversary does:**  
Abuses role assumption chains to temporarily elevate permissions beyond what the original identity holds. STS assume-role chaining is the primary vector. Agent actions requesting high-privilege roles on demand are a prime risk scenario.

**Implicated AWS API Actions:**
- `sts:AssumeRole` (to a role with higher permissions)
- `sts:AssumeRoleWithWebIdentity`
- `iam:PassRole`

**Agent Sentinel Enforcement:**
- Decision: `HUMAN_REQUIRED` for assumption of any role with `*:*` or `iam:*` permissions
- Decision: `BLOCK` for cross-account role assumption not on approved allowlist
- Risk score contribution: **0.85**

**Detection layer:** Pre-execution + policy enforcement (PolicyV1)

---

### T6. T1078.004 — Cloud Accounts (Privilege Escalation variant)
**Tactic:** Privilege Escalation / Defense Evasion  
**Platform:** IaaS

**What the adversary does:**  
Uses existing valid cloud account credentials but switches to higher-privileged roles or escalates via IAM permission boundaries. Often combined with T1548.005.

**Implicated AWS API Actions:**
- `iam:PutUserPolicy` (inline policy attachment)
- `iam:AttachUserPolicy`
- `iam:CreatePolicyVersion` (replacing policy with more permissive version)

**Agent Sentinel Enforcement:**
- Decision: `BLOCK` for any inline policy creation granting `iam:*` or `s3:*`
- Risk score contribution: **0.80**

**Detection layer:** Pre-execution — policy action classification

---

### T7. T1562.008 — Impair Defenses: Disable Cloud Logs
**Tactic:** Defense Evasion  
**Platform:** IaaS

**What the adversary does:**  
Disables or modifies CloudTrail, Config, GuardDuty, or VPC Flow Logs to blind defenders before executing the primary attack. Often the first action after initial privilege escalation.

**Implicated AWS API Actions:**
- `cloudtrail:StopLogging`
- `cloudtrail:DeleteTrail`
- `guardduty:DeleteDetector`
- `config:DeleteConfigRule`
- `config:StopConfigurationRecorder`

**Agent Sentinel Enforcement:**
- Decision: **`BLOCK` unconditionally** — no legitimate agent workflow should disable audit infrastructure
- Risk score contribution: **1.0** (maximum, hardcoded block)

**Detection layer:** Pre-execution, zero-tolerance policy

---

### T8. T1578 — Modify Cloud Compute Infrastructure
**Tactic:** Defense Evasion  
**Platform:** IaaS

**What the adversary does:**  
Creates or modifies compute resources (snapshots, AMIs, instances) to evade detection, establish persistence, or modify the attack surface. Includes creating snapshots of volumes to exfiltrate data without touching S3.

**Implicated AWS API Actions:**
- `ec2:CreateSnapshot`
- `ec2:ModifySnapshotAttribute` (making it public or sharing to attacker account)
- `ec2:CopySnapshot` (cross-region or cross-account)
- `ec2:CreateImage`

**Agent Sentinel Enforcement:**
- Decision: `HUMAN_REQUIRED` for snapshot sharing to any external account
- Decision: `BLOCK` for `ModifySnapshotAttribute` making snapshot public
- Risk score contribution: **0.75**

**Detection layer:** Pre-execution + causal chain (snapshot creation → cross-account share sequence)

---

### T9. T1580 — Cloud Infrastructure Discovery
**Tactic:** Discovery  
**Platform:** IaaS

**What the adversary does:**  
Systematically enumerates cloud resources — instances, snapshots, storage buckets, databases, Lambda functions, VPCs — to understand the environment before attacking. Often the first post-access action.

**Implicated AWS API Actions:**
- `ec2:DescribeInstances`
- `ec2:DescribeSnapshots`
- `s3:ListAllMyBuckets`
- `rds:DescribeDBInstances`
- `lambda:ListFunctions`
- `ec2:DescribeVpcs`

**Agent Sentinel Enforcement:**
- Single describe call: `ALLOW`
- Broad enumeration burst (5+ describe calls in 30 seconds): `HUMAN_REQUIRED`
- Full environment sweep pattern: `BLOCK`
- Risk score contribution: **0.40** (single) → **0.80** (sweep pattern)

**Detection layer:** Behavioral baseline + rate analysis

---

### T10. T1538 — Cloud Service Dashboard
**Tactic:** Discovery  
**Platform:** IaaS, SaaS

**What the adversary does:**  
Abuses access to cloud management consoles (AWS Console, Azure Portal) to discover resources, exfiltrate configurations, or modify settings without leaving API-level traces that standard CloudTrail covers.

**Implicated AWS API Actions:**
- Console sign-in events (CloudTrail `ConsoleLogin`)
- `iam:GetAccountSummary`
- `billing:GetBillingData`

**Agent Sentinel Enforcement:**
- Flag: Agent-initiated console sessions (agents should use API, not console)
- Decision: `BLOCK` for programmatic agents attempting console federation
- Risk score contribution: **0.60**

**Detection layer:** Behavioral — agents don't normally use console sign-in

---

### T11. T1526 — Cloud Service Discovery
**Tactic:** Discovery  
**Platform:** IaaS, SaaS

**What the adversary does:**  
Enumerates available cloud services and their configurations to identify attack surface. Differs from T1580 in scope — this targets service configuration rather than compute resources.

**Implicated AWS API Actions:**
- `iam:ListPolicies`, `iam:GetPolicy`
- `ec2:DescribeSecurityGroups`
- `ec2:DescribeNetworkAcls`
- `sts:GetCallerIdentity`
- `organizations:DescribeOrganization`

**Agent Sentinel Enforcement:**
- Flag: `organizations:DescribeOrganization` — rare, high-value for attackers
- Decision: `HUMAN_REQUIRED` for organization-level enumeration
- Risk score contribution: **0.55**

**Detection layer:** Pre-execution policy + behavioral

---

### T12. T1530 — Data from Cloud Storage
**Tactic:** Exfiltration (Collection)  
**Platform:** IaaS, SaaS

**What the adversary does:**  
Directly accesses data stored in S3, Azure Blob, or GCS. Doesn't require exfiltration tooling — just valid credentials and the right bucket permissions. One of the most common cloud data breach vectors.

**Implicated AWS API Actions:**
- `s3:GetObject`
- `s3:ListBucket`
- `s3:GetBucketAcl`
- `s3:GetBucketPolicy`

**Agent Sentinel Enforcement:**
- Single GetObject: `ALLOW` (normal operation)
- Burst download (100+ objects in 60 seconds): `HUMAN_REQUIRED`
- Cross-account or public bucket access: `BLOCK`
- Risk score contribution: **0.35** (single) → **0.85** (bulk exfil pattern)

**Detection layer:** Rate-based behavioral + causal chain

---

### T13. T1537 — Transfer Data to Cloud Account
**Tactic:** Exfiltration  
**Platform:** IaaS

**What the adversary does:**  
Exfiltrates data by transferring it to an attacker-controlled cloud account — via S3 bucket replication, snapshot sharing, or RDS snapshot export. Leaves minimal traces in the victim's environment.

**Implicated AWS API Actions:**
- `s3:PutBucketReplication` (to external account)
- `ec2:ModifySnapshotAttribute` (share to external account)
- `rds:CopyDBSnapshot` (cross-account)
- `s3:PutObject` (to external bucket via cross-account role)

**Agent Sentinel Enforcement:**
- Decision: **`BLOCK` unconditionally** for any replication/sharing to unrecognized external AWS account IDs
- Risk score contribution: **0.95**

**Detection layer:** Pre-execution — account ID allowlist enforcement

---

### T14. T1648 — Serverless Execution
**Tactic:** Execution  
**Platform:** IaaS

**What the adversary does:**  
Abuses Lambda, Azure Functions, or GCP Cloud Functions to execute arbitrary code. Can be used to bypass host-based detection, establish persistence via event triggers, or proxy malicious actions through legitimate cloud infrastructure.

**Implicated AWS API Actions:**
- `lambda:CreateFunction`
- `lambda:UpdateFunctionCode`
- `lambda:AddPermission`
- `lambda:InvokeFunction`
- `events:PutRule` (EventBridge trigger for persistence)

**Agent Sentinel Enforcement:**
- Decision: `HUMAN_REQUIRED` for Lambda creation with an execution role above read-only
- Decision: `BLOCK` for Lambda creation + EventBridge trigger in same session (persistence pattern)
- Risk score contribution: **0.70**

**Detection layer:** Causal chain — Lambda create → trigger creation sequence

---

### T15. T1485 — Data Destruction
**Tactic:** Impact  
**Platform:** IaaS

**What the adversary does:**  
Deletes cloud resources — S3 buckets, RDS databases, EC2 instances, snapshots — to cause maximum damage, often as the final stage of a ransomware or destructive attack. Increasingly common in cloud ransomware (e.g., groups targeting poorly secured S3).

**Implicated AWS API Actions:**
- `s3:DeleteBucket`
- `s3:DeleteObjects`
- `rds:DeleteDBInstance` (with skip-final-snapshot=true)
- `ec2:TerminateInstances`
- `dynamodb:DeleteTable`

**Agent Sentinel Enforcement:**
- Decision: **`BLOCK` unconditionally** for bulk delete operations (10+ resources in one session)
- Decision: `HUMAN_REQUIRED` for any RDS deletion or DynamoDB table deletion
- Risk score contribution: **1.0** (maximum)

**Detection layer:** Pre-execution — zero-tolerance for bulk destructive operations

---

## Risk Score Summary Table

| # | Technique | ID | Base Risk Score | Enforcement Default |
|---|---|---|---|---|
| 1 | Valid Accounts | T1078 | 0.65–0.85 | HUMAN_REQUIRED |
| 2 | Exploit Public-Facing App | T1190 | 0.70 | BLOCK (pattern) |
| 3 | Create Cloud Account | T1136.003 | 0.80 | HUMAN_REQUIRED |
| 4 | Additional Cloud Credentials | T1098.001 | 0.75 | BLOCK |
| 5 | Temporary Elevated Access | T1548.005 | 0.85 | HUMAN_REQUIRED |
| 6 | Cloud Account Priv Esc | T1078.004 | 0.80 | BLOCK |
| 7 | Disable Cloud Logs | T1562.008 | **1.0** | **BLOCK (hardcoded)** |
| 8 | Modify Compute Infrastructure | T1578 | 0.75 | HUMAN_REQUIRED |
| 9 | Cloud Infrastructure Discovery | T1580 | 0.40–0.80 | ALLOW→BLOCK (rate) |
| 10 | Cloud Service Dashboard | T1538 | 0.60 | BLOCK (agent) |
| 11 | Cloud Service Discovery | T1526 | 0.55 | HUMAN_REQUIRED |
| 12 | Data from Cloud Storage | T1530 | 0.35–0.85 | ALLOW→HUMAN (rate) |
| 13 | Transfer to Cloud Account | T1537 | **0.95** | **BLOCK (hardcoded)** |
| 14 | Serverless Execution | T1648 | 0.70 | HUMAN_REQUIRED |
| 15 | Data Destruction | T1485 | **1.0** | **BLOCK (hardcoded)** |

---

## Hardcoded Blocks (Zero-Tolerance)

Three techniques receive hardcoded BLOCK regardless of policy version or context:

| Technique | Reason |
|---|---|
| T1562.008 — Disable Cloud Logs | No legitimate agent workflow disables its own audit trail |
| T1537 — Transfer to External Account | Data leaving the AWS account is irreversible |
| T1485 — Data Destruction | Bulk resource deletion is irreversible |

These are encoded directly into the enforcement gateway, not the PolicyV1 DynamoDB store. They cannot be overridden by policy.

---

## Causal Chains for Day 4 (NetworkX Graph)

The following sequences represent multi-step attack paths that, individually, might score below the block threshold but together constitute high-confidence attack patterns:

**Chain A — Persistence after Initial Access:**
`sts:AssumeRole` → `iam:CreateUser` → `iam:CreateAccessKey` → `iam:AttachUserPolicy`  
Composite risk: **0.92**

**Chain B — Exfiltration via Snapshot:**
`ec2:CreateSnapshot` → `ec2:ModifySnapshotAttribute` (external share) → `ec2:CopySnapshot`  
Composite risk: **0.95**

**Chain C — Serverless Persistence:**
`lambda:CreateFunction` → `iam:PassRole` → `events:PutRule`  
Composite risk: **0.88**

**Chain D — Log Blind + Destroy:**
`cloudtrail:StopLogging` → `s3:DeleteBucket` / `rds:DeleteDBInstance`  
Composite risk: **1.0** (Chain A already triggers at step 1)

**Chain E — Discovery Sweep → Privilege Escalation:**
`s3:ListAllMyBuckets` + `ec2:DescribeInstances` + `iam:ListPolicies` (within 60s) → `sts:AssumeRole`  
Composite risk: **0.85**

---

## Next Steps

- **Day 2:** Build `actions.json` — comprehensive AWS API action → risk score + tactic mapping
- **Day 4:** Encode Chains A–E as directed graph in NetworkX; add edge weights from this doc
- **Day 6:** Train Isolation Forest baseline on normal agent API call sequences; flag deviations from T1580 / T1526 sweep patterns
- **Day 9:** Use LLM intent reasoning (Bedrock) to classify ambiguous agent requests against this tactic library

---

*Agent Sentinel — AI enforcement gateway for autonomous agents*  
*This document is proprietary and confidential.*