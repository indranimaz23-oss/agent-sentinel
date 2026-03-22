# Agent Sentinel: MITRE ATT&CK for Cloud Mapping
**Day 1 Research Document | Agent Sentinel v0.1**
Date: 2026-03-22
Author: Agent Sentinel Research
Framework: MITRE ATT&CK Enterprise v18 (October 2025)
Scope: IaaS (AWS primary), SaaS-adjacent

---

## Purpose

This document maps 15 high-priority MITRE ATT&CK Cloud techniques to Agent Sentinel's enforcement logic. For each technique we describe what an attacker does, which AWS API calls are involved, what decision Agent Sentinel should make, and how much risk weight that technique carries.

This mapping is the foundation for actions.json (Day 2) and the causal graph (Day 4).

---

## Tactic Coverage Summary

| Tactic | Techniques Covered |
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

### T1. T1078 - Valid Accounts (Cloud)
**Tactic:** Initial Access / Persistence / Defense Evasion
**Platform:** IaaS, SaaS, Identity Provider

**What the attacker does:**
Uses compromised credentials to log in as a legitimate user. This could be a stolen IAM key, a leaked role token, or an SSO cookie grabbed from a browser. From AWS's perspective the login looks completely normal. Real attack groups like Scattered Spider and LAPSUS$ rely on this heavily because it blends in with regular traffic.

**AWS API calls involved:**
- `sts:AssumeRole`
- `iam:CreateAccessKey`
- `sts:GetCallerIdentity` (used to confirm access after login)
- `iam:ListUsers`, `iam:ListRoles`

**Agent Sentinel decision:**
- HUMAN_REQUIRED if the credential is used from a new location or outside business hours
- BLOCK if the key is known to be revoked
- Risk score: 0.65 to 0.85 depending on context

**How we detect it:** Behavioral baseline (Day 6). We look for deviation from the normal pattern of how that credential is used.

---

### T2. T1190 - Exploit Public-Facing Application
**Tactic:** Initial Access
**Platform:** IaaS

**What the attacker does:**
Finds a vulnerability in something exposed to the internet, like a web app or API running on EC2. They exploit it to get code execution on the server. Once inside the machine, they hit the EC2 instance metadata endpoint at 169.254.169.254 to grab the IAM role credentials that are automatically available to anything running on that instance. No key theft needed. The credentials were just there.

**AWS API calls involved:**
- `ec2:DescribeInstances` (recon before exploit)
- `iam:GetInstanceProfile` and `sts:AssumeRole` (after getting inside)

**Agent Sentinel decision:**
- BLOCK if a new EC2 instance profile immediately starts doing IAM enumeration right after launch
- Risk score: 0.70

**How we detect it:** Causal chain detection (Day 7). New instance launch followed immediately by IAM calls is a red flag pattern.

---

### T3. T1136.003 - Create Cloud Account
**Tactic:** Persistence
**Platform:** IaaS, Identity Provider

**What the attacker does:**
Creates a new IAM user or service account so they can keep access even after the original compromise is discovered and cleaned up. This is one of the most common persistence techniques in real cloud breaches. The attacker creates the account, attaches permissions, and now has a backdoor that survives incident response.

**AWS API calls involved:**
- `iam:CreateUser`
- `iam:CreateAccessKey`
- `iam:AttachUserPolicy`
- `iam:AddUserToGroup`

**Agent Sentinel decision:**
- HUMAN_REQUIRED for any iam:CreateUser call outside an approved provisioning workflow
- BLOCK if CreateUser and AttachUserPolicy with AdministratorAccess happen in the same session
- Risk score: 0.80

**How we detect it:** Pre-execution enforcement. This is exactly what the gateway is built for.

---

### T4. T1098.001 - Additional Cloud Credentials
**Tactic:** Persistence
**Platform:** IaaS

**What the attacker does:**
Instead of creating a new user, they add extra access keys to an existing one. The real user keeps working normally and notices nothing. The attacker now has a second set of keys for the same account. Very hard to spot without monitoring.

**AWS API calls involved:**
- `iam:CreateAccessKey` on a user other than the caller
- `iam:UpdateAccessKey`

**Agent Sentinel decision:**
- BLOCK if an agent creates an access key for any user other than itself without human approval
- HUMAN_REQUIRED for access key creation outside business hours
- Risk score: 0.75

**How we detect it:** Pre-execution policy enforcement.

---

### T5. T1548.005 - Temporary Elevated Cloud Access
**Tactic:** Privilege Escalation
**Platform:** IaaS

**What the attacker does:**
Chains together role assumptions to temporarily grab more permissions than the original identity is supposed to have. AWS STS lets you assume one role from another, and if the trust policies are not set up carefully an attacker can hop through roles until they reach something very powerful. AI agents that request high-privilege roles on demand are a clear risk here.

**AWS API calls involved:**
- `sts:AssumeRole` targeting a higher-privilege role
- `sts:AssumeRoleWithWebIdentity`
- `iam:PassRole`

**Agent Sentinel decision:**
- HUMAN_REQUIRED for assumption of any role that has iam:* or *:* permissions
- BLOCK for cross-account role assumption not on an approved list
- Risk score: 0.85

**How we detect it:** Pre-execution enforcement using PolicyV1 rules.

---

### T6. T1078.004 - Cloud Accounts (Privilege Escalation)
**Tactic:** Privilege Escalation / Defense Evasion
**Platform:** IaaS

**What the attacker does:**
Uses an existing valid account but modifies its own permissions to escalate privileges. For example, attaching a new inline policy that grants admin access, or replacing an existing policy with a more permissive version. Often used alongside T5 above.

**AWS API calls involved:**
- `iam:PutUserPolicy`
- `iam:AttachUserPolicy`
- `iam:CreatePolicyVersion`

**Agent Sentinel decision:**
- BLOCK for any inline policy that grants iam:* or s3:*
- Risk score: 0.80

**How we detect it:** Pre-execution policy action classification.

---

### T7. T1562.008 - Disable Cloud Logs
**Tactic:** Defense Evasion
**Platform:** IaaS

**What the attacker does:**
Turns off CloudTrail, GuardDuty, Config, or VPC Flow Logs before doing anything else. This blinds the defenders. By the time anyone notices the logs are gone, the real damage may already be done. This is often the very first action after gaining elevated access.

**AWS API calls involved:**
- `cloudtrail:StopLogging`
- `cloudtrail:DeleteTrail`
- `guardduty:DeleteDetector`
- `config:DeleteConfigRule`
- `config:StopConfigurationRecorder`

**Agent Sentinel decision:**
- BLOCK unconditionally. No legitimate agent workflow should ever disable audit infrastructure.
- Risk score: 1.0 (hardcoded maximum)

**How we detect it:** Pre-execution, zero-tolerance. This block lives in the gateway source code, not in the policy store.

---

### T8. T1578 - Modify Cloud Compute Infrastructure
**Tactic:** Defense Evasion
**Platform:** IaaS

**What the attacker does:**
Creates or modifies compute resources like snapshots or AMIs to establish persistence or exfiltrate data. A common trick is to snapshot an EBS volume and then share that snapshot to an attacker-controlled AWS account. The data leaves without ever touching S3 or triggering typical data loss alerts.

**AWS API calls involved:**
- `ec2:CreateSnapshot`
- `ec2:ModifySnapshotAttribute` (to share it externally or make it public)
- `ec2:CopySnapshot`
- `ec2:CreateImage`

**Agent Sentinel decision:**
- HUMAN_REQUIRED for any snapshot shared to an external account
- BLOCK for ModifySnapshotAttribute that makes a snapshot public
- Risk score: 0.75

**How we detect it:** Pre-execution plus causal chain. Snapshot creation followed by cross-account sharing is the pattern to catch.

---

### T9. T1580 - Cloud Infrastructure Discovery
**Tactic:** Discovery
**Platform:** IaaS

**What the attacker does:**
Systematically lists everything in the AWS environment. Instances, snapshots, buckets, databases, Lambda functions, VPCs. This is almost always the first thing an attacker does after getting credentials. They need to understand what they have access to before deciding what to attack.

**AWS API calls involved:**
- `ec2:DescribeInstances`
- `ec2:DescribeSnapshots`
- `s3:ListAllMyBuckets`
- `rds:DescribeDBInstances`
- `lambda:ListFunctions`
- `ec2:DescribeVpcs`

**Agent Sentinel decision:**
- ALLOW for a single describe call (normal agent behavior)
- HUMAN_REQUIRED for 5 or more describe calls within 30 seconds
- BLOCK for a full environment sweep pattern
- Risk score: 0.40 for a single call, up to 0.80 for a sweep

**How we detect it:** Behavioral baseline plus rate analysis.

---

### T10. T1538 - Cloud Service Dashboard
**Tactic:** Discovery
**Platform:** IaaS, SaaS

**What the attacker does:**
Uses the AWS Management Console rather than API calls to look around. Console activity is sometimes logged differently or less completely than direct API calls depending on how CloudTrail is configured. An attacker who knows this can use the console to gather information with less visibility.

**AWS API calls involved:**
- Console sign-in events in CloudTrail
- `iam:GetAccountSummary`
- `billing:GetBillingData`

**Agent Sentinel decision:**
- BLOCK for any programmatic agent attempting to start a console session. Agents should use the API, not the console.
- Risk score: 0.60

**How we detect it:** Behavioral. Console sign-in from a programmatic agent is anomalous by definition.

---

### T11. T1526 - Cloud Service Discovery
**Tactic:** Discovery
**Platform:** IaaS, SaaS

**What the attacker does:**
Enumerates the configuration of cloud services rather than the resources themselves. Things like security group rules, network ACLs, IAM policies, and organization structure. This helps the attacker understand what protections are in place and where the gaps are.

**AWS API calls involved:**
- `iam:ListPolicies`, `iam:GetPolicy`
- `ec2:DescribeSecurityGroups`
- `ec2:DescribeNetworkAcls`
- `sts:GetCallerIdentity`
- `organizations:DescribeOrganization`

**Agent Sentinel decision:**
- HUMAN_REQUIRED for any organization-level enumeration. That call is rarely needed by a normal agent and is high value for an attacker.
- Risk score: 0.55

**How we detect it:** Pre-execution policy plus behavioral baseline.

---

### T12. T1530 - Data from Cloud Storage
**Tactic:** Collection / Exfiltration
**Platform:** IaaS, SaaS

**What the attacker does:**
Reads data directly from S3 buckets or similar cloud storage. Does not need special tools. Just valid credentials and bucket access. This is one of the most common ways data actually leaves an organization in a cloud breach.

**AWS API calls involved:**
- `s3:GetObject`
- `s3:ListBucket`
- `s3:GetBucketAcl`
- `s3:GetBucketPolicy`

**Agent Sentinel decision:**
- ALLOW for a single GetObject (normal operation)
- HUMAN_REQUIRED if 100 or more objects are downloaded within 60 seconds
- BLOCK for access to a public bucket or a bucket in a different AWS account
- Risk score: 0.35 for a single call, up to 0.85 for a bulk download pattern

**How we detect it:** Rate-based behavioral analysis plus causal chain.

---

### T13. T1537 - Transfer Data to Cloud Account
**Tactic:** Exfiltration
**Platform:** IaaS

**What the attacker does:**
Moves data to an AWS account they control. This can be done through S3 bucket replication rules, sharing EBS snapshots cross-account, or exporting RDS snapshots to another account. The data leaves the victim's AWS environment entirely and may be gone for good.

**AWS API calls involved:**
- `s3:PutBucketReplication` pointing to an external account
- `ec2:ModifySnapshotAttribute` to share to an external account
- `rds:CopyDBSnapshot` cross-account
- `s3:PutObject` to a bucket in another account

**Agent Sentinel decision:**
- BLOCK unconditionally for any replication or sharing to an AWS account ID not on the approved list.
- Risk score: 0.95

**How we detect it:** Pre-execution enforcement with an account ID allowlist.

---

### T14. T1648 - Serverless Execution
**Tactic:** Execution
**Platform:** IaaS

**What the attacker does:**
Creates or modifies Lambda functions to run arbitrary code inside the victim's cloud environment. Can be used to bypass endpoint detection, persist via EventBridge triggers, or use the victim's own infrastructure as a proxy for further attacks.

**AWS API calls involved:**
- `lambda:CreateFunction`
- `lambda:UpdateFunctionCode`
- `lambda:AddPermission`
- `lambda:InvokeFunction`
- `events:PutRule` (to create a scheduled trigger for persistence)

**Agent Sentinel decision:**
- HUMAN_REQUIRED for Lambda creation with an execution role above read-only
- BLOCK if Lambda creation and EventBridge trigger creation happen in the same session
- Risk score: 0.70

**How we detect it:** Causal chain detection. Lambda create followed by trigger creation is the persistence pattern to catch.

---

### T15. T1485 - Data Destruction
**Tactic:** Impact
**Platform:** IaaS

**What the attacker does:**
Deletes cloud resources to cause maximum damage. S3 buckets, RDS databases, EC2 instances, DynamoDB tables. This is the final stage of many ransomware attacks targeting cloud environments. Once data is deleted without a backup, it may be gone permanently.

**AWS API calls involved:**
- `s3:DeleteBucket`
- `s3:DeleteObjects`
- `rds:DeleteDBInstance` with skip-final-snapshot set to true
- `ec2:TerminateInstances`
- `dynamodb:DeleteTable`

**Agent Sentinel decision:**
- BLOCK unconditionally for bulk delete operations involving 10 or more resources in one session
- HUMAN_REQUIRED for any RDS or DynamoDB deletion
- Risk score: 1.0 (hardcoded maximum)

**How we detect it:** Pre-execution enforcement. Zero tolerance for bulk destructive operations.

---

## Risk Score Summary

| Technique | ID | Base Risk Score | Default Decision |
|---|---|---|---|
| Valid Accounts | T1078 | 0.65 to 0.85 | HUMAN_REQUIRED |
| Exploit Public-Facing App | T1190 | 0.70 | BLOCK (pattern) |
| Create Cloud Account | T1136.003 | 0.80 | HUMAN_REQUIRED |
| Additional Cloud Credentials | T1098.001 | 0.75 | BLOCK |
| Temporary Elevated Access | T1548.005 | 0.85 | HUMAN_REQUIRED |
| Cloud Account Priv Esc | T1078.004 | 0.80 | BLOCK |
| Disable Cloud Logs | T1562.008 | 1.0 | BLOCK (hardcoded) |
| Modify Compute Infrastructure | T1578 | 0.75 | HUMAN_REQUIRED |
| Cloud Infrastructure Discovery | T1580 | 0.40 to 0.80 | ALLOW to BLOCK (rate) |
| Cloud Service Dashboard | T1538 | 0.60 | BLOCK (agent) |
| Cloud Service Discovery | T1526 | 0.55 | HUMAN_REQUIRED |
| Data from Cloud Storage | T1530 | 0.35 to 0.85 | ALLOW to HUMAN_REQUIRED (rate) |
| Transfer to Cloud Account | T1537 | 0.95 | BLOCK (hardcoded) |
| Serverless Execution | T1648 | 0.70 | HUMAN_REQUIRED |
| Data Destruction | T1485 | 1.0 | BLOCK (hardcoded) |

---

## Hardcoded Blocks

Three techniques are hardcoded blocks regardless of policy version or context. These live in the gateway source code, not in the DynamoDB policy store. They cannot be overridden.

| Technique | Reason |
|---|---|
| T1562.008 - Disable Cloud Logs | No legitimate agent workflow should disable its own audit trail |
| T1537 - Transfer to External Account | Data leaving the AWS account is irreversible |
| T1485 - Data Destruction | Bulk resource deletion is irreversible |

---

## Causal Chains for Day 4

These are multi-step attack sequences. Each individual step might score below the block threshold on its own. But the sequence together is a high-confidence attack pattern. These will be encoded as a directed graph in NetworkX on Day 4.

**Chain A - Persistence after Initial Access:**
sts:AssumeRole then iam:CreateUser then iam:CreateAccessKey then iam:AttachUserPolicy
Composite risk: 0.92

**Chain B - Exfiltration via Snapshot:**
ec2:CreateSnapshot then ec2:ModifySnapshotAttribute (external share) then ec2:CopySnapshot
Composite risk: 0.95

**Chain C - Serverless Persistence:**
lambda:CreateFunction then iam:PassRole then events:PutRule
Composite risk: 0.88

**Chain D - Log Blind then Destroy:**
cloudtrail:StopLogging then s3:DeleteBucket or rds:DeleteDBInstance
Composite risk: 1.0 (already triggers a block at step 1)

**Chain E - Discovery Sweep into Privilege Escalation:**
s3:ListAllMyBuckets plus ec2:DescribeInstances plus iam:ListPolicies all within 60 seconds, followed by sts:AssumeRole
Composite risk: 0.85

---

## Next Steps

Day 2: Build actions.json, a structured file mapping every AWS API action above to a risk score and tactic category.
Day 4: Encode Chains A through E as a directed graph in NetworkX using edge weights from this document.
Day 6: Train an Isolation Forest model on normal agent API call sequences. Flag deviations matching T1580 and T1526 sweep patterns.
Day 9: Use LLM intent reasoning via AWS Bedrock to classify ambiguous agent requests against this tactic library.

---

*Agent Sentinel - AI enforcement gateway for autonomous agents*
*This document is proprietary and confidential.*