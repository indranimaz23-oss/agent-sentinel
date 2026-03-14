from fastapi import FastAPI
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import boto3
from boto3.dynamodb.conditions import Key
from fastapi import Header, HTTPException
import hashlib
import uuid
import os
import json
from typing import Any, Dict,  Optional
# Your v1 policy contract (already created in policy_schema.py)
from policy_schema import PolicyV1

app = FastAPI(title="Agent Sentinel")

# ---------------------------
# AWS Clients
# ---------------------------
AWS_REGION = os.getenv("AWS_REGION", os.getenv("AWS_DEFAULT_REGION", "us-east-1"))

dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
lambda_client = boto3.client("lambda", region_name=AWS_REGION)

POLICIES_V1_TABLE = os.getenv("POLICIES_V1_TABLE", "agentsentinel-policies-v1")
policies_v1_table = dynamodb.Table(POLICIES_V1_TABLE)

ACTIONLOG_TABLE = dynamodb.Table("agentsentinel-actionlog")
AGENTSTATE_TABLE = dynamodb.Table("agentsentinel-agentstate")
POLICIES_TABLE = dynamodb.Table("agentsentinel-policies")  # currently stores your legacy time-window policies

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))

def sha256_str(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def get_latest_policy_version(policy_id: str) -> int:
    resp = policies_v1_table.query(
        KeyConditionExpression=Key("policy_id").eq(policy_id),
        ScanIndexForward=False,  # highest version first
        Limit=1,
        ProjectionExpression="version",
    )
    items = resp.get("Items", [])
    return int(items[0]["version"]) if items else 0


def model_to_dict(m: Any) -> Dict[str, Any]:
    # Works with Pydantic v1 and v2
    if hasattr(m, "model_dump"):
        return m.model_dump()
    if hasattr(m, "dict"):
        return m.dict()
    if isinstance(m, dict):
        return m
    raise TypeError(f"Unsupported model type: {type(m)}")


# ---------------------------
# Models (Legacy)
# ---------------------------

class PolicyCreate(BaseModel):
    resource_id: str
    start_hour: int
    end_hour: int
    environment: str

class ProposedAction(BaseModel):
    agent_id: str
    action: str
    resource_id: str
    parameters: dict
    environment: str


# ---------------------------
# Step 0 + Step 2 (NEW): Human input surface via Swagger
# POST /policy/compile
# This is a MOCK compiler for now (no LLM yet)
# ---------------------------

class CompileRequest(BaseModel):
    text: str
    created_by: Optional[str] = "admin"

class CompileResponse(BaseModel):
    needs_clarification: bool
    clarifying_questions: list[str] = []
    policy: Optional[PolicyV1] = None

@app.post("/policy/compile", response_model=CompileResponse)
def policy_compile(req: CompileRequest) -> CompileResponse:
    """
    Stage-1: MOCK NL → PolicyV1 compiler (authoring-time only).

    Behavior:
    - If statement is missing key specifics, return clarifying questions.
    - Otherwise return a valid PolicyV1 JSON object.

    NOTE: This does NOT store into DynamoDB yet.
    We'll add /policies/v1 store endpoint in the next stage.
    """
    t = req.text.strip()
    tl = t.lower()

    # Minimal ambiguity checks
    if not t:
        return CompileResponse(
            needs_clarification=True,
            clarifying_questions=["Please provide a policy statement."],
            policy=None,
        )

    # Env check
    if ("prod" not in tl) and ("production" not in tl) and ("nonprod" not in tl) and ("dev" not in tl) and ("sandbox" not in tl):
        return CompileResponse(
            needs_clarification=True,
            clarifying_questions=["Which environment should this apply to (prod, nonprod, dev, sandbox)?"],
            policy=None,
        )

    # Service hint check (very basic for mock)
    known_services = ["ec2", "s3", "iam", "rds", "kms", "cloudtrail", "lambda", "eks", "route53", "dns", "vpc", "security group", "sg"]
    if not any(s in tl for s in known_services):
        return CompileResponse(
            needs_clarification=True,
            clarifying_questions=["Which AWS service is this about (ec2, s3, iam, rds, kms, cloudtrail, lambda, eks, route53)?"],
            policy=None,
        )

    # Action hint check (very basic for mock)
    action_words = ["delete", "terminate", "stop", "public", "attach", "disable", "update", "modify", "create"]
    if not any(w in tl for w in action_words):
        return CompileResponse(
            needs_clarification=True,
            clarifying_questions=["What action should be controlled (delete, stop, terminate, modify, create, etc.)?"],
            policy=None,
        )

    # MOCK output: we return a valid PolicyV1 that matches your schema
    # For now, always returns an EC2 terminate block in prod (we replace with real LLM compiler next).
    policy = PolicyV1(
        policy_id=f"P-{uuid.uuid4().hex[:8]}",
        version=1,
        enabled=True,
        priority=80,
        scope={"service": "ec2"},
        effect="BLOCK",
        actions=["ec2:TerminateInstances"],
        resource={"type": "ec2:instance", "selector": {"any": True}},
        conditions=[{"op": "eq", "path": "context.env", "value": "prod"}],
        exceptions=[],
        source_nl=req.text,
        created_at_utc=datetime.now(timezone.utc).isoformat(),
        created_by=req.created_by,
    )

    return CompileResponse(needs_clarification=False, policy=policy)

@app.post("/policy/compile-and-store")
def policy_compile_and_store(
    req: CompileRequest,
    x_user: Optional[str] = Header(default="unknown", convert_underscores=False),
):
    # 1) Compile using the existing compiler
    compiled = policy_compile(req)

    # 2) If ambiguous, return clarifying questions (do NOT store)
    if compiled.needs_clarification or compiled.policy is None:
        return compiled

    # 3) Convert PolicyV1 model -> dict for storage
    policy_dict = model_to_dict(compiled.policy)

    # 4) Build the storage request body for /policies/v1 logic
    policy_id = policy_dict.get("policy_id") or policy_dict.get("id") or f"P-{uuid.uuid4().hex[:8]}"

    store_body = PolicyV1CreateRequest(
        policy_id=policy_id,
        environment=policy_dict.get("conditions", [{}])[0].get("value", "*") if isinstance(policy_dict.get("conditions"), list) else "*",
        status="active",
        source_text=req.text,
        compiled_by="mock",
        compiler_version="mock-0.1",
        policy=policy_dict,
    )

    # 5) Store using the same storage function/endpoint logic
    stored = create_policy_v1(store_body, x_user=x_user)

    return {
        "needs_clarification": False,
        "clarifying_questions": [],
        "compiled_policy": policy_dict,
        "stored": stored,
    }


# ---------------------------
# Legacy: Create Policy Endpoint (time window protection)
# ---------------------------

@app.post("/policies")
def create_policy(policy: PolicyCreate):
    """
    Legacy policy format (resource_id + time window + environment).
    We keep this so your current demo doesn't break.
    """
    policy_id = str(uuid.uuid4())

    POLICIES_TABLE.put_item(
        Item={
            "policy_id": policy_id,
            "resource_id": policy.resource_id,
            "start_hour": policy.start_hour,
            "end_hour": policy.end_hour,
            "environment": policy.environment,
            "created_at": datetime.utcnow().isoformat()
        }
    )

    return {"message": "Policy created", "policy_id": policy_id}


# ---------------------------
# Legacy: Evaluate Endpoint (uses legacy policies)
# ---------------------------

# ---------------------------
# Evaluation Response Model
# ---------------------------

class EvaluationResult(BaseModel):
    decision: str
    reason: str
    risk_score: float
    action_id: str
    policy_id_matched: Optional[str] = None
    timestamp: str


def compute_risk_score(action: str, environment: str, resource_id: str) -> float:
    score = 0.0

    action_weights = {
        "delete":    0.8,
        "terminate": 0.8,
        "destroy":   0.9,
        "drop":      0.9,
        "disable":   0.6,
        "modify":    0.4,
        "update":    0.3,
        "create":    0.2,
        "read":      0.1,
        "list":      0.05,
        "describe":  0.05,
    }
    action_lower = action.lower()
    for keyword, weight in action_weights.items():
        if keyword in action_lower:
            score += weight
            break
    else:
        score += 0.3

    env_multipliers = {
        "prod":       1.5,
        "production": 1.5,
        "staging":    1.0,
        "dev":        0.5,
        "sandbox":    0.4,
    }
    env_lower = environment.lower()
    for env_key, mult in env_multipliers.items():
        if env_key in env_lower:
            score *= mult
            break

    sensitive_resources = ["iam", "kms", "cloudtrail", "prod", "database", "rds", "secret"]
    resource_lower = resource_id.lower()
    for sensitive in sensitive_resources:
        if sensitive in resource_lower:
            score += 0.2
            break

    return round(min(max(score, 0.0), 1.0), 2)


def check_policy_v1_match(proposed: ProposedAction) -> Optional[str]:
    try:
        items = policies_v1_table.scan().get("Items", [])
        for item in items:
            if item.get("status") != "active":
                continue
            policy = item.get("policy", {})
            effect = policy.get("effect", "ALLOW")
            actions = policy.get("actions", [])
            conditions = policy.get("conditions", [])

            action_match = any(
                proposed.action.lower() in a.lower() or a == "*"
                for a in actions
            )
            if not action_match:
                continue

            env_match = True
            for condition in conditions:
                if condition.get("path") == "context.env":
                    if condition.get("op") == "eq":
                        if condition.get("value") not in [proposed.environment, "*"]:
                            env_match = False
            if not env_match:
                continue

            if effect == "BLOCK":
                return item.get("policy_id")

    except Exception:
        pass
    return None


@app.post("/evaluate", response_model=EvaluationResult)
def evaluate_action(proposed: ProposedAction):
    action_id = str(uuid.uuid4())
    current_hour = datetime.utcnow().hour

    risk_score = compute_risk_score(
        proposed.action,
        proposed.environment,
        proposed.resource_id
    )

    # 1) Check PolicyV1 table first
    matched_policy_id = check_policy_v1_match(proposed)
    if matched_policy_id:
        decision = "BLOCK"
        reason = f"Blocked by policy {matched_policy_id}"
        log_action(action_id, proposed, decision, reason)
        return EvaluationResult(
            decision=decision,
            reason=reason,
            risk_score=risk_score,
            action_id=action_id,
            policy_id_matched=matched_policy_id,
            timestamp=now_iso(),
        )

    # 2) Check legacy time-window policies
    policies = POLICIES_TABLE.scan().get("Items", [])
    for policy in policies:
        if (
            policy.get("resource_id") == proposed.resource_id
            and policy.get("environment") == proposed.environment
            and int(policy.get("start_hour", 0)) <= current_hour <= int(policy.get("end_hour", 0))
        ):
            decision = "BLOCK"
            reason = "Protected resource during restricted hours"
            log_action(action_id, proposed, decision, reason)
            return EvaluationResult(
                decision=decision,
                reason=reason,
                risk_score=risk_score,
                action_id=action_id,
                policy_id_matched=policy.get("policy_id"),
                timestamp=now_iso(),
            )

    # 3) Risk score threshold
    if risk_score >= 0.75:
        decision = "BLOCK"
        reason = f"Risk score {risk_score} exceeds critical threshold (0.75)"
    elif risk_score >= 0.4:
        decision = "HUMAN_REQUIRED"
        reason = f"Risk score {risk_score} requires human approval"
    else:
        decision = "ALLOW"
        reason = "Action within acceptable risk parameters"

    log_action(action_id, proposed, decision, reason)
    return EvaluationResult(
        decision=decision,
        reason=reason,
        risk_score=risk_score,
        action_id=action_id,
        policy_id_matched=None,
        timestamp=now_iso(),
    )

def log_action(action_id: str, proposed: ProposedAction, decision: str, reason: str):
    ACTIONLOG_TABLE.put_item(
        Item={
            "action_id": action_id,
            "agent_id": proposed.agent_id,
            "action": proposed.action,
            "resource_id": proposed.resource_id,
            "environment": proposed.environment,
            "decision": decision,
            "reason": reason,
            "timestamp": datetime.utcnow().isoformat()
        }
    )
# ---------------------------
# Stage 3: Store compiled PolicyV1 into DynamoDB (versioned)
# POST /policies/v1
# ---------------------------

class PolicyV1CreateRequest(BaseModel):
    policy_id: str = Field(..., min_length=3)
    environment: str = Field("*")
    status: str = Field("active")
    source_text: Optional[str] = None
    compiled_by: str = Field("mock")
    compiler_version: str = Field("mock-0.1")
    policy: Dict[str, Any] = Field(...)


@app.post("/policies/v1")
def create_policy_v1(
    body: PolicyV1CreateRequest,
    x_user: Optional[str] = Header(default="unknown", convert_underscores=False),
):
    policy_hash = sha256_str(canonical_json(body.policy))

    # idempotency: if same hash exists, return it
    existing = policies_v1_table.query(
        KeyConditionExpression=Key("policy_id").eq(body.policy_id),
        FilterExpression=boto3.dynamodb.conditions.Attr("policy_hash").eq(policy_hash),
        Limit=1,
    ).get("Items", [])

    if existing:
        return {"stored": True, "idempotent": True, "item": existing[0]}

    latest_version = get_latest_policy_version(body.policy_id)
    new_version = latest_version + 1

    item = {
        "policy_id": body.policy_id,
        "version": new_version,
        "created_at": now_iso(),
        "created_by": x_user or "unknown",
        "environment": body.environment,
        "status": body.status,
        "source_text": body.source_text,
        "compiled_by": body.compiled_by,
        "compiler_version": body.compiler_version,
        "policy_hash": policy_hash,
        "policy": body.policy,
    }

    policies_v1_table.put_item(
        Item=item,
        ConditionExpression="attribute_not_exists(policy_id) AND attribute_not_exists(version)",
    )

    return {"stored": True, "idempotent": False, "item": item}
