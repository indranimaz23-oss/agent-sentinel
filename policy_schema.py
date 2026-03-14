from __future__ import annotations
from typing import Any, Dict, List, Literal, Optional, Union
from pydantic import BaseModel, Field, model_validator

Service = Literal["ec2", "s3", "iam", "rds", "kms", "cloudtrail", "lambda", "eks", "route53"]
Effect = Literal["ALLOW", "BLOCK", "REQUIRE_HUMAN_APPROVAL"]

Operator = Literal[
    "eq", "in", "contains",
    "gt", "gte", "lt", "lte",
    "inside_time_window", "outside_time_window",
]

class Condition(BaseModel):
    op: Operator
    path: str
    value: Any

class ResourceSelectorAny(BaseModel):
    any: bool = True

class ResourceSelectorId(BaseModel):
    id: str

class ResourceSelectorTag(BaseModel):
    tag: Dict[str, str]

ResourceSelector = Union[ResourceSelectorAny, ResourceSelectorId, ResourceSelectorTag]

class Resource(BaseModel):
    type: str
    selector: ResourceSelector

class Scope(BaseModel):
    service: Service

class PolicyV1(BaseModel):
    policy_id: str
    version: int = 1
    enabled: bool = True
    priority: int = Field(default=50, ge=0, le=100)

    scope: Scope
    effect: Effect
    actions: List[str]
    resource: Resource

    conditions: List[Condition] = Field(default_factory=list)
    exceptions: List[Condition] = Field(default_factory=list)

    source_nl: str
    created_at_utc: str
    created_by: Optional[str] = None

    @model_validator(mode="after")
    def checks(self):
        if not self.actions:
            raise ValueError("actions must not be empty")
        if not self.policy_id.strip():
            raise ValueError("policy_id must be non-empty")
        return self
