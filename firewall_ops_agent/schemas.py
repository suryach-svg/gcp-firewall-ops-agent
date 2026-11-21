# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Explicit JSON schemas (Pydantic models) shared by tools, agents and tests.

Every tool input is validated against one of these models before any work is
done, and every tool output is produced from one of these models. This keeps
the LLM "inside the lines": malformed arguments are rejected with a guided
error message instead of reaching Google Cloud APIs.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ScopeType = Literal["organization", "folder", "project"]
SourceKind = Literal["vpc_firewall_rule", "hierarchical_policy_rule", "network_policy_rule"]
Direction = Literal["INGRESS", "EGRESS"]
RuleAction = Literal["allow", "deny", "goto_next", "apply_security_profile_group"]

_NUMERIC_ID = re.compile(r"^[0-9]{1,20}$")
# GCP project IDs: 6-30 chars, lowercase letters, digits and hyphens, must
# start with a letter and must not end with a hyphen.
_PROJECT_ID = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")


class Severity(str, Enum):
    """Risk severity levels, ordered from most to least severe."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Numeric rank used for sorting and threshold filtering (4 = worst)."""
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}[self.value]


class ScopeRequest(BaseModel):
    """Validated request to read firewall rules at one level of the GCP hierarchy."""

    model_config = ConfigDict(extra="forbid")

    scope_type: ScopeType = Field(
        description="Level of the Google Cloud resource hierarchy to audit."
    )
    scope_id: str = Field(
        description=(
            "Numeric organization or folder ID (e.g. '123456789012'), or a "
            "project ID (e.g. 'my-project-123'). Prefixes such as "
            "'organizations/' or 'folders/' are accepted and stripped."
        )
    )
    include_inherited_policies: bool = Field(
        default=False,
        description=(
            "Only for project scope: also include hierarchical firewall policy "
            "rules inherited from parent folders and the organization."
        ),
    )

    @field_validator("scope_id", mode="before")
    @classmethod
    def _strip_prefix(cls, value: Any) -> Any:
        if isinstance(value, str):
            value = value.strip()
            for prefix in ("organizations/", "folders/", "projects/"):
                if value.startswith(prefix):
                    value = value[len(prefix):]
        return value

    @model_validator(mode="after")
    def _validate_id_format(self) -> ScopeRequest:
        if self.scope_type in ("organization", "folder"):
            if not _NUMERIC_ID.match(self.scope_id):
                raise ValueError(
                    f"{self.scope_type} IDs must be numeric (for example "
                    f"'123456789012'); got '{self.scope_id}'."
                )
        elif not (_PROJECT_ID.match(self.scope_id) or _NUMERIC_ID.match(self.scope_id)):
            raise ValueError(
                "project IDs must be 6-30 characters of lowercase letters, digits "
                f"or hyphens and start with a letter; got '{self.scope_id}'."
            )
        if self.include_inherited_policies and self.scope_type != "project":
            raise ValueError(
                "include_inherited_policies is only valid for scope_type='project'."
            )
        return self

    @property
    def scope_key(self) -> str:
        """Stable cache key such as 'project/my-project'."""
        return f"{self.scope_type}/{self.scope_id}"


class ProtocolPorts(BaseModel):
    """One protocol entry of a firewall rule (e.g. tcp ports 22 and 3389)."""

    protocol: str = Field(description="tcp, udp, icmp, sctp, esp, ah, ipip or 'all'.")
    ports: list[str] = Field(
        default_factory=list,
        description="Port numbers or ranges such as '22' or '1000-2000'. Empty means all ports.",
    )


class FirewallRule(BaseModel):
    """A firewall rule normalized across VPC firewall rules and firewall policies."""

    name: str
    source_kind: SourceKind
    scope_type: ScopeType
    scope_id: str
    policy_name: str | None = None
    network: str | None = None
    direction: Direction
    action: RuleAction
    priority: int = Field(ge=0, le=2147483647)
    source_ranges: list[str] = Field(default_factory=list)
    destination_ranges: list[str] = Field(default_factory=list)
    source_tags: list[str] = Field(default_factory=list)
    source_service_accounts: list[str] = Field(default_factory=list)
    target_tags: list[str] = Field(default_factory=list)
    target_service_accounts: list[str] = Field(default_factory=list)
    target_resources: list[str] = Field(default_factory=list)
    target_secure_tags: list[str] = Field(
        default_factory=list, description="IAM-governed secure tags (Resource Manager tags) a policy rule targets."
    )
    protocols_ports: list[ProtocolPorts] = Field(default_factory=list)
    logging_enabled: bool = False
    disabled: bool = False
    description: str = ""
    implicit_source_note: str | None = Field(
        default=None,
        description="Set when GCP applied an implicit 0.0.0.0/0 source to an ingress rule.",
    )

    @property
    def has_targets(self) -> bool:
        """True if the rule is scoped to specific tags, service accounts or resources."""
        return bool(self.target_tags or self.target_service_accounts or self.target_resources or self.target_secure_tags)

    def short_ports(self) -> str:
        """Human readable protocol/port summary such as 'tcp:22,3389; icmp'."""
        parts = []
        for entry in self.protocols_ports:
            if entry.protocol == "all":
                parts.append("all protocols")
            elif entry.ports:
                parts.append(f"{entry.protocol}:{','.join(entry.ports)}")
            elif entry.protocol in ("tcp", "udp", "sctp"):
                parts.append(f"{entry.protocol}:all-ports")
            else:
                parts.append(entry.protocol)
        return "; ".join(parts) or "none"


class RiskFinding(BaseModel):
    """A single, evidence-backed risk detected on one firewall rule."""

    check_id: str = Field(description="Stable check identifier, e.g. 'FW-001'.")
    title: str
    severity: Severity
    rule_name: str
    scope_type: ScopeType
    scope_id: str
    evidence: str = Field(description="Concrete facts from the rule that triggered the check.")
    risk_explanation: str
    recommendation: str
    scc_category: str | None = Field(
        default=None,
        description="Closest Security Command Center (Security Health Analytics) finding category.",
    )


class RiskReport(BaseModel):
    """Deterministic risk report for one scope. Produced by the risk engine."""

    scope_type: ScopeType
    scope_id: str
    rules_analyzed: int
    findings: list[RiskFinding]
    severity_counts: dict[str, int]
    posture_score: int = Field(ge=0, le=100)
    posture_grade: Literal["A", "B", "C", "D", "F"]
    strengths: list[str] = Field(default_factory=list)
    generated_at: str = Field(
        default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds")
    )


class RemediationProposal(BaseModel):
    """A least-privilege replacement for a risky rule, ready for human review."""

    rule_name: str
    scope_type: ScopeType
    scope_id: str
    summary_of_changes: list[str]
    hardened_rule: FirewallRule
    gcloud_command: str
    terraform_snippet: str
    residual_risks: list[str] = Field(default_factory=list)


class ToolError(BaseModel):
    """Guided error returned to the LLM instead of raising an exception.

    The ``recovery_hint`` tells the model exactly how to fix its next call.
    """

    status: Literal["error"] = "error"
    error_type: str
    message: str
    recovery_hint: str
