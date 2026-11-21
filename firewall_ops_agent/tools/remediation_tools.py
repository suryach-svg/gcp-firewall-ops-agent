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
"""Remediation tools: propose least-privilege rules and apply changes with human approval."""

import asyncio
import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from google.adk.tools.tool_context import ToolContext
from pydantic import BaseModel, Field, ValidationError, field_validator

from ..config import get_settings
from ..core.network_utils import SourceClass, classify_cidr
from ..core.remediation_builder import (
    RemediationInputError,
    build_least_privilege_proposal,
    gcloud_update_command,
)
from ..core.risk_engine import find_shadowed_rules
from ..observability.redaction import redact_text
from ..observability.tracing import traced_operation
from ..schemas import FirewallRule
from ._common import (
    STATE_CHANGES,
    STATE_PROPOSALS,
    STATE_SCOPES,
    inventory_state_key,
    resolve_rule,
    tool_error,
)
from .inventory_tools import OptionalScopeIdArg, RuleNameArg

logger = logging.getLogger("firewall_ops_agent.remediation")
ChangeType = Literal["restrict_source_ranges", "disable_rule", "enable_logging"]
CidrList = Annotated[
    list[str] | None,
    Field(default=None, description="Specific CIDR ranges such as ['10.20.0.0/24']. Internet-wide ranges are rejected."),
]


def propose_least_privilege_rule(
    rule_name: RuleNameArg,
    tool_context: ToolContext,
    allowed_source_ranges: CidrList = None,
    allowed_ports: Annotated[
        list[str] | None, Field(default=None, description="Ports the workload really listens on, e.g. ['443'].")
    ] = None,
    target_service_account: Annotated[
        str | None, Field(default=None, description="Service account email to scope the rule to (preferred).")
    ] = None,
    target_tags: Annotated[
        list[str] | None, Field(default=None, description="Network tags to scope the rule to.")
    ] = None,
    scope_id: OptionalScopeIdArg = None,
) -> dict[str, Any]:
    """Drafts a least-privilege replacement for a risky rule (proposal only, nothing is changed).

    Safe defaults are inferred where possible (IAP range for SSH/RDP, Google
    load balancer ranges for web ports, logging on). When the safe value
    depends on the engineer's architecture (for example who may reach a
    database), the tool returns status "needs_input" - ask the engineer and
    call again with the extra arguments.

    Args:
        rule_name: Exact name of the rule to harden.
        allowed_source_ranges: Optional CIDR ranges that legitimately need access,
            e.g. ["10.20.0.0/24"]. Never internet-wide ranges.
        allowed_ports: Optional ports the workload really listens on, e.g. ["443"].
        target_service_account: Optional service account email to scope the rule to.
        target_tags: Optional network tags to scope the rule to.
        scope_id: Optional scope ID when the rule name exists in several audited scopes.

    Returns:
        status "success" with summary_of_changes, hardened_rule, gcloud_command,
        terraform_snippet and residual_risks; status "needs_input" with the
        question to ask; or status "error" with a recovery_hint.
    """
    rule, rules, _, error = resolve_rule(tool_context.state, rule_name, scope_id)
    if error:
        return error
    shadowed_by = find_shadowed_rules(rules).get(rule.name)
    try:
        proposal = build_least_privilege_proposal(
            rule, shadowed_by=shadowed_by, allowed_source_ranges=allowed_source_ranges,
            allowed_ports=allowed_ports, target_service_account=target_service_account, target_tags=target_tags,
        )
    except RemediationInputError as exc:
        return {"status": "needs_input", "error_type": "missing_engineer_input", "message": str(exc),
                "recovery_hint": exc.recovery_hint}
    proposals = dict(tool_context.state.get(STATE_PROPOSALS) or {})
    proposals[f"{rule.scope_id}/{rule.name}"] = proposal.model_dump(mode="json")
    tool_context.state[STATE_PROPOSALS] = proposals
    return {
        "status": "success",
        **proposal.model_dump(mode="json"),
        "next_step": "Review with the engineer. Applying any change requires explicit human approval.",
    }


class RemediationRequest(BaseModel):
    """Validated input for apply_firewall_remediation."""

    rule_name: str = Field(min_length=1, max_length=200)
    change_type: ChangeType
    justification: str = Field(min_length=10, max_length=1000)
    new_source_ranges: list[str] | None = None

    @field_validator("new_source_ranges")
    @classmethod
    def _safe_ranges(cls, value: list[str] | None) -> list[str] | None:
        for cidr in value or []:
            kind = classify_cidr(cidr)
            if kind is SourceClass.INVALID:
                raise ValueError(f"'{cidr}' is not valid CIDR notation")
            if kind is SourceClass.INTERNET:
                raise ValueError(f"'{cidr}' would expose the rule to the internet")
        return value


def _planned_rule(rule: FirewallRule, request: RemediationRequest) -> FirewallRule:
    planned = rule.model_copy(deep=True)
    if request.change_type == "disable_rule":
        planned.disabled = True
    elif request.change_type == "enable_logging":
        planned.logging_enabled = True
    elif rule.direction == "INGRESS":
        planned.source_ranges = list(request.new_source_ranges or [])
    else:
        planned.destination_ranges = list(request.new_source_ranges or [])
    return planned


def _command_for(planned: FirewallRule, change_type: str) -> str:
    command = gcloud_update_command(planned)
    if change_type == "disable_rule":
        command += " \\\n    --disabled"
    return command


def _apply_live_vpc_change(rule: FirewallRule, planned: FirewallRule, change_type: str) -> str:
    """Patches a VPC firewall rule through the Compute Engine API and waits for completion (blocking)."""
    from google.cloud import compute_v1

    patch = compute_v1.Firewall()
    if change_type == "disable_rule":
        patch.disabled = True
    elif change_type == "enable_logging":
        patch.log_config = compute_v1.FirewallLogConfig(enable=True)
    elif planned.direction == "INGRESS":
        patch.source_ranges = planned.source_ranges
    else:
        patch.destination_ranges = planned.destination_ranges
    with traced_operation("compute.firewalls.patch", project=rule.scope_id, rule=rule.name, change_type=change_type):
        operation = compute_v1.FirewallsClient().patch(project=rule.scope_id, firewall=rule.name, firewall_resource=patch)
        operation.result(timeout=180)
    return "applied"


def _simulate_in_session(state: Any, planned: FirewallRule) -> None:
    """Reflects a staged change in every cached view of the same rule, so a re-audit shows its effect."""
    for key in state.get(STATE_SCOPES) or []:
        items = state.get(inventory_state_key(key)) or []
        if any(i.get("name") == planned.name and i.get("scope_id") == planned.scope_id for i in items):
            state[inventory_state_key(key)] = [
                planned.model_dump(mode="json")
                if i.get("name") == planned.name and i.get("scope_id") == planned.scope_id else i
                for i in items
            ]


async def apply_firewall_remediation(
    rule_name: RuleNameArg,
    change_type: Annotated[
        Literal["restrict_source_ranges", "disable_rule", "enable_logging"],
        Field(description="The single change to make."),
    ],
    justification: Annotated[
        str, Field(min_length=10, max_length=1000, description="Why the change is needed; recorded in the audit trail.")
    ],
    tool_context: ToolContext,
    new_source_ranges: CidrList = None,
    scope_id: OptionalScopeIdArg = None,
) -> dict[str, Any]:
    """HIGH-STAKES: changes a firewall rule, but only after explicit human approval.

    The first call never changes anything: it pauses the agent and asks a human
    to approve the exact change (shown with its gcloud command). Only after a
    human approves is the change executed. In sample mode, or when
    ENABLE_LIVE_REMEDIATION is not "true", the approved change is staged as a
    change request (dry run) instead of being applied to Google Cloud. Live
    changes additionally require a change ticket in the approval.

    Args:
        rule_name: Exact name of the rule to change.
        change_type: "restrict_source_ranges", "disable_rule" or "enable_logging".
        justification: Why the change is needed (10-1000 characters), recorded in
            the audit trail.
        new_source_ranges: Required for restrict_source_ranges. Specific CIDR
            ranges only - internet-wide ranges are rejected.
        scope_id: Optional scope ID when the rule name exists in several audited scopes.

    Returns:
        status "pending_human_approval" (first call), "rejected", "applied" or
        "staged" with a change_request_id; or status "error" with a recovery_hint.
    """
    try:
        request = RemediationRequest(rule_name=rule_name, change_type=change_type, justification=justification,
                                     new_source_ranges=new_source_ranges)
    except ValidationError as exc:
        return tool_error("invalid_arguments", "; ".join(e["msg"] for e in exc.errors()),
                          "Provide a justification of at least 10 characters and specific CIDR ranges "
                          "(never 0.0.0.0/0) for restrict_source_ranges.")
    if request.change_type == "restrict_source_ranges" and not request.new_source_ranges:
        return tool_error("invalid_arguments", "new_source_ranges is required for restrict_source_ranges.",
                          "Ask the engineer which CIDR ranges should keep access, then retry.")
    rule, _, _, error = resolve_rule(tool_context.state, request.rule_name, scope_id)
    if error:
        return error

    planned = _planned_rule(rule, request)
    command = _command_for(planned, request.change_type)
    settings = get_settings()
    will_apply_live = (settings.firewall_data_mode == "live" and settings.enable_live_remediation
                       and rule.source_kind == "vpc_firewall_rule")
    plan = {
        "rule_name": rule.name, "scope": f"{rule.scope_type}/{rule.scope_id}", "change_type": request.change_type,
        "new_source_ranges": request.new_source_ranges, "gcloud_command": command,
        "execution_mode": "LIVE change to Google Cloud" if will_apply_live else "staged change request (dry run)",
    }

    # ---- Human-in-the-loop gate: explicit stop until a human approves. ----
    confirmation = tool_context.tool_confirmation
    if confirmation is None:
        ticket_note = " A change ticket is REQUIRED for live changes." if will_apply_live else ""
        tool_context.request_confirmation(
            hint=(f"APPROVAL REQUIRED - {plan['execution_mode']}: {request.change_type} on rule '{rule.name}' "
                  f"({plan['scope']}). Justification: {request.justification}.{ticket_note} Command:\n{command}"),
            payload={"change_ticket": ""},
        )
        tool_context.actions.skip_summarization = True
        logger.info("remediation awaiting human approval", extra={
            "event": "remediation_approval_requested", "rule": rule.name, "change_type": request.change_type})
        return {"status": "pending_human_approval", "change_status": "awaiting_approval", "planned_change": plan}

    approver_payload = confirmation.payload if isinstance(confirmation.payload, dict) else {}
    ticket = str(approver_payload.get("change_ticket", "")).strip()[:100]
    record = {
        "change_request_id": f"CR-{uuid.uuid4().hex[:8].upper()}",
        "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
        "approved": bool(confirmation.confirmed),
        "change_ticket": ticket,
        "justification": redact_text(request.justification),
        **plan,
    }
    if not confirmation.confirmed:
        record["change_status"] = "rejected_by_human"
        status = "rejected"
    elif will_apply_live and not ticket:
        record["change_status"] = "rejected_missing_ticket"
        status = "rejected"
    else:
        try:
            if will_apply_live:
                status = await asyncio.to_thread(_apply_live_vpc_change, rule, planned, request.change_type)
            else:
                status = "staged"
        except Exception as exc:  # noqa: BLE001 - surface as a guided error, never crash the agent
            logger.error("live remediation failed", extra={"event": "remediation_failed", "rule": rule.name,
                                                           "error_type": type(exc).__name__})
            return tool_error("remediation_failed", f"Applying the change failed ({type(exc).__name__}).",
                              "Nothing was changed. Share the gcloud command with the engineer to run manually.")
        if status == "staged":
            _simulate_in_session(tool_context.state, planned)
        record["change_status"] = status

    changes = list(tool_context.state.get(STATE_CHANGES) or [])
    changes.append(record)
    tool_context.state[STATE_CHANGES] = changes
    logger.info("remediation decision recorded", extra={
        "event": f"remediation_{record['change_status']}", "rule": rule.name, "change_type": request.change_type,
        "change_request_id": record["change_request_id"]})
    notes = {
        "staged": "Staged only: run the gcloud command (or merge the Terraform change) after your change review.",
        "rejected_missing_ticket": "Live changes need a change ticket in the approval. Nothing was changed.",
    }
    return {"status": status, "change_status": record["change_status"],
            "change_request_id": record["change_request_id"], "planned_change": plan,
            "note": notes.get(record["change_status"], "")}
