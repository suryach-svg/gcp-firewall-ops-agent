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
"""Inventory tools: read firewall rules for a scope and inspect a single rule."""

from typing import Annotated, Any, Literal

from google.adk.tools.tool_context import ToolContext
from pydantic import Field, ValidationError

from ..config import get_settings
from ..core.risk_engine import find_shadowed_rules
from ..schemas import ScopeRequest
from ._common import compact_rule, load_rules, report_for_key, resolve_rule, rule_level, tool_error

SCOPE_ID_PATTERN = r"^((organizations|folders|projects)/)?([0-9]{1,20}|[a-z][a-z0-9-]{4,28}[a-z0-9])$"
ScopeTypeArg = Annotated[
    Literal["organization", "folder", "project"],
    Field(description="Hierarchy level to read: organization, folder or project."),
]
ScopeIdArg = Annotated[
    str,
    Field(
        min_length=1,
        max_length=80,
        pattern=SCOPE_ID_PATTERN,
        description="Numeric organization or folder ID (e.g. '123456789012') or a project ID (e.g. 'prod-payments-app').",
    ),
]
RuleNameArg = Annotated[
    str, Field(min_length=1, max_length=200, description="Exact firewall rule name from the audit, e.g. 'default-allow-ssh'.")
]
OptionalScopeIdArg = Annotated[
    str | None,
    Field(default=None, description="Optional scope (project/folder/org ID) when the rule name exists in several audited scopes."),
]


async def list_firewall_rules_for_scope(
    scope_type: ScopeTypeArg,
    scope_id: ScopeIdArg,
    tool_context: ToolContext,
    include_inherited_policies: Annotated[
        bool, Field(description="Project scope only: also include inherited organization/folder policy rules.")
    ] = False,
) -> dict[str, Any]:
    """Reads the firewall rules defined at one level of the Google Cloud resource hierarchy.

    Call this first in every audit. Organization and folder scopes return the
    hierarchical firewall policy rules attached at that node. Project scope
    returns the project's VPC firewall rules and network firewall policy
    rules, and, when include_inherited_policies is true, the organization and
    folder policy rules that are evaluated before them for the project's VMs.

    Args:
        scope_type: Hierarchy level to read: "organization", "folder" or "project".
        scope_id: Numeric organization or folder ID such as "123456789012", or a
            project ID such as "prod-payments-app".
        include_inherited_policies: Project scope only. Also return inherited
            organization and folder policy rules (recommended for an
            effective-exposure audit).

    Returns:
        On success: status "success", the validated scope, data_mode, rule_count,
        rules_by_level, a compact list of rules (name, level, direction, action,
        priority, peers, ports, targets, logging) and any non-fatal warnings. On
        failure: status "error" with error_type, message and a recovery_hint
        explaining how to fix the call.
    """
    try:
        request = ScopeRequest(
            scope_type=scope_type, scope_id=scope_id, include_inherited_policies=include_inherited_policies
        )
    except ValidationError as exc:
        return tool_error(
            "invalid_arguments",
            "; ".join(err["msg"] for err in exc.errors()),
            "Use scope_type 'organization' or 'folder' with a numeric ID, or 'project' with a project ID. "
            "Only set include_inherited_policies=true for projects.",
        )

    # An explicit list request always refreshes, so the audit reflects current rules.
    rules, warnings, error = await load_rules(tool_context.state, request, refresh=True)
    if error:
        return error
    settings = get_settings()
    limit = settings.max_rules_in_tool_response
    by_level: dict[str, int] = {}
    for rule in rules:
        level = compact_rule(rule)["level"]
        by_level[level] = by_level.get(level, 0) + 1
    result: dict[str, Any] = {
        "status": "success",
        "scope": request.model_dump(),
        "data_mode": settings.firewall_data_mode,
        "rule_count": len(rules),
        "rules_by_level": by_level,
        "rules": [compact_rule(rule) for rule in rules[:limit]],
        "truncated": len(rules) > limit,
        "note": "Full rule details are cached in session state; call analyze_firewall_rule_risks next.",
    }
    if warnings:
        result["warnings"] = warnings
    return result


def get_firewall_rule_details(
    rule_name: RuleNameArg,
    tool_context: ToolContext,
    scope_id: OptionalScopeIdArg = None,
) -> dict[str, Any]:
    """Returns everything known about one firewall rule from the latest audit of its scope.

    Use this to answer follow-up questions such as "why is this rule risky?"
    or "what overrides this rule?". The rule is looked up in the last audited
    scope (or in scope_id), and the result includes the full normalized rule,
    its risk findings, and any shadowing relationship computed within that
    same scope (a higher-precedence rule that overrides it, or rules it
    overrides).

    Args:
        rule_name: Exact rule name, e.g. "default-allow-ssh". For hierarchical
            policy rules this is the rule name (or "<policy>/priority-<n>").
        scope_id: Optional project, folder or organization ID, needed only when
            the same rule name exists in several audited scopes.

    Returns:
        On success: status "success" with scope, rule, evaluation_level,
        findings, shadowed_by and shadows. On failure: status "error" with
        close name matches or the scopes to choose from in the recovery_hint.
    """
    rule, rules, key, error = resolve_rule(tool_context.state, rule_name, scope_id)
    if error:
        return error
    report = report_for_key(tool_context.state, key) or {}
    findings = [f for f in report.get("findings", []) if f.get("rule_name") == rule.name]
    shadowed = find_shadowed_rules(rules)
    shadowed_by = shadowed.get(rule.name)
    shadows = [name for name, outer in shadowed.items() if outer.name == rule.name]
    return {
        "status": "success",
        "scope": key,
        "rule": rule.model_dump(mode="json"),
        "evaluation_level": rule_level(rule),
        "findings": findings,
        "findings_note": None if report else "Scope not analyzed yet; call analyze_firewall_rule_risks for findings.",
        "shadowed_by": compact_rule(shadowed_by) if shadowed_by else None,
        "shadows": shadows,
        "evaluation_order_note": (
            "Organization policy rules are evaluated first, then folder policies, then project VPC rules, then "
            "network firewall policies; within a level the lowest priority number wins and deny wins ties."
        ),
    }
