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
"""Shared helpers for tools: session-state layout, scoped rule lookup and guided errors.

Context engineering notes:
  * Full rule inventories and risk reports live in session *state* (persisted by
    the session service); tools return only compact views to the model.
  * Each audited scope is stored under its own state key, so auditing a new
    scope writes only that scope (state deltas stay small for large orgs).
  * Rules are always resolved *within one scope*, so a rule name that exists in
    several projects (e.g. default-allow-ssh) is never mixed up.
"""

import asyncio
import difflib
import logging
from typing import Any

from ..config import get_settings
from ..core.data_sources import ScopeNotFoundError, get_data_source
from ..observability.tracing import traced_operation
from ..schemas import FirewallRule, ScopeRequest, ToolError

logger = logging.getLogger("firewall_ops_agent.tools")

STATE_SCOPES = "audited_scopes"            # list of scope keys, most recent last
STATE_LAST_SCOPE = "last_audited_scope"
STATE_RISK_SUMMARY = "latest_risk_summary"
STATE_PROPOSALS = "remediation_proposals"
STATE_CHANGES = "approved_change_requests"
_INVENTORY_PREFIX = "firewall_inventory/"
_REPORT_PREFIX = "risk_report/"


def tool_error(error_type: str, message: str, recovery_hint: str) -> dict[str, Any]:
    """Builds a guided error result (validated by the ToolError schema)."""
    return ToolError(error_type=error_type, message=message, recovery_hint=recovery_hint).model_dump()


def scope_key(request: ScopeRequest) -> str:
    """Cache key for a scope, distinguishing inherited-policy views."""
    return request.scope_key + ("+inherited" if request.include_inherited_policies else "")


def inventory_state_key(key: str) -> str:
    """Session-state key holding the normalized rules of one scope."""
    return _INVENTORY_PREFIX + key


def report_state_key(key: str) -> str:
    """Session-state key holding the risk report of one scope."""
    return _REPORT_PREFIX + key


def scope_id_of(key: str) -> str:
    """'project/prod-app+inherited' -> 'prod-app'."""
    return key.split("/", 1)[-1].removesuffix("+inherited")


def last_scope_key(state: Any) -> str | None:
    """Key of the most recently audited scope, if any."""
    return (state.get(STATE_LAST_SCOPE) or {}).get("scope_key")


def cache_rules(state: Any, request: ScopeRequest, rules: list[FirewallRule]) -> None:
    """Stores one scope's rules under its own key and marks it as the last audited scope."""
    key = scope_key(request)
    state[inventory_state_key(key)] = [rule.model_dump(mode="json") for rule in rules]
    scopes = [k for k in (state.get(STATE_SCOPES) or []) if k != key] + [key]
    state[STATE_SCOPES] = scopes
    state[STATE_LAST_SCOPE] = {
        "scope_type": request.scope_type,
        "scope_id": request.scope_id,
        "include_inherited_policies": request.include_inherited_policies,
        "scope_key": key,
    }


def rules_for_key(state: Any, key: str) -> list[FirewallRule] | None:
    """Rules cached for a scope key, or None."""
    raw = state.get(inventory_state_key(key))
    if raw is None:
        return None
    return [FirewallRule.model_validate(item) for item in raw]


def cached_rules(state: Any, request: ScopeRequest) -> list[FirewallRule] | None:
    """Returns cached rules for ``request`` or None."""
    return rules_for_key(state, scope_key(request))


def store_report(state: Any, key: str, report: dict[str, Any]) -> None:
    """Persists a risk report for one scope."""
    state[report_state_key(key)] = report


def report_for_key(state: Any, key: str | None) -> dict[str, Any] | None:
    """Risk report for a scope key, or None."""
    return state.get(report_state_key(key)) if key else None


def resolve_rule(
    state: Any, rule_name: str, scope_id: str | None = None
) -> tuple[FirewallRule | None, list[FirewallRule], str | None, dict[str, Any] | None]:
    """Finds a rule inside exactly one audited scope.

    Preference order: the last audited scope, then any other single scope that
    contains the name. If the name exists in several other scopes the caller
    must disambiguate with ``scope_id``.

    Returns:
      (rule, rules_of_that_scope, scope_key, None) on success, or
      (None, [], None, guided_error) on failure.
    """
    scopes = list(state.get(STATE_SCOPES) or [])
    if not scopes:
        return None, [], None, tool_error(
            "no_inventory", "No firewall rules have been loaded in this session yet.",
            "Audit the scope that contains the rule first (list_firewall_rules_for_scope).")
    if scope_id:
        scopes = [k for k in scopes if scope_id_of(k) == scope_id.split("/")[-1]]
        if not scopes:
            return None, [], None, tool_error(
                "scope_not_loaded", f"Scope '{scope_id}' has not been audited in this session.",
                "Audit that scope first, or omit scope_id to use the last audited scope.")
    last = last_scope_key(state)
    ordered = ([last] if last in scopes else []) + [k for k in reversed(scopes) if k != last]

    matches: list[tuple[str, FirewallRule, list[FirewallRule]]] = []
    all_names: set[str] = set()
    for key in ordered:
        rules = rules_for_key(state, key) or []
        all_names.update(r.name for r in rules)
        hit = next((r for r in rules if r.name == rule_name), None) or next(
            (r for r in rules if r.name.lower() == rule_name.lower()), None)
        if hit is not None:
            matches.append((key, hit, rules))
    if not matches:
        suggestions = difflib.get_close_matches(rule_name, sorted(all_names), n=3, cutoff=0.4)
        return None, [], None, tool_error(
            "rule_not_found", f"No rule named '{rule_name}' in the audited scope(s).",
            f"Did you mean: {', '.join(suggestions) or 'none found'}? Retry with the exact name, "
            "or audit the scope that contains the rule.")
    first_key = matches[0][0]
    distinct_scopes = {scope_id_of(key) for key, _, _ in matches}
    if first_key != last and len(distinct_scopes) > 1:
        return None, [], None, tool_error(
            "ambiguous_rule_name",
            f"'{rule_name}' exists in several audited scopes: {', '.join(sorted(distinct_scopes))}.",
            "Ask which scope the engineer means and retry with scope_id.")
    key, rule, rules = matches[0]
    return rule, rules, key, None


def map_exception_to_error(exc: Exception, request: ScopeRequest) -> dict[str, Any]:
    """Translates data-source exceptions into guided errors the model can act on."""
    if isinstance(exc, ScopeNotFoundError):
        return tool_error("scope_not_found", str(exc), "Ask the user to confirm the ID, or choose one of the known IDs listed.")
    name = type(exc).__name__
    if name in ("PermissionDenied", "Forbidden"):
        return tool_error(
            "permission_denied",
            f"The agent's identity cannot read firewall rules for {request.scope_type} {request.scope_id}.",
            "Grant read-only access: roles/compute.networkViewer on the project, or "
            "roles/compute.orgFirewallPolicyUser on the organization/folder, then retry.",
        )
    if name == "NotFound":
        return tool_error("scope_not_found", f"{request.scope_type} '{request.scope_id}' was not found.",
                          "Verify the ID with the user (organization/folder IDs are numeric).")
    if name in ("DefaultCredentialsError", "Unauthenticated", "Unauthorized", "RefreshError"):
        return tool_error("authentication_required", "No valid Google Cloud credentials are available.",
                          "Run 'gcloud auth application-default login' or attach a service account, then retry.")
    if name in ("TooManyRequests", "ResourceExhausted"):
        return tool_error("rate_limited", "The Compute Engine API rate limit was reached.",
                          "Wait a few seconds and retry once.")
    return tool_error("cloud_api_error", f"Reading firewall rules failed ({name}).",
                      "Retry once; if it keeps failing, tell the user and suggest FIREWALL_DATA_MODE=sample for a demo.")


async def load_rules(
    state: Any, request: ScopeRequest, *, refresh: bool = False
) -> tuple[list[FirewallRule] | None, list[str], dict[str, Any] | None]:
    """Returns (rules, warnings, None) from cache or the data source, or (None, [], guided_error).

    Blocking Compute Engine calls run in a worker thread (``asyncio.to_thread``)
    so concurrent sessions are never stalled on the event loop.
    """
    if not refresh:
        rules = cached_rules(state, request)
        if rules is not None:
            return rules, [], None
    settings = get_settings()
    source = get_data_source(settings.firewall_data_mode)
    try:
        with traced_operation("firewall_inventory.list_rules", scope_type=request.scope_type,
                              scope_id=request.scope_id, data_mode=source.mode,
                              include_inherited=request.include_inherited_policies) as span:
            rules, warnings = await asyncio.to_thread(source.list_rules_with_warnings, request)
            span.set_attribute("firewall_ops.rule_count", len(rules))
    except Exception as exc:  # noqa: BLE001 - every failure becomes a guided error
        logger.warning("firewall inventory read failed", extra={
            "event": "inventory_read_failed", "scope_type": request.scope_type,
            "scope_id": request.scope_id, "error_type": type(exc).__name__})
        return None, [], map_exception_to_error(exc, request)
    for warning in warnings:
        logger.warning("partial inventory read", extra={"event": "inventory_read_warning", "detail": warning})
    cache_rules(state, request, rules)
    return rules, warnings, None


def compact_rule(rule: FirewallRule) -> dict[str, Any]:
    """Token-efficient view of a rule for the model."""
    if rule.source_kind == "vpc_firewall_rule":
        level = "vpc"
    elif rule.source_kind == "network_policy_rule":
        level = "network_policy"
    else:
        level = f"{rule.scope_type}_policy"
    targets = rule.target_service_accounts + rule.target_tags + rule.target_secure_tags + rule.target_resources
    view: dict[str, Any] = {
        "name": rule.name,
        "level": level,
        "direction": rule.direction,
        "action": rule.action,
        "priority": rule.priority,
        "peers": rule.source_ranges if rule.direction == "INGRESS" else rule.destination_ranges,
        "ports": rule.short_ports(),
        "targets": targets or "ALL instances",
        "logging": rule.logging_enabled,
    }
    if rule.policy_name:
        view["policy"] = rule.policy_name
    if rule.network:
        view["network"] = rule.network
    if rule.disabled:
        view["disabled"] = True
    if rule.implicit_source_note:
        view["note"] = "implicit 0.0.0.0/0 source"
    return view


def rule_level(rule: FirewallRule) -> str:
    """Human-readable evaluation level of a rule."""
    if rule.source_kind == "hierarchical_policy_rule":
        return "1 - organization policy" if rule.scope_type == "organization" else "2 - folder policy"
    if rule.source_kind == "network_policy_rule":
        return "4 - network firewall policy (after VPC rules by default)"
    return "3 - project VPC firewall rule"
