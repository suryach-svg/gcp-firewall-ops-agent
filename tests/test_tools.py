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
"""Unit tests for the ADK function tools (schemas, guided errors, per-scope state, HITL)."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from google.adk.tools import FunctionTool
from google.adk.tools.tool_confirmation import ToolConfirmation
from google.api_core import exceptions as api_exceptions

from firewall_ops_agent.config import get_settings
from firewall_ops_agent.schemas import ScopeRequest
from firewall_ops_agent.tools import remediation_tools
from firewall_ops_agent.tools._common import inventory_state_key, map_exception_to_error, report_state_key
from firewall_ops_agent.tools.analysis_tools import analyze_firewall_rule_risks, explain_firewall_risk_check
from firewall_ops_agent.tools.inventory_tools import get_firewall_rule_details, list_firewall_rules_for_scope
from firewall_ops_agent.tools.knowledge_tools import search_firewall_best_practices
from firewall_ops_agent.tools.remediation_tools import apply_firewall_remediation, propose_least_privilege_rule
from tests.conftest import FakeToolContext

PAYMENTS = "project/prod-payments-app+inherited"


async def _load(ctx, project="prod-payments-app", inherited=True, scope_type="project"):
    result = await list_firewall_rules_for_scope(scope_type, project, ctx,
                                                 include_inherited_policies=inherited and scope_type == "project")
    assert result["status"] == "success", result
    return result


# ---------------------------------------------------------------- inventory + per-scope state
async def test_list_rules_returns_compact_view_and_caches_state(tool_context):
    result = await _load(tool_context)
    assert result["rule_count"] == 18
    assert result["rules_by_level"] == {"vpc": 11, "organization_policy": 4, "folder_policy": 3}
    assert {"name", "level", "ports", "targets", "logging"} <= set(result["rules"][0])
    state = tool_context.state
    assert state["last_audited_scope"]["scope_key"] == PAYMENTS
    assert len(state[inventory_state_key(PAYMENTS)]) == 18
    assert state["audited_scopes"] == [PAYMENTS]


async def test_each_scope_gets_its_own_state_key(tool_context):
    await _load(tool_context, "prod-data-platform")
    await _load(tool_context)
    assert tool_context.state["audited_scopes"] == ["project/prod-data-platform+inherited", PAYMENTS]
    assert inventory_state_key("project/prod-data-platform+inherited") in tool_context.state
    # Re-auditing a scope moves it to the end instead of duplicating it.
    await _load(tool_context, "prod-data-platform")
    assert tool_context.state["audited_scopes"] == [PAYMENTS, "project/prod-data-platform+inherited"]


async def test_list_rules_invalid_id_returns_guided_error(tool_context):
    result = await list_firewall_rules_for_scope("organization", "acme-org", tool_context)
    assert result["status"] == "error" and result["error_type"] == "invalid_arguments"
    assert "numeric" in result["message"] and result["recovery_hint"]


async def test_list_rules_unknown_scope_lists_known_ids(tool_context):
    result = await list_firewall_rules_for_scope("project", "unknown-project-1", tool_context)
    assert result["error_type"] == "scope_not_found"
    assert "prod-payments-app" in result["message"]


# ---------------------------------------------------------------- analysis
async def test_analyze_requires_a_scope(tool_context):
    result = await analyze_firewall_rule_risks(tool_context)
    assert result["error_type"] == "no_scope" and "list_firewall_rules_for_scope" in result["recovery_hint"]


async def test_analyze_uses_last_scope_and_stores_report(tool_context):
    await _load(tool_context)
    result = await analyze_firewall_rule_risks(tool_context)
    assert result["status"] == "success"
    assert (result["posture_score"], result["posture_grade"]) == (19, "F")
    assert result["findings"][0]["severity"] == "CRITICAL"
    assert "recommendation" in result["findings"][0]
    assert {"default-allow-ssh", "allow-mysql-from-anywhere"} <= set(result["critical_and_high_rules"])
    assert "prod-payments-app" in tool_context.state["latest_risk_summary"]
    assert tool_context.state[report_state_key(PAYMENTS)]["posture_score"] == 19


async def test_analyze_severity_filter(tool_context):
    await _load(tool_context)
    result = await analyze_firewall_rule_risks(tool_context, min_severity="CRITICAL")
    assert result["findings"] and {f["severity"] for f in result["findings"]} == {"CRITICAL"}


async def test_analyze_explicit_scope_loads_it_on_demand(tool_context):
    result = await analyze_firewall_rule_risks(tool_context, scope_type="folder", scope_id="200000000001")
    assert result["status"] == "success" and result["posture_grade"] == "A"
    assert report_state_key("folder/200000000001") in tool_context.state


# ---------------------------------------------------------------- rule details + scoped lookup
async def test_rule_details_include_findings_and_shadowing(tool_context):
    await _load(tool_context)
    await analyze_firewall_rule_risks(tool_context)
    result = get_firewall_rule_details("allow-legacy-telnet", tool_context)
    assert result["status"] == "success" and result["scope"] == PAYMENTS
    assert result["shadowed_by"]["name"] == "org-deny-cleartext-protocols"
    assert "FW-005" in {f["check_id"] for f in result["findings"]}


async def test_rule_details_suggests_close_matches(tool_context):
    await _load(tool_context)
    result = get_firewall_rule_details("default-allow-shh", tool_context)
    assert result["error_type"] == "rule_not_found" and "default-allow-ssh" in result["recovery_hint"]


async def test_rule_lookup_never_mixes_rules_from_other_scopes(tool_context):
    # The nonprod folder allows everything; it does not govern prod-payments-app and must not be
    # treated as the rule that shadows the project's telnet deny.
    await _load(tool_context, "200000000002", scope_type="folder")
    await _load(tool_context, inherited=False)
    result = get_firewall_rule_details("deny-telnet-from-internet", tool_context)
    assert result["scope"] == "project/prod-payments-app"
    assert result["shadowed_by"]["name"] == "allow-legacy-telnet"


async def test_rule_present_in_several_other_scopes_requires_scope_id(tool_context):
    await _load(tool_context)
    await _load(tool_context, "prod-data-platform")
    await _load(tool_context, "200000000002", scope_type="folder")  # last scope does not contain the rule
    ambiguous = get_firewall_rule_details("org-allow-iap-admin", tool_context)
    assert ambiguous["error_type"] == "ambiguous_rule_name"
    assert "prod-data-platform" in ambiguous["message"] and "scope_id" in ambiguous["recovery_hint"]
    resolved = get_firewall_rule_details("org-allow-iap-admin", tool_context, scope_id="prod-data-platform")
    assert resolved["status"] == "success" and resolved["scope"] == "project/prod-data-platform+inherited"


async def test_rule_lookup_rejects_unaudited_scope(tool_context):
    await _load(tool_context)
    result = get_firewall_rule_details("default-allow-ssh", tool_context, scope_id="dev-sandbox-web")
    assert result["error_type"] == "scope_not_loaded"


# ---------------------------------------------------------------- knowledge tools
def test_explain_check_links_knowledge_base():
    result = explain_firewall_risk_check("fw-001")
    assert result["status"] == "success" and result["check_id"] == "FW-001"
    assert "KB-IAP-ADMIN" in {g["kb_id"] for g in result["guidance"]}
    assert explain_firewall_risk_check("FW-999")["error_type"] == "unknown_check"


def test_knowledge_base_search_ranks_relevant_article_first():
    result = search_firewall_best_practices("ssh exposed to internet use iap", max_results=3)
    assert result["articles"][0]["kb_id"] == "KB-IAP-ADMIN"
    assert search_firewall_best_practices("   ")["status"] == "error"


# ---------------------------------------------------------------- tool schemas the model sees
def _schema(fn) -> dict:
    declaration = FunctionTool(fn)._get_declaration()
    if declaration.parameters_json_schema:
        return declaration.parameters_json_schema
    return declaration.parameters.model_dump(mode="json", exclude_none=True, by_alias=True)


def test_tool_declarations_carry_enums_patterns_bounds_and_descriptions():
    listing = _schema(list_firewall_rules_for_scope)["properties"]
    assert listing["scope_type"]["enum"] == ["organization", "folder", "project"]
    assert listing["scope_id"]["pattern"].startswith("^") and listing["scope_id"]["description"]
    analysis = _schema(analyze_firewall_rule_risks)["properties"]
    assert analysis["max_findings"]["maximum"] == 50 and analysis["max_findings"]["minimum"] == 1
    assert "CRITICAL" in analysis["min_severity"]["enum"]
    remediation = _schema(apply_firewall_remediation)
    assert remediation["properties"]["change_type"]["enum"] == ["restrict_source_ranges", "disable_rule", "enable_logging"]
    assert set(remediation["required"]) == {"rule_name", "change_type", "justification"}
    assert "tool_context" not in remediation["properties"]
    assert _schema(explain_firewall_risk_check)["properties"]["check_id"]["pattern"]


# ---------------------------------------------------------------- guided errors from real API exceptions
@pytest.mark.parametrize(
    ("exception", "error_type"),
    [
        (api_exceptions.PermissionDenied("denied"), "permission_denied"),
        (api_exceptions.Forbidden("forbidden"), "permission_denied"),
        (api_exceptions.NotFound("missing"), "scope_not_found"),
        (api_exceptions.Unauthorized("no creds"), "authentication_required"),
        (api_exceptions.Unauthenticated("no creds"), "authentication_required"),
        (api_exceptions.TooManyRequests("slow down"), "rate_limited"),
        (api_exceptions.ResourceExhausted("quota"), "rate_limited"),
        (api_exceptions.InternalServerError("boom"), "cloud_api_error"),
    ],
)
def test_api_exceptions_become_guided_errors(exception, error_type):
    error = map_exception_to_error(exception, ScopeRequest(scope_type="project", scope_id="prod-payments-app"))
    assert error["status"] == "error" and error["error_type"] == error_type and error["recovery_hint"]


# ---------------------------------------------------------------- remediation proposals
async def test_propose_uses_iap_for_admin_ports(tool_context):
    await _load(tool_context)
    result = propose_least_privilege_rule("default-allow-ssh", tool_context)
    assert result["status"] == "success"
    assert result["hardened_rule"]["source_ranges"] == ["35.235.240.0/20"]
    assert result["hardened_rule"]["logging_enabled"] is True
    assert "--source-ranges=35.235.240.0/20" in result["gcloud_command"]
    assert 'resource "google_compute_firewall"' in result["terraform_snippet"]


async def test_propose_database_rule_asks_engineer_for_sources(tool_context):
    await _load(tool_context)
    first = propose_least_privilege_rule("allow-mysql-from-anywhere", tool_context)
    assert first["status"] == "needs_input" and "allowed_source_ranges" in first["recovery_hint"]
    second = propose_least_privilege_rule("allow-mysql-from-anywhere", tool_context,
                                          allowed_source_ranges=["10.20.0.0/24"])
    assert second["status"] == "success" and second["hardened_rule"]["source_ranges"] == ["10.20.0.0/24"]


async def test_propose_fixes_shadowed_deny_priority(tool_context):
    await _load(tool_context, inherited=False)
    result = propose_least_privilege_rule("deny-telnet-from-internet", tool_context)
    assert result["hardened_rule"]["priority"] == 999


# ---------------------------------------------------------------- human-in-the-loop remediation
async def test_apply_pauses_for_human_approval(tool_context):
    await _load(tool_context)
    result = await apply_firewall_remediation("default-allow-ssh", "restrict_source_ranges",
                                              "Replace internet SSH with IAP access", tool_context,
                                              new_source_ranges=["35.235.240.0/20"])
    assert result["status"] == "pending_human_approval"
    assert len(tool_context.confirmation_requests) == 1
    assert "APPROVAL REQUIRED" in tool_context.confirmation_requests[0]["hint"]
    assert tool_context.actions.skip_summarization is True
    assert "approved_change_requests" not in tool_context.state


async def test_apply_after_approval_stages_change_in_sample_mode():
    ctx = FakeToolContext(confirmation=ToolConfirmation(confirmed=True, payload={"change_ticket": "CHG-42"}))
    await _load(ctx)
    result = await apply_firewall_remediation("default-allow-ssh", "restrict_source_ranges",
                                              "Replace internet SSH with IAP access", ctx,
                                              new_source_ranges=["35.235.240.0/20"])
    assert result["status"] == "staged" and result["change_request_id"].startswith("CR-")
    record = ctx.state["approved_change_requests"][0]
    assert record["change_ticket"] == "CHG-42" and record["execution_mode"].startswith("staged")
    rule = next(r for r in ctx.state[inventory_state_key(PAYMENTS)] if r["name"] == "default-allow-ssh")
    assert rule["source_ranges"] == ["35.235.240.0/20"]


async def test_staged_change_is_reflected_in_every_cached_view_of_the_rule():
    ctx = FakeToolContext(confirmation=ToolConfirmation(confirmed=True, payload={"change_ticket": "CHG-7"}))
    await _load(ctx, inherited=False)
    await _load(ctx)
    await apply_firewall_remediation("default-allow-rdp", "disable_rule", "Unused legacy RDP access rule", ctx)
    for key in ("project/prod-payments-app", PAYMENTS):
        rule = next(r for r in ctx.state[inventory_state_key(key)] if r["name"] == "default-allow-rdp")
        assert rule["disabled"] is True, key


async def test_apply_rejected_by_human():
    ctx = FakeToolContext(confirmation=ToolConfirmation(confirmed=False))
    await _load(ctx)
    result = await apply_firewall_remediation("default-allow-rdp", "disable_rule", "Unused legacy RDP access rule", ctx)
    assert result["status"] == "rejected"
    assert ctx.state["approved_change_requests"][0]["change_status"] == "rejected_by_human"


async def test_apply_refuses_internet_wide_ranges(tool_context):
    await _load(tool_context)
    result = await apply_firewall_remediation("default-allow-ssh", "restrict_source_ranges",
                                              "This would be a bad idea", tool_context,
                                              new_source_ranges=["0.0.0.0/0"])
    assert result["status"] == "error" and "internet" in result["message"]
    assert not tool_context.confirmation_requests


class _FakeFirewallsClient:
    """Records PATCH calls instead of calling the Compute Engine API."""

    patches: list = []

    def patch(self, *, project, firewall, firewall_resource):
        self.patches.append((project, firewall, firewall_resource))
        return SimpleNamespace(result=lambda timeout=None: None)


@pytest.fixture
def live_remediation(monkeypatch):
    """Live data mode + ENABLE_LIVE_REMEDIATION=true, with the Compute client mocked."""
    from google.cloud import compute_v1

    live = replace(get_settings(), firewall_data_mode="live", enable_live_remediation=True)
    monkeypatch.setattr(remediation_tools, "get_settings", lambda: live)
    _FakeFirewallsClient.patches = []
    monkeypatch.setattr(compute_v1, "FirewallsClient", _FakeFirewallsClient)
    return _FakeFirewallsClient


async def test_live_change_requires_a_change_ticket(live_remediation):
    pending = FakeToolContext()
    await _load(pending)
    first = await apply_firewall_remediation("default-allow-ssh", "restrict_source_ranges",
                                             "Replace internet SSH with IAP access", pending,
                                             new_source_ranges=["35.235.240.0/20"])
    assert first["planned_change"]["execution_mode"] == "LIVE change to Google Cloud"
    assert "change ticket is REQUIRED" in pending.confirmation_requests[0]["hint"]

    no_ticket = FakeToolContext(confirmation=ToolConfirmation(confirmed=True, payload={"change_ticket": " "}))
    await _load(no_ticket)
    result = await apply_firewall_remediation("default-allow-ssh", "restrict_source_ranges",
                                              "Replace internet SSH with IAP access", no_ticket,
                                              new_source_ranges=["35.235.240.0/20"])
    assert result["status"] == "rejected" and result["change_status"] == "rejected_missing_ticket"
    assert live_remediation.patches == [], "nothing may be changed without a ticket"


async def test_live_change_with_ticket_patches_only_the_approved_fields(live_remediation):
    ctx = FakeToolContext(confirmation=ToolConfirmation(confirmed=True, payload={"change_ticket": "CHG-9"}))
    await _load(ctx)
    result = await apply_firewall_remediation("default-allow-ssh", "restrict_source_ranges",
                                              "Replace internet SSH with IAP access", ctx,
                                              new_source_ranges=["35.235.240.0/20"])
    assert result["status"] == "applied" and result["change_status"] == "applied"
    [(project, firewall, patch)] = live_remediation.patches
    assert (project, firewall) == ("prod-payments-app", "default-allow-ssh")
    assert list(patch.source_ranges) == ["35.235.240.0/20"]
    assert not patch.allowed, "the patch must not touch other fields"
    assert ctx.state["approved_change_requests"][-1]["change_ticket"] == "CHG-9"


async def test_live_mode_never_patches_hierarchical_policy_rules(live_remediation):
    ctx = FakeToolContext(confirmation=ToolConfirmation(confirmed=True, payload={"change_ticket": "CHG-10"}))
    await _load(ctx)
    result = await apply_firewall_remediation("org-legacy-break-glass-ssh", "disable_rule",
                                              "Break-glass SSH is no longer needed", ctx)
    assert result["status"] == "staged" and result["planned_change"]["execution_mode"].startswith("staged")
    assert live_remediation.patches == []
