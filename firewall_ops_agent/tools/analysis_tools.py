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
"""Analysis tools: run the deterministic risk engine and explain its checks."""

import logging
from typing import Annotated, Any, Literal

from google.adk.tools.tool_context import ToolContext
from pydantic import Field, ValidationError

from ..core.knowledge_base import get_knowledge_base
from ..core.risk_engine import CHECK_CATALOG, analyze_rules, filter_findings
from ..observability.tracing import traced_operation
from ..schemas import ScopeRequest, Severity
from ._common import STATE_LAST_SCOPE, STATE_RISK_SUMMARY, load_rules, scope_key, store_report, tool_error
from .inventory_tools import SCOPE_ID_PATTERN

logger = logging.getLogger("firewall_ops_agent.tools")
_DETAILED_FINDINGS = 12


async def analyze_firewall_rule_risks(
    tool_context: ToolContext,
    min_severity: Annotated[
        Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        Field(description="Lowest severity to include in the returned findings."),
    ] = "LOW",
    max_findings: Annotated[
        int, Field(ge=1, le=50, description="Maximum number of findings to return, worst first.")
    ] = 25,
    scope_type: Annotated[
        Literal["organization", "folder", "project"] | None,
        Field(description="Optional: analyze a different scope than the last one loaded."),
    ] = None,
    scope_id: Annotated[
        str | None,
        Field(pattern=SCOPE_ID_PATTERN, description="Optional: required together with scope_type."),
    ] = None,
    include_inherited_policies: Annotated[
        bool | None, Field(description="Optional, project scope only: include inherited org/folder policies.")
    ] = None,
) -> dict[str, Any]:
    """Runs the deterministic firewall risk engine and returns prioritized findings.

    By default analyzes the scope most recently loaded with
    list_firewall_rules_for_scope. The findings, severities and posture score
    come from a rule engine (13 checks covering internet exposure, broad port
    ranges, missing logging, default rules, hierarchy overrides and shadowed
    rules) and are the source of truth: explain them, do not change them.

    Args:
        min_severity: Lowest severity to include: CRITICAL, HIGH, MEDIUM, LOW or INFO.
        max_findings: Maximum number of findings to return (1-50), worst first.
        scope_type: Optional. Analyze a different scope than the last one loaded.
        scope_id: Optional. Required together with scope_type.
        include_inherited_policies: Optional. Project scope only.

    Returns:
        status "success" with posture_score (0-100, higher is better),
        posture_grade (A-F), severity_counts, findings (check_id, severity,
        rule_name, title, evidence, risk_explanation, recommendation,
        scc_category) and strengths; or status "error" with a recovery_hint.
    """
    state = tool_context.state
    last = state.get(STATE_LAST_SCOPE) or {}
    try:
        if scope_type and scope_id:
            request = ScopeRequest(scope_type=scope_type, scope_id=scope_id,
                                   include_inherited_policies=bool(include_inherited_policies))
        elif last:
            request = ScopeRequest(scope_type=last["scope_type"], scope_id=last["scope_id"],
                                   include_inherited_policies=last.get("include_inherited_policies", False))
        else:
            return tool_error("no_scope", "No scope has been loaded and none was provided.",
                              "Call list_firewall_rules_for_scope first, or pass scope_type and scope_id.")
    except ValidationError as exc:
        return tool_error("invalid_arguments", "; ".join(e["msg"] for e in exc.errors()),
                          "Organization/folder IDs are numeric; project IDs are lowercase with hyphens.")
    max_findings = max(1, min(50, int(max_findings)))

    rules, _, error = await load_rules(state, request)
    if error:
        return error
    with traced_operation("risk_engine.analyze", scope_type=request.scope_type, scope_id=request.scope_id,
                          rule_count=len(rules)) as span:
        report = analyze_rules(rules, request.scope_type, request.scope_id)
        span.set_attribute("firewall_ops.finding_count", len(report.findings))
        span.set_attribute("firewall_ops.posture_score", report.posture_score)

    store_report(state, scope_key(request), report.model_dump(mode="json"))
    top = [f"{f.rule_name} ({f.check_id} {f.severity.value})" for f in report.findings[:5]]
    state[STATE_RISK_SUMMARY] = (
        f"{request.scope_type} {request.scope_id}: posture {report.posture_score}/100 (grade {report.posture_grade}); "
        f"counts {report.severity_counts}; top risks: {', '.join(top) or 'none'}"
    )
    logger.info("risk analysis complete", extra={
        "event": "risk_analysis_complete", "scope_type": request.scope_type, "scope_id": request.scope_id,
        "rules": len(rules), "findings": len(report.findings), "posture_score": report.posture_score})

    selected = filter_findings(report, Severity(min_severity))[:max_findings]
    findings = []
    for index, finding in enumerate(selected):
        item = {"check_id": finding.check_id, "severity": finding.severity.value, "rule_name": finding.rule_name,
                "title": finding.title, "evidence": finding.evidence}
        if index < _DETAILED_FINDINGS:
            item.update(risk_explanation=finding.risk_explanation, recommendation=finding.recommendation,
                        scc_category=finding.scc_category)
        findings.append(item)
    high_risk_rules = sorted({f.rule_name for f in report.findings if f.severity.rank >= Severity.HIGH.rank})
    return {
        "status": "success",
        "scope": request.model_dump(),
        "rules_analyzed": report.rules_analyzed,
        "posture_score": report.posture_score,
        "posture_grade": report.posture_grade,
        "severity_counts": report.severity_counts,
        "total_findings": len(report.findings),
        "findings_returned": len(findings),
        "findings": findings,
        "critical_and_high_rules": high_risk_rules,
        "strengths": report.strengths,
        "analysis_engine": "deterministic rule engine (source of truth - do not re-rate findings)",
    }


def explain_firewall_risk_check(
    check_id: Annotated[str, Field(pattern=r"^[Ff][Ww]-\d{3}$", description="Check identifier, FW-001 to FW-013.")],
) -> dict[str, Any]:
    """Explains what a risk check (e.g. "FW-012") detects and how to remediate it.

    Args:
        check_id: Check identifier from a finding, from FW-001 to FW-013.

    Returns:
        status "success" with the check's title, default severity, detection
        logic and the linked knowledge base guidance; or status "error".
    """
    normalized = (check_id or "").strip().upper()
    entry = CHECK_CATALOG.get(normalized)
    if entry is None:
        return tool_error("unknown_check", f"Unknown check id '{check_id}'.",
                          f"Use one of: {', '.join(sorted(CHECK_CATALOG))}.")
    articles = get_knowledge_base().by_check_id(normalized)
    return {
        "status": "success",
        "check_id": normalized,
        **entry,
        "guidance": [
            {"kb_id": a.id, "title": a.title, "content": a.content, "references": a.references} for a in articles
        ],
    }
