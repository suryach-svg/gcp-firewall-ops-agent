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
"""A scripted, deterministic stand-in for Gemini used by offline end-to-end tests.

It recognizes which agent is calling from the system instruction and returns
the function calls / text that a well-behaved model would produce, built from
the *real* tool responses. This exercises the full ADK machinery (Runner,
transfers, SequentialAgent, output_key state passing, plugins, HITL
confirmation, persistence) without network access or credentials.
"""

import re
from collections.abc import AsyncGenerator
from typing import Any

from google.adk.models import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.genai import types
from pydantic import Field

_MARKERS = (
    ("**GCP Firewall Ops Coordinator**", "coordinator"),
    ("**Rule Collector**", "collector"),
    ("**Risk Analyst**", "analyst"),
    ("**Report Writer**", "writer"),
    ("**Firewall Ops Coach**", "coach"),
)


def _system_text(llm_request: LlmRequest) -> str:
    instruction = llm_request.config.system_instruction if llm_request.config else None
    if instruction is None:
        return ""
    if isinstance(instruction, str):
        return instruction
    if isinstance(instruction, types.Content):
        return " ".join(p.text or "" for p in instruction.parts or [])
    return str(instruction)


def _is_quoted_context(text: str) -> bool:
    """ADK presents other agents' turns as quoted 'For context' / '[agent] ...' user messages."""
    return text.startswith("For context") or text.startswith("[")


def _latest_user_text(llm_request: LlmRequest) -> str:
    for content in reversed(llm_request.contents):
        if content.role != "user":
            continue
        for part in content.parts or []:
            if part.text and not _is_quoted_context(part.text):
                return part.text
    return ""


def _last_function_response(llm_request: LlmRequest) -> types.FunctionResponse | None:
    """Most recent function response produced after the latest real user message."""
    for content in reversed(llm_request.contents):
        for part in reversed(content.parts or []):
            if part.function_response is not None and part.function_response.name != "adk_request_confirmation":
                return part.function_response
            if content.role == "user" and part.text and not _is_quoted_context(part.text):
                return None
    return None


def _find_response(llm_request: LlmRequest, name: str) -> dict[str, Any] | None:
    for content in reversed(llm_request.contents):
        for part in content.parts or []:
            if part.function_response is not None and part.function_response.name == name:
                return dict(part.function_response.response or {})
    return None


def _call(name: str, **args: Any) -> LlmResponse:
    return LlmResponse(content=types.Content(role="model", parts=[types.Part(function_call=types.FunctionCall(name=name, args=args))]))


def _text(text: str) -> LlmResponse:
    return LlmResponse(content=types.Content(role="model", parts=[types.Part(text=text)]))


class ScriptedFirewallLlm(BaseLlm):
    """Deterministic fake model that follows each agent's instructions."""

    model: str = "scripted-firewall-llm"
    calls: list[str] = Field(default_factory=list)
    seen_user_texts: list[str] = Field(default_factory=list)

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        system = _system_text(llm_request)
        agent = next((name for marker, name in _MARKERS if marker in system), "summarizer")
        self.calls.append(agent)
        self.seen_user_texts.extend(
            part.text for content in llm_request.contents if content.role == "user"
            for part in content.parts or [] if part.text)
        handler = getattr(self, f"_{agent}")
        yield handler(llm_request)

    # ---- per-agent behaviour ---------------------------------------------------
    def _coordinator(self, llm_request: LlmRequest) -> LlmResponse:
        text = _latest_user_text(llm_request).lower()
        if "audit" in text:
            return _call("transfer_to_agent", agent_name="firewall_audit_pipeline")
        if any(word in text for word in ("why", "stage", "draft", "explain", "fix")):
            return _call("transfer_to_agent", agent_name="firewall_ops_coach")
        return _text("I can audit firewall rules for an organization, folder or project. Try: 'Audit project prod-payments-app'.")

    def _collector(self, llm_request: LlmRequest) -> LlmResponse:
        last = _last_function_response(llm_request)
        if last is not None and last.name == "list_firewall_rules_for_scope":
            resp = dict(last.response or {})
            return _text(f"Collected {resp.get('rule_count')} rules for {resp.get('scope', {}).get('scope_id')} "
                         f"in {resp.get('data_mode')} mode: {resp.get('rules_by_level')}.")
        match = re.search(r"project ([a-z][a-z0-9-]{4,28}[a-z0-9])", _latest_user_text(llm_request))
        return _call("list_firewall_rules_for_scope", scope_type="project",
                     scope_id=match.group(1) if match else "prod-payments-app", include_inherited_policies=True)

    def _analyst(self, llm_request: LlmRequest) -> LlmResponse:
        last = _last_function_response(llm_request)
        if last is None or last.name not in ("analyze_firewall_rule_risks", "search_firewall_best_practices"):
            return _call("analyze_firewall_rule_risks")
        if last.name == "analyze_firewall_rule_risks":
            return _call("search_firewall_best_practices", query="internet exposed ssh iap", max_results=2)
        analysis = _find_response(llm_request, "analyze_firewall_rule_risks") or {}
        kb = (_find_response(llm_request, "search_firewall_best_practices") or {}).get("articles", [{}])[0]
        high = [f for f in analysis.get("findings", []) if f["severity"] in ("CRITICAL", "HIGH")]
        lines = [f"Posture: {analysis.get('posture_score')}/100 (grade {analysis.get('posture_grade')}).",
                 f"Counts: {analysis.get('severity_counts')}.", "Top risks:"]
        lines += [f"- **{f['rule_name']}** {f['severity']} {f['check_id']}: {f['title']}" for f in high]
        lines.append(f"Grounding: {kb.get('kb_id')}")
        return _text("\n".join(lines))

    def _writer(self, llm_request: LlmRequest) -> LlmResponse:
        system = _system_text(llm_request)
        analysis = system.split("Analysis:", 1)[-1].split("## Required Markdown format", 1)[0].strip()
        return _text("# Firewall Risk Report - project prod-payments-app\n" + analysis)

    def _coach(self, llm_request: LlmRequest) -> LlmResponse:
        last = _last_function_response(llm_request)
        text = _latest_user_text(llm_request).lower()
        if last is None:
            if "stage" in text:
                return _call("apply_firewall_remediation", rule_name="default-allow-ssh",
                             change_type="restrict_source_ranges",
                             justification="Replace internet-wide SSH with IAP-only access",
                             new_source_ranges=["35.235.240.0/20"])
            if "draft" in text:
                return _call("propose_least_privilege_rule", rule_name="default-allow-ssh")
            return _call("get_firewall_rule_details", rule_name="default-allow-ssh")
        resp = dict(last.response or {})
        if last.name == "get_firewall_rule_details":
            checks = sorted({f["check_id"] for f in resp.get("findings", [])})
            return _text(f"default-allow-ssh is risky: findings {checks}. Use IAP (KB-IAP-ADMIN).")
        if last.name == "apply_firewall_remediation":
            return _text(f"Change {resp.get('status')} {resp.get('change_request_id', '')}".strip())
        return _text(f"Done: {last.name} -> {resp.get('status')}")

    def _summarizer(self, llm_request: LlmRequest) -> LlmResponse:
        return _text("Summary: the engineer audited firewall rules and discussed remediation.")
