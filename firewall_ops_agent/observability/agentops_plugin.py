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
"""AgentOps plugin: records the agent's INTENT before every action and the OUTCOME after.

For every model call and tool call this plugin writes a pair of structured,
redacted JSON log entries and matching OpenTelemetry span events:

  model_intent   -> what the agent is about to ask the model (model, context size)
  agent_decision -> which tools the model decided to call, with which arguments
  tool_intent    -> the exact tool call about to execute
  tool_outcome   -> status, duration and a compact summary of what happened

Comparing intent with outcome makes failures explainable ("the agent intended
to read project X but got permission_denied after 120 ms").
"""

from __future__ import annotations

import logging
import time
from typing import Any

from google.adk.agents.base_agent import BaseAgent
from google.adk.agents.callback_context import CallbackContext
from google.adk.agents.invocation_context import InvocationContext
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.tool_context import ToolContext
from opentelemetry import trace

from .redaction import redact_value

logger = logging.getLogger("firewall_ops_agent.agentops")
_SUMMARY_KEYS = (
    "error_type", "data_mode", "rule_count", "posture_score", "posture_grade", "findings_returned",
    "total_findings", "results_returned", "change_status", "change_request_id",
)


def summarize_tool_result(result: Any) -> dict[str, Any]:
    """Builds a compact, log-safe summary of a tool result."""
    if not isinstance(result, dict):
        return {"status": "success", "result_type": type(result).__name__}
    status = result.get("status") or ("error" if "error" in result else "success")
    summary: dict[str, Any] = {"status": status}
    for key in _SUMMARY_KEYS:
        if key in result:
            summary[key] = result[key]
    if isinstance(result.get("error"), str):
        summary["error"] = result["error"][:200]
    if "reflection_guidance" in result:
        summary["status"] = "error_reflected"
    return summary


def _span_event(name: str, attributes: dict[str, Any]) -> None:
    safe = {k: v if isinstance(v, (str, bool, int, float)) else str(v) for k, v in attributes.items() if v is not None}
    trace.get_current_span().add_event(name, attributes=safe)


def _approx_tokens(llm_request: LlmRequest) -> int:
    chars = 0
    for content in llm_request.contents or []:
        for part in content.parts or []:
            if part.text:
                chars += len(part.text)
            elif part.function_response is not None:
                chars += len(str(part.function_response.response))
    return chars // 4


class AgentOpsObservabilityPlugin(BasePlugin):
    """Structured intent/outcome logging + span events for every agent action."""

    def __init__(self, name: str = "agentops_observability") -> None:
        super().__init__(name)
        self._run_started: dict[str, float] = {}
        self._model_started: dict[str, float] = {}
        self._tool_started: dict[str, float] = {}

    # ---- invocation lifecycle -------------------------------------------------
    async def before_run_callback(self, *, invocation_context: InvocationContext) -> None:
        self._run_started[invocation_context.invocation_id] = time.perf_counter()
        logger.info("invocation started", extra={
            "event": "invocation_start",
            "invocation_id": invocation_context.invocation_id,
            "session_id": invocation_context.session.id,
            "app_name": invocation_context.session.app_name,
        })

    async def after_run_callback(self, *, invocation_context: InvocationContext) -> None:
        started = self._run_started.pop(invocation_context.invocation_id, None)
        logger.info("invocation finished", extra={
            "event": "invocation_end",
            "invocation_id": invocation_context.invocation_id,
            "session_id": invocation_context.session.id,
            "duration_ms": round((time.perf_counter() - started) * 1000, 1) if started else None,
        })

    async def before_agent_callback(self, *, agent: BaseAgent, callback_context: CallbackContext) -> None:
        logger.info("agent started", extra={"event": "agent_start", "agent": agent.name,
                                             "invocation_id": callback_context.invocation_id})

    async def after_agent_callback(self, *, agent: BaseAgent, callback_context: CallbackContext) -> None:
        logger.info("agent finished", extra={"event": "agent_end", "agent": agent.name,
                                              "invocation_id": callback_context.invocation_id})

    # ---- model calls ------------------------------------------------------------
    async def before_model_callback(
        self, *, callback_context: CallbackContext, llm_request: LlmRequest
    ) -> LlmResponse | None:
        key = f"{callback_context.invocation_id}:{callback_context.agent_name}"
        self._model_started[key] = time.perf_counter()
        fields = {
            "event": "model_intent",
            "agent": callback_context.agent_name,
            "invocation_id": callback_context.invocation_id,
            "model": llm_request.model,
            "content_count": len(llm_request.contents or []),
            "approx_prompt_tokens": _approx_tokens(llm_request),
        }
        logger.info("model call intended", extra=fields)
        _span_event("model_intent", fields)
        return None

    async def after_model_callback(
        self, *, callback_context: CallbackContext, llm_response: LlmResponse
    ) -> LlmResponse | None:
        if llm_response.partial:
            return None
        key = f"{callback_context.invocation_id}:{callback_context.agent_name}"
        started = self._model_started.pop(key, None)
        usage = llm_response.usage_metadata
        calls = [p.function_call for p in (llm_response.content.parts if llm_response.content else []) if p.function_call]
        fields = {
            "event": "model_outcome",
            "agent": callback_context.agent_name,
            "invocation_id": callback_context.invocation_id,
            "duration_ms": round((time.perf_counter() - started) * 1000, 1) if started else None,
            "finish_reason": str(llm_response.finish_reason) if llm_response.finish_reason else None,
            "prompt_tokens": usage.prompt_token_count if usage else None,
            "output_tokens": usage.candidates_token_count if usage else None,
            "error_code": llm_response.error_code,
        }
        logger.info("model call finished", extra=fields)
        _span_event("model_outcome", fields)
        if calls:
            decision = {
                "event": "agent_decision",
                "agent": callback_context.agent_name,
                "invocation_id": callback_context.invocation_id,
                "intended_tools": [c.name for c in calls],
                "intended_args": redact_value([dict(c.args or {}) for c in calls]),
            }
            logger.info("agent decided to call tools", extra=decision)
            _span_event("agent_decision", {"intended_tools": ",".join(c.name or "" for c in calls)})
        return None

    async def on_model_error_callback(
        self, *, callback_context: CallbackContext, llm_request: LlmRequest, error: Exception
    ) -> LlmResponse | None:
        logger.error("model call failed", extra={
            "event": "model_error", "agent": callback_context.agent_name,
            "invocation_id": callback_context.invocation_id, "model": llm_request.model,
            "error_type": type(error).__name__,
        })
        return None

    # ---- tool calls ---------------------------------------------------------------
    async def before_tool_callback(
        self, *, tool: BaseTool, tool_args: dict[str, Any], tool_context: ToolContext
    ) -> dict[str, Any] | None:
        call_key = tool_context.function_call_id or f"{tool_context.invocation_id}:{tool.name}"
        self._tool_started[call_key] = time.perf_counter()
        fields = {
            "event": "tool_intent",
            "agent": tool_context.agent_name,
            "invocation_id": tool_context.invocation_id,
            "function_call_id": tool_context.function_call_id,
            "tool": tool.name,
            "tool_args": redact_value(dict(tool_args)),
        }
        logger.info("tool call intended", extra=fields)
        _span_event("tool_intent", {"tool": tool.name, "agent": tool_context.agent_name})
        return None

    async def after_tool_callback(
        self, *, tool: BaseTool, tool_args: dict[str, Any], tool_context: ToolContext, result: dict[str, Any]
    ) -> dict[str, Any] | None:
        call_key = tool_context.function_call_id or f"{tool_context.invocation_id}:{tool.name}"
        started = self._tool_started.pop(call_key, None)
        summary = summarize_tool_result(result)
        fields = {
            "event": "tool_outcome",
            "agent": tool_context.agent_name,
            "invocation_id": tool_context.invocation_id,
            "function_call_id": tool_context.function_call_id,
            "tool": tool.name,
            "duration_ms": round((time.perf_counter() - started) * 1000, 1) if started else None,
            **summary,
        }
        log = logger.warning if summary.get("status") in ("error", "blocked") else logger.info
        log("tool call finished", extra=fields)
        _span_event("tool_outcome", {"tool": tool.name, "status": summary.get("status")})
        return None

    async def on_tool_error_callback(
        self, *, tool: BaseTool, tool_args: dict[str, Any], tool_context: ToolContext, error: Exception
    ) -> dict[str, Any] | None:
        logger.error("tool raised an exception", extra={
            "event": "tool_exception", "tool": tool.name, "agent": tool_context.agent_name,
            "invocation_id": tool_context.invocation_id, "error_type": type(error).__name__,
        })
        return None
