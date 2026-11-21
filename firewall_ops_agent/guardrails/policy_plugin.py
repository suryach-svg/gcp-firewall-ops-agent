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
"""ADK plugins that enforce security policy across every agent in the app.

* ``SecurityGuardrailsPlugin``
    - Input redaction: secrets and personal data are scrubbed from the user's
      message before it is stored in the session or sent to any model.
    - Input guardrail: blocks prompt injection, secret exfiltration and
      destructive requests *before* any model call (no tokens spent).
    - Tool policy: per-invocation tool-call budget (loop protection), optional
      scope allowlist, and a hard ban on remediations that widen exposure.
    - Output guardrail: scrubs credentials from model responses.
* ``GuidedToolErrorReflectionPlugin``
    - Self-healing: when a tool returns a guided error (status="error"), the
      model gets structured reflection guidance (including the tool's own
      ``recovery_hint``) and a bounded number of retries.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any

from google.adk.agents.callback_context import CallbackContext
from google.adk.agents.invocation_context import InvocationContext
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.plugins.reflect_retry_tool_plugin import ReflectAndRetryToolPlugin, ToolReflectionContext
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.tool_context import ToolContext
from google.genai import types

from ..observability.redaction import redact_secrets, redact_user_input
from .input_guardrails import GuardrailVerdict, evaluate_user_input, invalid_ranges, widens_exposure

logger = logging.getLogger("firewall_ops_agent.guardrails")
_RANGE_ARGUMENTS = ("allowed_source_ranges", "new_source_ranges")


def _blocked(error_type: str, message: str, hint: str) -> dict[str, Any]:
    # status="blocked" (not "error") so the reflection plugin does not retry policy denials.
    return {"status": "blocked", "error_type": error_type, "message": message, "recovery_hint": hint}


def _user_text(content: types.Content | None) -> str:
    if content is None or not content.parts:
        return ""
    return " ".join(part.text for part in content.parts if part.text)


class SecurityGuardrailsPlugin(BasePlugin):
    """Input, tool-policy and output guardrails applied to all agents."""

    def __init__(
        self,
        max_tool_calls_per_invocation: int = 30,
        allowed_scope_ids: tuple[str, ...] = (),
        name: str = "security_guardrails",
    ) -> None:
        super().__init__(name)
        self._max_tool_calls = max_tool_calls_per_invocation
        self._allowed_scope_ids = set(allowed_scope_ids)
        self._verdicts: dict[str, GuardrailVerdict] = {}
        self._tool_calls: Counter[str] = Counter()

    async def on_user_message_callback(
        self, *, invocation_context: InvocationContext, user_message: types.Content
    ) -> types.Content | None:
        """Redacts secrets and personal data before the message is stored or sent to a model.

        Only text parts are rewritten; function responses (e.g. a human's
        approval of a staged change) pass through untouched.
        """
        if user_message is None or not user_message.parts:
            return None
        parts: list[types.Part] = []
        changed = False
        for part in user_message.parts:
            if part.text and not part.thought:
                clean = redact_user_input(part.text)
                if clean != part.text:
                    part = part.model_copy(update={"text": clean})
                    changed = True
            parts.append(part)
        if not changed:
            return None
        logger.warning("sensitive data removed from user input", extra={
            "event": "user_input_redacted", "invocation_id": invocation_context.invocation_id})
        return user_message.model_copy(update={"parts": parts})

    async def before_model_callback(
        self, *, callback_context: CallbackContext, llm_request: LlmRequest
    ) -> LlmResponse | None:
        invocation_id = callback_context.invocation_id
        verdict = self._verdicts.get(invocation_id)
        if verdict is None:
            verdict = evaluate_user_input(_user_text(callback_context.user_content))
            self._verdicts[invocation_id] = verdict
            if len(self._verdicts) > 1000:  # bound memory in long-running servers
                self._verdicts.pop(next(iter(self._verdicts)))
            if not verdict.allowed:
                logger.warning("user input blocked by guardrail", extra={
                    "event": "guardrail_blocked", "category": verdict.category,
                    "agent": callback_context.agent_name, "invocation_id": invocation_id,
                })
        if verdict.allowed:
            return None
        return LlmResponse(content=types.Content(role="model", parts=[types.Part(text=verdict.refusal)]))

    async def before_tool_callback(
        self, *, tool: BaseTool, tool_args: dict[str, Any], tool_context: ToolContext
    ) -> dict[str, Any] | None:
        invocation_id = tool_context.invocation_id
        self._tool_calls[invocation_id] += 1
        if self._tool_calls[invocation_id] > self._max_tool_calls:
            logger.warning("tool budget exceeded", extra={"event": "policy_blocked", "policy": "tool_budget",
                                                          "tool": tool.name, "invocation_id": invocation_id})
            return _blocked("tool_budget_exceeded",
                            f"More than {self._max_tool_calls} tool calls in one request.",
                            "Stop calling tools and summarize what you have so far for the user.")

        scope_id = tool_args.get("scope_id")
        if self._allowed_scope_ids and scope_id and str(scope_id).split("/")[-1] not in self._allowed_scope_ids:
            logger.warning("scope outside allowlist", extra={"event": "policy_blocked", "policy": "scope_allowlist",
                                                             "tool": tool.name, "scope_id": scope_id})
            return _blocked("scope_not_allowed",
                            f"Scope '{scope_id}' is not in this deployment's allowlist.",
                            f"Ask the user to choose one of: {', '.join(sorted(self._allowed_scope_ids))}.")

        for argument in _RANGE_ARGUMENTS:
            ranges = tool_args.get(argument)
            if not ranges:
                continue
            if isinstance(ranges, str):
                ranges = [ranges]
            wide = widens_exposure(ranges)
            if wide:
                logger.warning("remediation would widen exposure", extra={
                    "event": "policy_blocked", "policy": "no_internet_wide_sources", "tool": tool.name})
                return _blocked("widens_exposure",
                                f"Source ranges {wide} would expose the rule to the entire internet.",
                                "Ask the engineer for the specific client CIDR ranges that need access "
                                "(for admin access use the IAP range 35.235.240.0/20).")
            bad = invalid_ranges(ranges)
            if bad:
                return _blocked("invalid_cidr", f"Not valid CIDR notation: {bad}.",
                                "Use CIDR notation such as 10.10.0.0/24 or 203.0.113.0/24.")
        return None

    async def after_run_callback(self, *, invocation_context) -> None:  # type: ignore[override]
        self._tool_calls.pop(invocation_context.invocation_id, None)
        self._verdicts.pop(invocation_context.invocation_id, None)

    async def after_model_callback(
        self, *, callback_context: CallbackContext, llm_response: LlmResponse
    ) -> LlmResponse | None:
        if not llm_response.content or not llm_response.content.parts:
            return None
        changed = False
        for part in llm_response.content.parts:
            if part.text and not part.thought:
                scrubbed = redact_secrets(part.text)
                if scrubbed != part.text:
                    part.text = scrubbed
                    changed = True
        if changed:
            logger.warning("secret removed from model output", extra={
                "event": "output_redacted", "agent": callback_context.agent_name,
                "invocation_id": callback_context.invocation_id})
            return llm_response
        return None


def _reflection_guidance(ctx: ToolReflectionContext) -> str:
    hint = ctx.error.get("recovery_hint") if isinstance(ctx.error, dict) else None
    message = ctx.error.get("message") if isinstance(ctx.error, dict) else ctx.error_details
    return (
        f"The tool '{ctx.tool_name}' failed (attempt {ctx.retry_count} of {ctx.max_retries}): {message}. "
        + (f"Recovery hint from the tool: {hint} " if hint else ctx.default_guidance + " ")
        + "Correct the arguments and call the tool again, or ask the user for the missing information."
    )


def _retry_exceeded_guidance(ctx: ToolReflectionContext) -> str:
    return (
        f"The tool '{ctx.tool_name}' kept failing after {ctx.max_retries} retries ({ctx.error_details}). "
        "Do not call it again in this turn. Explain the problem and the recovery hint to the user."
    )


class GuidedToolErrorReflectionPlugin(ReflectAndRetryToolPlugin):
    """Reflect-and-retry on the agent's guided tool errors (status == 'error')."""

    def __init__(self, max_retries: int = 2) -> None:
        super().__init__(
            name="guided_tool_error_reflection",
            max_retries=max_retries,
            throw_exception_if_retry_exceeded=False,
            reflection_guidance=_reflection_guidance,
            retry_exceeded_guidance=_retry_exceeded_guidance,
        )

    async def extract_error_from_result(
        self, *, tool: BaseTool, tool_args: dict[str, Any], tool_context: ToolContext, result: Any
    ) -> dict[str, Any] | None:
        if isinstance(result, dict) and result.get("status") == "error":
            return result
        return None
