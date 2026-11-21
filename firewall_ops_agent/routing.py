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
"""Dynamic (per-request) model routing.

Static routing (``config.model_routing_table``) gives every agent the cheapest
model that does its job. Two ``before_model_callback`` functions add
per-request escalation from the fast model to the reasoning model:

* ``escalate_for_complex_questions`` (ops coach): complex intents such as
  diagnosis, hierarchy interactions or rule rewrites, very long requests, or a
  large audited inventory.
* ``escalate_for_large_inventories`` (report writer): only the size of the
  audited inventory matters. The writer always produces the same kind of
  report, so the wording of the user's question does not change how hard its
  job is.
"""

import logging
import re

from google.adk.agents.callback_context import CallbackContext
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse

from .config import get_settings
from .tools._common import inventory_state_key, last_scope_key

logger = logging.getLogger("firewall_ops_agent.routing")

_COMPLEX_INTENT = re.compile(
    r"\b(why|diagnos\w*|root cause|shadow\w*|overrid\w*|hierarch\w*|inherit\w*|rewrite|terraform|"
    r"least[- ]privilege|compare|trade-?offs?|design|migrat\w*|precedence|conflict\w*)\b",
    re.IGNORECASE,
)
_LONG_REQUEST_CHARS = 600


def needs_reasoning_model(user_text: str, inventory_size: int, threshold: int) -> tuple[bool, str]:
    """Decides whether a coaching request should be escalated (pure function, unit tested).

    Args:
      user_text: The user's message for this turn.
      inventory_size: Number of rules in the most recently audited scope.
      threshold: Inventory size above which the reasoning model is used.

    Returns:
      (escalate, reason) where reason is complex_intent, long_request,
      large_inventory or simple.
    """
    if _COMPLEX_INTENT.search(user_text or ""):
        return True, "complex_intent"
    if len(user_text or "") > _LONG_REQUEST_CHARS:
        return True, "long_request"
    if inventory_size > threshold:
        return True, "large_inventory"
    return False, "simple"


def _inventory_size(state) -> int:
    key = last_scope_key(state)
    return len(state.get(inventory_state_key(key)) or []) if key else 0


def _user_text(callback_context: CallbackContext) -> str:
    content = callback_context.user_content
    return " ".join(p.text for p in (content.parts if content and content.parts else []) if p.text)


def _route_to_reasoning_model(callback_context: CallbackContext, llm_request: LlmRequest, reason: str) -> None:
    settings = get_settings()
    llm_request.model = settings.reasoning_model
    logger.info("model routed", extra={"event": "model_routed", "agent": callback_context.agent_name,
                                       "from_model": settings.fast_model, "to_model": settings.reasoning_model,
                                       "reason": reason, "invocation_id": callback_context.invocation_id})


def escalate_for_complex_questions(
    callback_context: CallbackContext, llm_request: LlmRequest
) -> LlmResponse | None:
    """before_model_callback (ops coach): use the reasoning model for complex questions.

    Escalates when the question needs multi-step reasoning (why / diagnose /
    precedence / rewrite ...), is very long, or concerns a large inventory.
    Returns None so the (possibly upgraded) request continues normally.
    """
    settings = get_settings()
    if llm_request.model != settings.fast_model:
        return None
    escalate, reason = needs_reasoning_model(
        _user_text(callback_context), _inventory_size(callback_context.state), settings.complex_inventory_threshold)
    if escalate:
        _route_to_reasoning_model(callback_context, llm_request, reason)
    return None


def escalate_for_large_inventories(
    callback_context: CallbackContext, llm_request: LlmRequest
) -> LlmResponse | None:
    """before_model_callback (report writer): use the reasoning model only for large inventories.

    Returns None so the (possibly upgraded) request continues normally.
    """
    settings = get_settings()
    if llm_request.model != settings.fast_model:
        return None
    if _inventory_size(callback_context.state) > settings.complex_inventory_threshold:
        _route_to_reasoning_model(callback_context, llm_request, "large_inventory")
    return None
