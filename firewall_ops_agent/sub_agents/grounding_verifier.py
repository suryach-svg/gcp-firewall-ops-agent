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
"""Custom (non-LLM) agent that self-evaluates the audit report before the user relies on it."""

from collections.abc import AsyncGenerator

from google.adk.agents import BaseAgent
from google.adk.agents.invocation_context import InvocationContext
from google.adk.events import Event, EventActions
from google.genai import types

from ..core.grounding import identifiers_from_inventory, verify_report_grounding
from ..tools._common import inventory_state_key, last_scope_key, report_for_key


class ReportGroundingVerifier(BaseAgent):
    """Final pipeline step: deterministic hallucination and coverage check of the report.

    It compares the report written by the LLM with the inventory and the risk
    engine output stored in session state, then appends a verdict to the
    conversation and records it in state under ``grounding_verification``.
    """

    async def _run_async_impl(self, ctx: InvocationContext) -> AsyncGenerator[Event, None]:
        state = ctx.session.state
        key = last_scope_key(state)
        inventory = (state.get(inventory_state_key(key)) or []) if key else []
        verdict = verify_report_grounding(
            state.get("final_report") or "",
            {item["name"] for item in inventory},
            report_for_key(state, key),
            identifiers_from_inventory(inventory),
        )
        yield Event(
            invocation_id=ctx.invocation_id,
            author=self.name,
            branch=ctx.branch,
            content=types.Content(role="model", parts=[types.Part(text=verdict.to_markdown())]),
            actions=EventActions(state_delta={"grounding_verification": verdict.to_dict()}),
        )
