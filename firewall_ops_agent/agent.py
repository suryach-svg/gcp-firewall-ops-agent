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
"""GCP Firewall Ops Agent - entry point discovered by ``adk web`` / ``adk run`` / ``adk deploy``.

Architecture (Coordinator + Sequential pipeline + custom verifier agent):

    firewall_ops_coordinator (LlmAgent, fast model)  -- LLM-driven delegation
    |-- firewall_audit_pipeline (SequentialAgent)
    |   |-- rule_collector_agent      (fast model)      list_firewall_rules_for_scope
    |   |-- risk_analyst_agent        (reasoning model, falls back to fast)
    |   |                             analyze_firewall_rule_risks, search_firewall_best_practices
    |   |-- report_writer_agent       (fast model, escalates for large inventories)
    |   `-- report_grounding_verifier (deterministic self-evaluation, no LLM)
    `-- firewall_ops_coach (LlmAgent, fast model, escalates for complex questions)
        get_firewall_rule_details, explain_firewall_risk_check, search_firewall_best_practices,
        propose_least_privilege_rule, apply_firewall_remediation (human approval), load_memory

App-level capabilities: AgentOps intent/outcome logging, security guardrails,
reflect-and-retry on guided tool errors, background memory ingestion, event
compaction (sliding window + token threshold) and context caching.
"""

from google.adk.agents import LlmAgent
from google.adk.agents.context_cache_config import ContextCacheConfig
from google.adk.apps import App
from google.adk.apps.app import EventsCompactionConfig
from google.adk.apps.llm_event_summarizer import LlmEventSummarizer
from google.adk.models import BaseLlm, Gemini

from .config import TaskProfile, configure_model_credentials, get_settings, model_for
from .guardrails.policy_plugin import GuidedToolErrorReflectionPlugin, SecurityGuardrailsPlugin
from .memory.services import BackgroundMemoryIngestionPlugin
from .observability.agentops_plugin import AgentOpsObservabilityPlugin
from .observability.logging_config import configure_logging
from .observability.tracing import apply_privacy_defaults, configure_tracing
from .prompts import COORDINATOR_INSTRUCTION
from .sub_agents.audit_pipeline import build_audit_pipeline
from .sub_agents.ops_coach import build_ops_coach

APP_NAME = "firewall_ops_agent"

settings = get_settings()
apply_privacy_defaults()  # keep raw prompts/responses out of trace spans (ADK reads the flag per invocation)
configure_logging(settings.log_level, settings.log_format, settings.google_cloud_project)
configure_tracing(settings.enable_cloud_trace, settings.enable_console_trace)
configure_model_credentials()


def build_root_agent() -> LlmAgent:
    """Builds the coordinator and its specialist sub-agents."""
    return LlmAgent(
        name="firewall_ops_coordinator",
        description="Front door for GCP firewall audits and coaching; delegates to the right specialist.",
        model=model_for(TaskProfile.ROUTING),
        instruction=COORDINATOR_INSTRUCTION,
        sub_agents=[build_audit_pipeline(), build_ops_coach()],
    )


def build_app(root: LlmAgent | None = None, summarizer_llm: BaseLlm | None = None) -> App:
    """Wraps the agent tree with plugins, history compaction and context caching.

    Args:
      root: Optional pre-built root agent (tests inject agents with a fake model).
      summarizer_llm: Optional model for history compaction (defaults to the lite model).
    """
    return App(
        name=APP_NAME,
        root_agent=root or build_root_agent(),
        plugins=[
            AgentOpsObservabilityPlugin(),  # first: always records intent/outcome
            SecurityGuardrailsPlugin(
                max_tool_calls_per_invocation=settings.max_tool_calls_per_invocation,
                allowed_scope_ids=settings.allowed_scope_ids,
            ),
            GuidedToolErrorReflectionPlugin(max_retries=2),
            BackgroundMemoryIngestionPlugin(
                dlp_project_id=settings.google_cloud_project if settings.enable_cloud_dlp else None
            ),
        ],
        # History compaction: summarize older turns with a cheap model, triggered both by a sliding
        # window of invocations and by prompt size, while keeping the most recent events verbatim.
        events_compaction_config=EventsCompactionConfig(
            summarizer=LlmEventSummarizer(
                llm=summarizer_llm or Gemini(model=model_for(TaskProfile.SUMMARIZATION))
            ),
            compaction_interval=settings.compaction_interval,
            overlap_size=1,
            token_threshold=settings.compaction_token_threshold,
            event_retention_size=10,
        ),
        # Reuse the large, stable prefix (instructions + tool schemas) across turns on Gemini 3 models.
        context_cache_config=ContextCacheConfig(min_tokens=4096, ttl_seconds=1800, cache_intervals=10),
    )


root_agent = build_root_agent()
app = build_app(root_agent)
