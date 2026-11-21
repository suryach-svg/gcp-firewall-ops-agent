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
"""Tests for memory services, background ingestion and the agent/app wiring."""

import asyncio
import os
import re
import time
from pathlib import Path
from types import SimpleNamespace

from google.adk.agents import LlmAgent, SequentialAgent
from google.adk.events import Event
from google.adk.memory import InMemoryMemoryService, SqliteMemoryService
from google.adk.models import FallbackModel
from google.adk.sessions import DatabaseSessionService, Session
from google.genai import types

from firewall_ops_agent.agent import app, root_agent
from firewall_ops_agent.config import Settings, get_settings
from firewall_ops_agent.memory.services import (
    BackgroundMemoryIngestionPlugin,
    RedactingMemoryService,
    build_memory_service,
    build_session_service,
)
from firewall_ops_agent.sub_agents.grounding_verifier import ReportGroundingVerifier

REPO = Path(__file__).resolve().parent.parent


def _session(text: str) -> Session:
    event = Event(author="user", invocation_id="inv-1",
                  content=types.Content(role="user", parts=[types.Part(text=text)]))
    return Session(id="s-1", app_name="firewall_ops_agent", user_id="u-1", events=[event])


async def test_redacting_memory_service_scrubs_before_persistent_storage(tmp_path):
    inner = SqliteMemoryService(db_path=tmp_path / "memory.db")
    memory = RedactingMemoryService(inner)
    await memory.add_session_to_memory(_session("Audit notes for prod: email jane.doe@example.com, call 415-555-0100"))
    result = await memory.search_memory(app_name="firewall_ops_agent", user_id="u-1", query="audit notes")
    stored = " ".join(p.text or "" for m in result.memories for p in m.content.parts or [])
    assert "Audit notes" in stored
    assert "jane.doe@example.com" not in stored and "415-555-0100" not in stored


async def test_background_ingestion_does_not_block_the_response():
    class SlowMemory:
        def __init__(self):
            self.ingested = 0

        async def add_session_to_memory(self, session):
            await asyncio.sleep(0.3)
            self.ingested += 1

    memory = SlowMemory()
    plugin = BackgroundMemoryIngestionPlugin()
    ctx = SimpleNamespace(memory_service=memory, session=_session("hello"), invocation_id="inv-9")
    started = time.perf_counter()
    await plugin.after_run_callback(invocation_context=ctx)
    assert time.perf_counter() - started < 0.1, "scheduling must return immediately"
    assert plugin.pending == 1 and memory.ingested == 0
    await plugin.drain()
    assert memory.ingested == 1 and plugin.pending == 0


async def test_background_ingestion_redacts_even_for_host_provided_memory_service():
    """Agent Runtime / adk web may inject Memory Bank directly; PII must still be scrubbed."""
    host_memory = InMemoryMemoryService()  # deliberately NOT wrapped in RedactingMemoryService
    plugin = BackgroundMemoryIngestionPlugin()
    ctx = SimpleNamespace(memory_service=host_memory, invocation_id="inv-1",
                          session=_session("my email is jane.doe@example.com, audit prod please"))
    await plugin.after_run_callback(invocation_context=ctx)
    await plugin.drain()
    result = await host_memory.search_memory(app_name="firewall_ops_agent", user_id="u-1", query="email")
    stored = " ".join(p.text or "" for m in result.memories for p in m.content.parts or [])
    assert "[REDACTED_EMAIL]" in stored and "jane.doe@example.com" not in stored


def test_service_factories(tmp_path):
    base = get_settings()
    settings = Settings(**{**base.__dict__, "session_db_url": f"sqlite+aiosqlite:///{tmp_path}/s.db",
                           "memory_backend": "sqlite", "memory_db_path": str(tmp_path / "m.db")})
    assert isinstance(build_session_service(settings), DatabaseSessionService)
    memory = build_memory_service(settings)
    assert isinstance(memory, RedactingMemoryService) and isinstance(memory.inner, SqliteMemoryService)
    assert build_memory_service(Settings(**{**settings.__dict__, "memory_backend": "none"})) is None


def test_agent_runtime_services_use_the_regional_location():
    """Models use the global endpoint, but Agent Runtime sessions and Memory Bank are regional."""
    settings = Settings(**{**get_settings().__dict__, "google_cloud_project": "demo-proj",
                           "google_cloud_location": "global", "agent_engine_id": "1234567890",
                           "agent_engine_location": "europe-west4", "memory_backend": "vertex_memory_bank"})
    sessions = build_session_service(settings)
    memory = build_memory_service(settings)
    assert type(sessions).__name__ == "VertexAiSessionService" and sessions._location == "europe-west4"
    assert type(memory.inner).__name__ == "VertexAiMemoryBankService" and memory.inner._location == "europe-west4"


def test_agent_tree_uses_coordinator_and_sequential_patterns():
    assert root_agent.name == "firewall_ops_coordinator"
    pipeline, coach = root_agent.sub_agents
    assert isinstance(pipeline, SequentialAgent) and isinstance(coach, LlmAgent)
    assert [a.name for a in pipeline.sub_agents] == [
        "rule_collector_agent", "risk_analyst_agent", "report_writer_agent", "report_grounding_verifier"]
    assert isinstance(pipeline.sub_agents[-1], ReportGroundingVerifier)
    assert [a.output_key for a in pipeline.sub_agents[:3]] == ["collection_summary", "risk_analysis", "final_report"]


def test_strategic_model_routing():
    settings = get_settings()
    pipeline, coach = root_agent.sub_agents
    collector, analyst, writer, _ = pipeline.sub_agents
    assert root_agent.model == collector.model == writer.model == coach.model == settings.fast_model
    assert isinstance(analyst.model, FallbackModel)
    assert analyst.model.models[0] == settings.reasoning_model


def test_tools_are_scoped_per_agent():
    pipeline, coach = root_agent.sub_agents
    names = lambda agent: {getattr(t, "__name__", getattr(t, "name", "")) for t in agent.tools}  # noqa: E731
    assert names(pipeline.sub_agents[0]) == {"list_firewall_rules_for_scope"}
    assert names(pipeline.sub_agents[1]) == {"analyze_firewall_rule_risks", "search_firewall_best_practices"}
    assert {"apply_firewall_remediation", "propose_least_privilege_rule", "load_memory"} <= names(coach)
    assert not root_agent.tools, "the coordinator only delegates"


def test_app_plugins_compaction_and_caching():
    assert [p.name for p in app.plugins] == [
        "agentops_observability", "security_guardrails", "guided_tool_error_reflection", "background_memory_ingestion"]
    compaction = app.events_compaction_config
    assert compaction.compaction_interval and compaction.token_threshold and compaction.summarizer is not None
    assert app.context_cache_config.min_tokens == 4096


def test_every_llm_agent_has_a_constitution():
    def llm_agents(agent):
        if isinstance(agent, LlmAgent):
            yield agent
        for child in agent.sub_agents:
            yield from llm_agents(child)
    for agent in llm_agents(root_agent):
        assert "Non-negotiable rules" in agent.instruction, agent.name


def test_repository_contains_no_hardcoded_secrets():
    secret = re.compile(r"AIza[0-9A-Za-z_\-]{35}|-----BEGIN [A-Z ]*PRIVATE KEY-----\n[A-Za-z0-9+/]|ya29\.[0-9A-Za-z_\-]{20,}")
    skipped_dirs = {".venv", ".git", ".adk_data", ".ruff_cache", ".pytest_cache", "__pycache__", "artifacts"}
    suffixes = {".py", ".json", ".tf", ".md", ".yml", ".yaml", ".toml", ".txt", ".example", ".cfg"}
    offenders = []
    for root, dirs, files in os.walk(REPO):
        dirs[:] = [d for d in dirs if d not in skipped_dirs]
        for name in files:
            path = Path(root) / name
            if path.suffix in suffixes and secret.search(path.read_text(encoding="utf-8", errors="ignore")):
                offenders.append(str(path.relative_to(REPO)))
    assert not offenders, f"possible hardcoded secrets in: {offenders}"
    assert ".env" in (REPO / ".gitignore").read_text().split()
