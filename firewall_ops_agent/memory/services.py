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
"""Persistent session state and long-term memory with PII scrubbing.

* Sessions (conversation history + state such as cached inventories) are
  persisted in a database: SQLite locally, Cloud SQL (PostgreSQL) via
  SESSION_DB_URL, or Agent Runtime sessions when AGENT_ENGINE_ID is set
  (regional: AGENT_ENGINE_LOCATION, default us-central1).
* Long-term memory (what past audits found, engineer preferences) uses
  Vertex AI Memory Bank in production or ADK's persistent SqliteMemoryService
  locally, always wrapped by ``RedactingMemoryService`` so PII and secrets are
  scrubbed *before* anything is stored.
* ``BackgroundMemoryIngestionPlugin`` writes memories asynchronously after each
  turn so the user never waits for memory generation/consolidation.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Mapping, Sequence
from typing import Any

from google.adk.memory import BaseMemoryService
from google.adk.memory.base_memory_service import SearchMemoryResponse
from google.adk.plugins.base_plugin import BasePlugin

from ..config import Settings
from ..observability.redaction import redact_text, redact_text_with_dlp, redact_value

logger = logging.getLogger("firewall_ops_agent.memory")


async def _redact_text(text: str, dlp_project_id: str | None) -> str:
    if dlp_project_id:
        return await asyncio.to_thread(redact_text_with_dlp, text, dlp_project_id)
    return redact_text(text)


async def redact_event(event: Any, dlp_project_id: str | None = None) -> Any:
    """Returns a deep copy of an ADK event with PII/secrets scrubbed from every part."""
    copy = event.model_copy(deep=True)
    if copy.content and copy.content.parts:
        for part in copy.content.parts:
            if part.text:
                part.text = await _redact_text(part.text, dlp_project_id)
            if part.function_call is not None and part.function_call.args:
                part.function_call.args = redact_value(dict(part.function_call.args))
            if part.function_response is not None and part.function_response.response:
                part.function_response.response = redact_value(dict(part.function_response.response))
    return copy


class RedactingMemoryService(BaseMemoryService):
    """Decorator that scrubs PII/secrets from events before delegating storage."""

    def __init__(self, inner: BaseMemoryService, dlp_project_id: str | None = None) -> None:
        self._inner = inner
        self._dlp_project_id = dlp_project_id

    @property
    def inner(self) -> BaseMemoryService:
        """The wrapped memory service."""
        return self._inner

    async def _redact(self, text: str) -> str:
        return await _redact_text(text, self._dlp_project_id)

    async def _redact_event(self, event: Any) -> Any:
        return await redact_event(event, self._dlp_project_id)

    async def add_session_to_memory(self, session: Any) -> None:
        events = [await self._redact_event(e) for e in session.events]
        await self._inner.add_session_to_memory(session.model_copy(update={"events": events}))

    async def add_events_to_memory(
        self,
        *,
        app_name: str,
        user_id: str,
        events: Sequence[Any],
        session_id: str | None = None,
        custom_metadata: Mapping[str, object] | None = None,
    ) -> None:
        redacted = [await self._redact_event(e) for e in events]
        await self._inner.add_events_to_memory(app_name=app_name, user_id=user_id, events=redacted,
                                               session_id=session_id, custom_metadata=custom_metadata)

    async def add_memory(
        self,
        *,
        app_name: str,
        user_id: str,
        memories: Sequence[Any],
        custom_metadata: Mapping[str, object] | None = None,
    ) -> None:
        redacted = []
        for memory in memories:
            copy = memory.model_copy(deep=True)
            for part in (copy.content.parts if copy.content else None) or []:
                if part.text:
                    part.text = await self._redact(part.text)
            redacted.append(copy)
        await self._inner.add_memory(app_name=app_name, user_id=user_id, memories=redacted,
                                     custom_metadata=custom_metadata)

    async def search_memory(self, *, app_name: str, user_id: str, query: str) -> SearchMemoryResponse:
        return await self._inner.search_memory(app_name=app_name, user_id=user_id, query=query)

    async def delete_memory(self, *, app_name: str, user_id: str, memory_id: str | None = None) -> None:
        await self._inner.delete_memory(app_name=app_name, user_id=user_id, memory_id=memory_id)


def build_session_service(settings: Settings):
    """Persistent session service: Agent Engine sessions, or any SQLAlchemy database."""
    if settings.agent_engine_id:
        from google.adk.sessions import VertexAiSessionService

        return VertexAiSessionService(project=settings.google_cloud_project,
                                      location=settings.agent_engine_location,
                                      agent_engine_id=settings.agent_engine_id)
    from google.adk.sessions import DatabaseSessionService

    if settings.session_db_url.startswith("sqlite"):
        from pathlib import Path

        path = settings.session_db_url.split(":///", 1)[-1]
        if path and path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
    return DatabaseSessionService(db_url=settings.session_db_url)


def build_memory_service(settings: Settings) -> BaseMemoryService | None:
    """Long-term memory service, always wrapped with PII redaction."""
    inner: BaseMemoryService | None
    if settings.memory_backend == "none":
        return None
    if settings.memory_backend == "vertex_memory_bank" and settings.agent_engine_id:
        from google.adk.memory import VertexAiMemoryBankService

        inner = VertexAiMemoryBankService(project=settings.google_cloud_project,
                                          location=settings.agent_engine_location,
                                          agent_engine_id=settings.agent_engine_id)
    elif settings.memory_backend == "in_memory":
        from google.adk.memory import InMemoryMemoryService

        inner = InMemoryMemoryService()
    else:
        from google.adk.memory import SqliteMemoryService

        inner = SqliteMemoryService(db_path=settings.memory_db_path)
    dlp_project = settings.google_cloud_project if settings.enable_cloud_dlp else None
    return RedactingMemoryService(inner, dlp_project_id=dlp_project)


class BackgroundMemoryIngestionPlugin(BasePlugin):
    """Schedules memory generation after each run without blocking the response.

    * Non-blocking: memory extraction/consolidation (Memory Bank runs an LLM to
      distill facts) happens in a background task, so user latency is unaffected.
    * Incremental: only the events of the invocation that just finished are sent
      (``add_events_to_memory``), falling back to the whole session for services
      without delta support.
    * Private by construction: events are scrubbed before they leave the
      process, even when the host injects its own memory service (for example
      Agent Platform Memory Bank auto-configured by ``adk web``/Agent Runtime).
    """

    def __init__(self, dlp_project_id: str | None = None, name: str = "background_memory_ingestion") -> None:
        super().__init__(name)
        self._dlp_project_id = dlp_project_id
        self._tasks: set[asyncio.Task[None]] = set()

    async def after_run_callback(self, *, invocation_context: Any) -> None:
        memory_service = invocation_context.memory_service
        if memory_service is None:
            return
        session = invocation_context.session
        invocation_id = invocation_context.invocation_id
        events = [e for e in session.events if e.invocation_id == invocation_id] or list(session.events)
        task = asyncio.create_task(self._ingest(memory_service, session, events, invocation_id),
                                   name=f"memory-ingest-{invocation_id}")
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        logger.info("memory ingestion scheduled", extra={
            "event": "memory_ingestion_scheduled", "invocation_id": invocation_id,
            "session_id": session.id, "event_count": len(events)})

    async def _ingest(self, memory_service: Any, session: Any, events: list[Any], invocation_id: str) -> None:
        started = time.perf_counter()
        try:
            if not isinstance(memory_service, RedactingMemoryService):
                events = [await redact_event(e, self._dlp_project_id) for e in events]
            add_delta = getattr(memory_service, "add_events_to_memory", None)
            try:
                if add_delta is None:
                    raise NotImplementedError
                await add_delta(app_name=session.app_name, user_id=session.user_id,
                                session_id=session.id, events=events)
                mode = "incremental"
            except NotImplementedError:
                await memory_service.add_session_to_memory(session.model_copy(update={"events": events}))
                mode = "full_session"
            logger.info("memory ingestion finished", extra={
                "event": "memory_ingestion_done", "invocation_id": invocation_id, "mode": mode,
                "duration_ms": round((time.perf_counter() - started) * 1000, 1)})
        except Exception as exc:  # noqa: BLE001 - background work must never crash the app
            logger.warning("memory ingestion failed", extra={
                "event": "memory_ingestion_failed", "invocation_id": invocation_id, "error_type": type(exc).__name__})

    @property
    def pending(self) -> int:
        """Number of in-flight ingestion tasks."""
        return len(self._tasks)

    async def drain(self, timeout: float = 15.0) -> None:
        """Waits for in-flight ingestion tasks (call on shutdown)."""
        if self._tasks:
            await asyncio.wait(set(self._tasks), timeout=timeout)

    async def close(self) -> None:
        await self.drain()
