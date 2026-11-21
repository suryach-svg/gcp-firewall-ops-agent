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
"""Runtime configuration, strategic model routing and secure secret loading.

All configuration comes from environment variables (optionally loaded from a
local ``.env`` file that is git-ignored). No credentials are ever hardcoded:
on Google Cloud the agent authenticates with Application Default Credentials
(a service account), and the only optional secret (a Gemini API key for
non-Vertex development) is read from Secret Manager at startup.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from typing import Literal

logger = logging.getLogger(__name__)

# Long-term GA models on Gemini Enterprise Agent Platform (Nov 2026). The
# Gemini 2.5 family was retired on 2026-10-20, so do not default to it.
# Sampling: agents keep the models' default temperature (1.0). Google recommends
# not lowering it for Gemini 3+ models (it can cause looping or weaker
# reasoning); consistency comes from the deterministic risk engine instead.
DEFAULT_FAST_MODEL = "gemini-3.8-flash"
DEFAULT_REASONING_MODEL = "gemini-4-argon"
DEFAULT_LITE_MODEL = "gemini-3.5-flash-lite"


class TaskProfile(str, Enum):
    """Kinds of LLM work in this system, used for strategic model routing."""

    ROUTING = "routing"                # intent detection + delegation
    COLLECTION = "collection"          # extract scope, call one tool, summarize
    RISK_REASONING = "risk_reasoning"  # prioritize, reason about hierarchy interactions
    REPORT_WRITING = "report_writing"  # format a grounded report
    COACHING = "coaching"              # interactive Q&A; escalates when complex
    SUMMARIZATION = "summarization"    # background history compaction


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        logger.warning("Invalid integer for %s; using default %s", name, default)
        return default


@dataclass(frozen=True)
class Settings:
    """Immutable runtime settings resolved from the environment."""

    google_cloud_project: str | None
    google_cloud_location: str
    use_enterprise_backend: bool
    fast_model: str
    reasoning_model: str
    lite_model: str
    firewall_data_mode: Literal["sample", "live"]
    enable_live_remediation: bool
    session_db_url: str
    memory_backend: Literal["sqlite", "vertex_memory_bank", "in_memory", "none"]
    memory_db_path: str
    agent_engine_id: str | None
    agent_engine_location: str
    enable_cloud_trace: bool
    enable_console_trace: bool
    enable_cloud_dlp: bool
    log_level: str
    log_format: Literal["json", "text"]
    complex_inventory_threshold: int
    max_rules_in_tool_response: int
    max_tool_calls_per_invocation: int
    allowed_scope_ids: tuple[str, ...]
    compaction_interval: int
    compaction_token_threshold: int

    @property
    def model_routing_table(self) -> dict[TaskProfile, str]:
        """Static routing table: the cheapest model that does each job well."""
        return {
            TaskProfile.ROUTING: self.fast_model,
            TaskProfile.COLLECTION: self.fast_model,
            TaskProfile.RISK_REASONING: self.reasoning_model,
            TaskProfile.REPORT_WRITING: self.fast_model,
            TaskProfile.COACHING: self.fast_model,
            TaskProfile.SUMMARIZATION: self.lite_model,
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Reads settings once per process (call ``get_settings.cache_clear()`` in tests)."""
    try:
        from dotenv import load_dotenv

        load_dotenv(override=False)
    except ImportError:  # pragma: no cover - python-dotenv ships with google-adk
        pass

    data_mode = os.environ.get("FIREWALL_DATA_MODE", "sample").strip().lower()
    if data_mode not in ("sample", "live"):
        logger.warning("Unknown FIREWALL_DATA_MODE=%s; falling back to 'sample'", data_mode)
        data_mode = "sample"
    memory_backend = os.environ.get("MEMORY_BACKEND", "sqlite").strip().lower()
    if memory_backend not in ("sqlite", "vertex_memory_bank", "in_memory", "none"):
        memory_backend = "sqlite"
    allowed = tuple(s.strip() for s in os.environ.get("ALLOWED_SCOPE_IDS", "").split(",") if s.strip())
    log_format = os.environ.get("LOG_FORMAT", "json").strip().lower()

    return Settings(
        google_cloud_project=os.environ.get("GOOGLE_CLOUD_PROJECT") or None,
        google_cloud_location=os.environ.get("GOOGLE_CLOUD_LOCATION", "global"),
        use_enterprise_backend=_env_bool("GOOGLE_GENAI_USE_ENTERPRISE", _env_bool("GOOGLE_GENAI_USE_VERTEXAI", False)),
        fast_model=os.environ.get("FAST_MODEL", DEFAULT_FAST_MODEL),
        reasoning_model=os.environ.get("REASONING_MODEL", DEFAULT_REASONING_MODEL),
        lite_model=os.environ.get("LITE_MODEL", DEFAULT_LITE_MODEL),
        firewall_data_mode=data_mode,  # type: ignore[arg-type]
        enable_live_remediation=_env_bool("ENABLE_LIVE_REMEDIATION", False),
        session_db_url=os.environ.get("SESSION_DB_URL", "sqlite+aiosqlite:///./.adk_data/sessions.db"),
        memory_backend=memory_backend,  # type: ignore[arg-type]
        memory_db_path=os.environ.get("MEMORY_DB_PATH", "./.adk_data/memory.db"),
        agent_engine_id=os.environ.get("AGENT_ENGINE_ID") or None,
        # Agent Runtime (sessions, Memory Bank) is regional, while Gemini models default to "global".
        agent_engine_location=os.environ.get("AGENT_ENGINE_LOCATION", "us-central1"),
        enable_cloud_trace=_env_bool("ENABLE_CLOUD_TRACE", False),
        enable_console_trace=_env_bool("ENABLE_CONSOLE_TRACE", False),
        enable_cloud_dlp=_env_bool("ENABLE_CLOUD_DLP", False),
        log_level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        log_format="text" if log_format == "text" else "json",
        complex_inventory_threshold=_env_int("COMPLEX_INVENTORY_THRESHOLD", 15),
        max_rules_in_tool_response=_env_int("MAX_RULES_IN_TOOL_RESPONSE", 40),
        max_tool_calls_per_invocation=_env_int("MAX_TOOL_CALLS_PER_INVOCATION", 30),
        allowed_scope_ids=allowed,
        compaction_interval=_env_int("COMPACTION_INTERVAL", 4),
        compaction_token_threshold=_env_int("COMPACTION_TOKEN_THRESHOLD", 60000),
    )


def model_for(task: TaskProfile) -> str:
    """Returns the model name routed to ``task``."""
    return get_settings().model_routing_table[task]


def resilient_model(task: TaskProfile):
    """Model for ``task`` that fails over to the fast model on 429/5xx errors.

    Uses ADK's FallbackModel so a capacity spike on the reasoning model never
    blocks an audit; the fast model takes over for that turn.
    """
    from google.adk.models import FallbackModel

    primary = model_for(task)
    fallback = get_settings().fast_model
    if primary == fallback:
        return primary
    return FallbackModel(models=[primary, fallback])


def load_secret(secret_resource: str) -> str:
    """Reads a secret version from Google Secret Manager.

    Args:
      secret_resource: Full resource name, e.g.
        'projects/my-proj/secrets/gemini-api-key/versions/latest'.

    Returns:
      The secret payload as text. The value is never logged.
    """
    from google.cloud import secretmanager

    client = secretmanager.SecretManagerServiceClient()
    response = client.access_secret_version(name=secret_resource)
    return response.payload.data.decode("utf-8")


def configure_model_credentials() -> None:
    """Ensures the Gemini client can authenticate without hardcoded keys.

    * Enterprise/Vertex backend (recommended): uses Application Default
      Credentials; nothing to load.
    * Developer API key: if GOOGLE_API_KEY is not already set and
      GOOGLE_API_KEY_SECRET names a Secret Manager secret version, the key is
      fetched at startup and kept only in process memory.
    """
    settings = get_settings()
    if settings.use_enterprise_backend or os.environ.get("GOOGLE_API_KEY"):
        return
    secret_resource = os.environ.get("GOOGLE_API_KEY_SECRET")
    if not secret_resource:
        return
    try:
        os.environ["GOOGLE_API_KEY"] = load_secret(secret_resource)
        logger.info("Loaded Gemini API key from Secret Manager", extra={"event": "secret_loaded"})
    except Exception as exc:  # noqa: BLE001 - startup must not crash on a missing optional secret
        logger.warning("Could not load GOOGLE_API_KEY_SECRET: %s", type(exc).__name__)
