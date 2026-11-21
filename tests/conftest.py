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
"""Shared pytest fixtures. Tests run fully offline against the sample inventory."""

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

# Configure the environment BEFORE the agent package is imported anywhere.
os.environ["FIREWALL_DATA_MODE"] = "sample"
os.environ["ENABLE_LIVE_REMEDIATION"] = "false"
os.environ["ENABLE_CLOUD_TRACE"] = "false"
os.environ["ENABLE_CLOUD_DLP"] = "false"
os.environ["MEMORY_BACKEND"] = "in_memory"
os.environ["LOG_LEVEL"] = "WARNING"
if os.environ.get("RUN_LIVE_EVAL") != "1":
    # Offline runs never call a model. Live runs keep the backend from the shell or firewall_ops_agent/.env.
    os.environ.setdefault("GOOGLE_GENAI_USE_ENTERPRISE", "false")
os.environ.pop("ALLOWED_SCOPE_IDS", None)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


class FakeToolContext:
    """Minimal stand-in for ADK's ToolContext used by unit tests of tool functions."""

    def __init__(self, state: dict | None = None, confirmation=None) -> None:
        self.state = state if state is not None else {}
        self.tool_confirmation = confirmation
        self.actions = SimpleNamespace(skip_summarization=False)
        self.confirmation_requests: list[dict] = []
        self.invocation_id = "inv-test"
        self.agent_name = "test_agent"
        self.function_call_id = "fc-test"

    def request_confirmation(self, *, hint=None, payload=None) -> None:
        self.confirmation_requests.append({"hint": hint, "payload": payload})


@pytest.fixture
def tool_context() -> FakeToolContext:
    """A fresh fake ToolContext with empty session state."""
    return FakeToolContext()
