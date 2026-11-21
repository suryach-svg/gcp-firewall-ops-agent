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
"""Interactive terminal chat with persistent sessions, long-term memory and human approvals.

Unlike ``adk run``, this runner wires in the project's own session and memory
services (SQLite locally, Agent Engine sessions + Memory Bank when
AGENT_ENGINE_ID is set) and asks a human to approve every firewall change.

Usage:
  python -m scripts.chat_cli                      # new session
  python -m scripts.chat_cli --session <id>       # resume a persisted session
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from google.adk.runners import Runner  # noqa: E402
from google.genai import types  # noqa: E402

from firewall_ops_agent.agent import APP_NAME, app  # noqa: E402
from firewall_ops_agent.config import get_settings  # noqa: E402
from firewall_ops_agent.memory.services import (  # noqa: E402
    BackgroundMemoryIngestionPlugin,
    build_memory_service,
    build_session_service,
)

APPROVAL_CALL = "adk_request_confirmation"


def _approval_response(call: types.FunctionCall) -> types.Content:
    confirmation = (call.args or {}).get("toolConfirmation", {})
    print("\n" + "=" * 72 + "\nHUMAN APPROVAL REQUIRED\n" + "=" * 72)
    print(confirmation.get("hint", "The agent wants to change a firewall rule."))
    approved = input("\nApprove this change? [y/N] ").strip().lower() == "y"
    ticket = input("Change ticket ID (required for live changes): ").strip() if approved else ""
    return types.Content(role="user", parts=[types.Part(function_response=types.FunctionResponse(
        id=call.id, name=APPROVAL_CALL, response={"confirmed": approved, "payload": {"change_ticket": ticket}}))])


async def chat(user_id: str, session_id: str | None) -> None:
    settings = get_settings()
    session_service = build_session_service(settings)
    runner = Runner(app=app, session_service=session_service, memory_service=build_memory_service(settings))
    if session_id:
        session = await session_service.get_session(app_name=APP_NAME, user_id=user_id, session_id=session_id)
        if session is None:
            raise SystemExit(f"Session {session_id} not found for user {user_id}.")
    else:
        session = await session_service.create_session(app_name=APP_NAME, user_id=user_id)
    print(f"GCP Firewall Ops Agent | data mode: {settings.firewall_data_mode} | session: {session.id}")
    print("Try: 'Audit project prod-payments-app including inherited policies'. Type 'exit' to quit.\n")

    while True:
        try:
            text = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if text.lower() in {"exit", "quit"}:
            break
        if not text:
            continue
        message: types.Content | None = types.Content(role="user", parts=[types.Part(text=text)])
        while message is not None:
            approval_call = None
            async for event in runner.run_async(user_id=user_id, session_id=session.id, new_message=message):
                for call in event.get_function_calls():
                    if call.name == APPROVAL_CALL:
                        approval_call = call
                for part in (event.content.parts if event.content and event.content.parts else []):
                    if part.text and not part.thought:
                        print(f"\n[{event.author}]\n{part.text}\n")
            message = _approval_response(approval_call) if approval_call else None

    for plugin in app.plugins:
        if isinstance(plugin, BackgroundMemoryIngestionPlugin):
            await plugin.drain()
    print(f"Bye. Resume later with: python -m scripts.chat_cli --session {session.id}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--user", default="ops-engineer", help="User ID for session and memory scoping.")
    parser.add_argument("--session", default=None, help="Existing session ID to resume.")
    args = parser.parse_args()
    asyncio.run(chat(args.user, args.session))
