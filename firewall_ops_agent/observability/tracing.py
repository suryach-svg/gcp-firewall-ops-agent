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
"""OpenTelemetry distributed tracing.

ADK already emits OpenTelemetry spans for every invocation, agent run, model
call and tool call. This module (1) wires those spans to an exporter (Cloud
Trace via ADK's GCP exporters, and/or the console for local debugging) and
(2) provides ``traced_operation`` for custom child spans inside our tools, so
one trace shows: user query -> agent -> tool -> Compute API call -> answer.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from .redaction import redact_text

logger = logging.getLogger(__name__)
TRACER_NAME = "firewall_ops_agent"
CAPTURE_CONTENT_ENV = "ADK_CAPTURE_MESSAGE_CONTENT_IN_SPANS"
_configured = False


def apply_privacy_defaults() -> None:
    """Keeps full prompts and model responses out of trace spans unless an operator opts in.

    ADK copies whole model requests/responses into span attributes by default
    (``ADK_CAPTURE_MESSAGE_CONTENT_IN_SPANS=true``). Conversations can contain
    personal data, so this agent defaults the flag to ``false``; spans still
    carry timings, model names, token counts, tool names and our redacted
    intent/outcome events. An explicit value in the environment or ``.env``
    always wins, e.g. set it to ``true`` to inspect prompts in the local
    ``adk web`` Trace tab. ADK reads the flag lazily per invocation, so calling
    this at import time of the agent module is early enough.
    """
    os.environ.setdefault(CAPTURE_CONTENT_ENV, "false")


def get_tracer() -> trace.Tracer:
    """Returns this application's tracer."""
    return trace.get_tracer(TRACER_NAME)


def configure_tracing(enable_cloud_trace: bool, enable_console_trace: bool) -> None:
    """Registers span exporters once per process.

    Does nothing if a TracerProvider was already installed (for example by
    ``adk web --otel_to_cloud`` or Agent Engine), so it never fights the host.
    """
    global _configured
    if _configured or not (enable_cloud_trace or enable_console_trace):
        return
    _configured = True
    try:
        from google.adk.telemetry.setup import OTelHooks, maybe_set_otel_providers

        hooks: list[OTelHooks] = []
        if enable_cloud_trace:
            from google.adk.telemetry.google_cloud import get_gcp_exporters

            hooks.append(get_gcp_exporters(enable_cloud_tracing=True))
        if enable_console_trace:
            from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor

            hooks.append(OTelHooks(span_processors=[SimpleSpanProcessor(ConsoleSpanExporter())]))
        maybe_set_otel_providers(otel_hooks_to_setup=hooks)
        logger.info("OpenTelemetry tracing configured", extra={"event": "tracing_configured",
                                                               "cloud_trace": enable_cloud_trace})
    except Exception as exc:  # noqa: BLE001 - tracing must never break the agent
        logger.warning("Tracing setup skipped: %s", type(exc).__name__)


@contextmanager
def traced_operation(name: str, **attributes: Any) -> Iterator[trace.Span]:
    """Creates a child span with redacted attributes and records failures.

    Example:
      with traced_operation("compute.firewalls.list", scope_id="my-proj") as span:
          span.set_attribute("rule_count", 12)
    """
    with get_tracer().start_as_current_span(name) as span:
        for key, value in attributes.items():
            if value is None:
                continue
            span.set_attribute(f"firewall_ops.{key}", value if isinstance(value, (bool, int, float)) else redact_text(str(value)))
        try:
            yield span
        except Exception as exc:
            span.record_exception(exc)
            span.set_status(Status(StatusCode.ERROR, type(exc).__name__))
            raise
