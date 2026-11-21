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
"""Structured JSON logging with PII redaction and trace correlation.

Each log line is one JSON object on stdout. Cloud Run, GKE and Agent Engine
ingest these as structured Cloud Logging entries: ``severity`` maps to the log
level and ``logging.googleapis.com/trace`` links the entry to its Cloud Trace
span, so you can jump from a trace to the exact tool intent/outcome logs.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime

from opentelemetry import trace

from .redaction import redact_text, redact_value

APP_LOGGER_NAME = "firewall_ops_agent"
_STANDARD_ATTRS = set(vars(logging.LogRecord("x", 0, "x", 0, "x", None, None))) | {"message", "asctime", "taskName"}


class JsonFormatter(logging.Formatter):
    """Formats records as single-line JSON with redacted fields."""

    def __init__(self, project_id: str | None = None) -> None:
        super().__init__()
        self._project_id = project_id

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(timespec="milliseconds"),
            "severity": record.levelname,
            "logger": record.name,
            "message": redact_text(record.getMessage()),
        }
        for key, value in vars(record).items():
            if key not in _STANDARD_ATTRS and not key.startswith("_"):
                payload[key] = redact_value(value)

        span_context = trace.get_current_span().get_span_context()
        if span_context.is_valid:
            trace_id = f"{span_context.trace_id:032x}"
            payload["trace_id"] = trace_id
            payload["span_id"] = f"{span_context.span_id:016x}"
            if self._project_id:
                payload["logging.googleapis.com/trace"] = f"projects/{self._project_id}/traces/{trace_id}"
                payload["logging.googleapis.com/spanId"] = payload["span_id"]
        if record.exc_info:
            payload["exception"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(payload, default=str, ensure_ascii=False)


class RedactingTextFormatter(logging.Formatter):
    """Human-friendly formatter for local development (still redacted)."""

    def format(self, record: logging.LogRecord) -> str:
        return redact_text(super().format(record))


def configure_logging(level: str = "INFO", log_format: str = "json", project_id: str | None = None) -> logging.Logger:
    """Configures the application logger once (idempotent).

    Args:
      level: Log level name.
      log_format: 'json' (default, for Cloud Logging) or 'text'.
      project_id: GCP project used to build Cloud Trace correlation fields.

    Returns:
      The configured application logger.
    """
    app_logger = logging.getLogger(APP_LOGGER_NAME)
    if getattr(app_logger, "_firewall_ops_configured", False):
        return app_logger
    handler = logging.StreamHandler(sys.stdout)
    if log_format == "text":
        handler.setFormatter(RedactingTextFormatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    else:
        handler.setFormatter(JsonFormatter(project_id=project_id))
    app_logger.addHandler(handler)
    app_logger.setLevel(level)
    app_logger.propagate = False
    app_logger._firewall_ops_configured = True  # type: ignore[attr-defined]
    return app_logger
