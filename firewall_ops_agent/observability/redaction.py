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
"""PII and secret redaction for user input, logs, traces and long-term memory.

Layers:
  1. ``redact_user_input``: applied to every user message before it is stored
     in the session or sent to a model (keeps IPs, see below).
  2. ``redact_text``: fast, offline regex scrubbing used by the JSON log
     formatter, span attributes and the memory pipeline.
  3. ``redact_secrets``: credentials only; applied to model output.
  4. ``redact_text_with_dlp``: optional Google Cloud Sensitive Data Protection
     (DLP) de-identification for the memory pipeline when ENABLE_CLOUD_DLP=true.
     It runs in the background memory task, never on the request path.

Firewall CIDR ranges (e.g. 10.0.0.0/8) and service-account identities are
configuration, not personal data, so they are intentionally preserved; human
email addresses, tokens, keys and other PII are removed. Public host IPs are
masked in logs and memory but kept in user input, because engineers
legitimately ask about specific hosts ("is 203.0.113.7 allowed on port 22?").
"""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "[REDACTED_GOOGLE_API_KEY]"),
    (re.compile(r"\bya29\.[0-9A-Za-z_\-.]+"), "[REDACTED_OAUTH_TOKEN]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_ACCESS_KEY]"),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]+=*"), "Bearer [REDACTED_TOKEN]"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"), "[REDACTED_JWT]"),
    (re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)\b(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|\S+)"),
     r"\1\2[REDACTED]"),
]
_PII_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
    (re.compile(r"(?<![\w.])(?:\+\d{1,3}[ -])?\(?\d{3}\)?[ -]\d{3}[ -]\d{4}\b"), "[REDACTED_PHONE]"),
]
_PATTERNS = _SECRET_PATTERNS + _PII_PATTERNS
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b")
_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_BARE_IPV4 = re.compile(r"(?<![\d./])((?:\d{1,3}\.){3}\d{1,3})(?![\d/])")
_SERVICE_ACCOUNT_DOMAINS = ("gserviceaccount.com",)
# Stricter shapes for user input, so port lists ("443 636 3389") and long numeric resource IDs
# (organization, folder, firewall-policy IDs) are not mistaken for phone or card numbers.
_USER_PHONE = re.compile(
    r"(?<![\w.])(?:\+\d{1,3}[ .-]?\(?\d{3}\)?[ .-]?\d{3}[ .-]?\d{4}|\(\d{3}\)\s?\d{3}[-.]\d{4}|\d{3}-\d{3}-\d{4})\b"
)
_USER_CARD = re.compile(r"(?<![\w/.:-])(?:\d[ -]?){14,15}\d(?![\w/.:-])")
_SSN = _PII_PATTERNS[0]


def _luhn_valid(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for index, char in enumerate(digits):
        value = int(char)
        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _redact_email(match: re.Match[str]) -> str:
    domain = match.group(1).lower()
    if domain.endswith(_SERVICE_ACCOUNT_DOMAINS):
        return match.group(0)  # workload identity, not personal data
    return "[REDACTED_EMAIL]"


def _redact_card(match: re.Match[str]) -> str:
    digits = re.sub(r"[ -]", "", match.group(0))
    if 13 <= len(digits) <= 19 and _luhn_valid(digits):
        return "[REDACTED_CARD_NUMBER]"
    return match.group(0)


def _redact_ip(match: re.Match[str]) -> str:
    text = match.group(1)
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return text
    if address.is_global:
        octets = text.split(".")
        return f"{octets[0]}.{octets[1]}.{octets[2]}.[REDACTED]"
    return text


def redact_text(text: str) -> str:
    """Scrubs secrets and PII from free text using offline regular expressions.

    Args:
      text: Any string (log message, conversation turn, tool argument).

    Returns:
      The text with sensitive values replaced by [REDACTED_*] markers.
    """
    if not text:
        return text
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    text = _EMAIL.sub(_redact_email, text)
    text = _CARD.sub(_redact_card, text)
    text = _BARE_IPV4.sub(_redact_ip, text)
    return text


def redact_secrets(text: str) -> str:
    """Removes only credentials/secrets (keeps IPs, emails). Used on model output."""
    if not text:
        return text
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_user_input(text: str) -> str:
    """Scrubs secrets and personal data from a user message before the session or a model sees it.

    Removes credentials, SSNs, phone numbers, personal email addresses and
    Luhn-valid card numbers. Keeps IP addresses, CIDR ranges, port lists,
    numeric resource IDs and service-account emails, which the agent needs to
    answer firewall questions.

    Args:
      text: The raw text typed or pasted by the user.

    Returns:
      The text with sensitive values replaced by [REDACTED_*] markers.
    """
    if not text:
        return text
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    ssn_pattern, ssn_replacement = _SSN
    text = ssn_pattern.sub(ssn_replacement, text)
    text = _USER_PHONE.sub("[REDACTED_PHONE]", text)
    text = _EMAIL.sub(_redact_email, text)
    text = _USER_CARD.sub(_redact_card, text)
    return text


def redact_value(value: Any, _depth: int = 0) -> Any:
    """Recursively redacts strings inside dicts/lists (for structured log fields)."""
    if _depth > 6:
        return "[TRUNCATED]"
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {k: redact_value(v, _depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_value(v, _depth + 1) for v in value]
    return value


_DLP_INFO_TYPES = (
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "PERSON_NAME",
    "CREDIT_CARD_NUMBER",
    "US_SOCIAL_SECURITY_NUMBER",
    "GCP_API_KEY",
    "AUTH_TOKEN",
    "PASSWORD",
)


def redact_text_with_dlp(text: str, project_id: str) -> str:
    """De-identifies text with Cloud Sensitive Data Protection, after regex scrubbing.

    Falls back to regex-only redaction if the DLP API is unavailable, so memory
    ingestion never fails because of the optional DLP layer.
    """
    text = redact_text(text)
    if not text or not project_id:
        return text
    try:
        from google.cloud import dlp_v2

        client = dlp_v2.DlpServiceClient()
        response = client.deidentify_content(
            request={
                "parent": f"projects/{project_id}/locations/global",
                "inspect_config": {"info_types": [{"name": name} for name in _DLP_INFO_TYPES]},
                "deidentify_config": {
                    "info_type_transformations": {
                        "transformations": [{"primitive_transformation": {"replace_with_info_type_config": {}}}]
                    }
                },
                "item": {"value": text},
            }
        )
        return response.item.value
    except Exception as exc:  # noqa: BLE001 - optional layer must never break the pipeline
        logger.warning("Cloud DLP de-identification unavailable; regex redaction only (%s)", type(exc).__name__)
        return text
