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
"""Pure-Python input and policy checks (unit-testable without ADK or an LLM).

The patterns are deliberately narrow. A firewall engineer constantly says
things like "ignore the deny rules", "which rules allow all traffic from the
internet?" or "delete all unused rules"; those must pass. Only clear attacks
(overriding the agent's own instructions, asking for credentials, or
commanding a mass opening/disabling of the firewall) are refused.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..core.network_utils import SourceClass, classify_cidr

MAX_INPUT_CHARS = 8000

_PROMPT_INJECTION = [
    # "ignore all previous instructions", "disregard the system prompt" (but not "ignore my previous instructions").
    r"\b(ignore|disregard|forget|override)\b(?!\s+(my|what i)\b).{0,40}"
    r"\b(previous|prior|above|earlier|all|your|system|developer)\b.{0,20}\b(instructions?|prompts?|guidelines|directives?)\b",
    # "ignore your safety rules", "override your system policies" ("ignore the deny rules" is fine).
    r"\b(ignore|disregard|forget|override)\b.{0,20}\b(your|system|safety)\s+(rules|policies|constraints|guardrails|restrictions)\b",
    r"\b(reveal|show|print|repeat|dump|leak)\b.{0,30}\b(system prompt|hidden prompt|your instructions|initial prompt)\b",
    r"\byou are now\b.{0,30}\b(developer mode|dan|jailbroken|unrestricted)\b",
    r"\b(act|pretend|behave) as\b.{0,30}\b(unrestricted|unfiltered|jailbroken)\b",
    r"<\s*/?\s*(system|instructions)\s*>",
]
_SECRET_NOUN = (
    r"(api[ _-]?keys?|service[ -]account(\s+json)?\s+keys?|credentials|secrets?|access[ _-]?tokens?"
    r"|auth(entication)?\s+tokens?|passwords?|private[ _-]?keys?)"
)
_SECRET_QUALIFIER = (
    r"(admin|administrator|root|database|db|ssh|gcp|cloud|aws|stored|current|real|actual|raw|full|plaintext"
    r"|default|master|signing|user)"
)
_SECRET_EXFILTRATION = [
    # "show me your API key", "give me the admin password", "export the service account key".
    # Not: "show me rules that protect the secrets bucket" or "show the secret manager rule".
    r"\b(show|print|reveal|give|send|export|dump|leak|display|output|share)\b(\s+(me|us))?(\s+(all|any|every))?"
    r"(\s+of)?(\s+(your|the agent'?s|this agent'?s|its|the|our))?(\s+" + _SECRET_QUALIFIER + r")?\s+"
    + _SECRET_NOUN
    + r"\b(?!\s+(bucket|rules?|polic(y|ies)|storage|vault|rotation|manager|scanner|engine|endpoint|api|service))",
]
# Imperative phrasing ("open all ports...", "please allow any traffic..."), so questions such as
# "which rules allow all traffic from the internet?" are not refused.
_IMPERATIVE = (
    r"(?:^|[.!?;:]\s*|\b(?:please|just|go ahead and|can you|could you|would you|will you|i want you to|you should"
    r"|let'?s|now)\s+)"
)
_EXPOSURE_COMMAND = (
    _IMPERATIVE + r"(open|allow|expose)\b.{0,15}\b(all|every|any)\b.{0,10}\b(ports?|traffic|protocols?)\b.{0,40}"
    r"\b(internet|0\.0\.0\.0/0|anywhere|everyone|public)\b"
)
_MASS_DELETION = (
    r"\b(delete|remove|disable|drop|wipe|purge)\b.{0,15}\b(all|every)\s+(of\s+)?(the\s+|our\s+|my\s+)?"
    r"((vpc|firewall|hierarchical|org|organization|folder|project|network|ingress|egress|deny|allow)\s+){0,2}"
    r"(firewalls?|rules?|polic(y|ies))\b"
)
# Turning the firewall off entirely; disabling one named rule ("disable the firewall rule X") is a normal fix.
_FIREWALL_OFF = (
    r"\b(turn off|shut off|switch off|disable|remove|delete)\b.{0,15}\b(the |all |our |my )?firewalls?\b"
    r"(?!\s+(rules?|polic(y|ies)|entries|entry))"
)
# Clean-up requests ("delete all unused rules", "remove every shadowed rule") are legitimate hygiene.
_CLEANUP_WORDS = re.compile(
    r"\b(disabled|unused|shadowed|redundant|stale|duplicates?|duplicated|dead|expired|orphaned|obsolete|deprecated"
    r"|empty)\b"
)


REFUSALS = {
    "prompt_injection": (
        "I can't follow instructions that try to override my safety rules or reveal my configuration. "
        "I'm happy to audit firewall rules, explain findings or help you write a least-privilege rule."
    ),
    "secret_exfiltration": (
        "I can't share credentials, keys or secrets. This agent authenticates with Application Default "
        "Credentials and never exposes secret values."
    ),
    "destructive_change": (
        "I won't mass-delete rules, turn off the firewall or open all ports, because that would expose your "
        "workloads. I can audit the scope and propose specific least-privilege changes that a human approves "
        "before anything is applied (clean-ups such as removing unused or shadowed rules are fine to ask for)."
    ),
    "input_too_long": (
        f"That message is longer than {MAX_INPUT_CHARS} characters. Please send a shorter request or the specific "
        "rules you want me to look at."
    ),
}


@dataclass(frozen=True)
class GuardrailVerdict:
    """Result of an input guardrail check."""

    allowed: bool
    category: str | None = None

    @property
    def refusal(self) -> str | None:
        """User-facing refusal text when blocked."""
        return REFUSALS.get(self.category or "")


def _is_destructive(normalized: str) -> bool:
    if re.search(_EXPOSURE_COMMAND, normalized) or re.search(_FIREWALL_OFF, normalized):
        return True
    return bool(re.search(_MASS_DELETION, normalized)) and not _CLEANUP_WORDS.search(normalized)


def evaluate_user_input(text: str | None) -> GuardrailVerdict:
    """Checks a user message for prompt injection, secret exfiltration and destructive intent.

    Args:
      text: The raw user message.

    Returns:
      A verdict; ``allowed`` is False with a ``category`` when the message is refused.
    """
    if not text:
        return GuardrailVerdict(True)
    if len(text) > MAX_INPUT_CHARS:
        return GuardrailVerdict(False, "input_too_long")
    normalized = re.sub(r"\s+", " ", text.lower()).strip()
    if any(re.search(pattern, normalized) for pattern in _PROMPT_INJECTION):
        return GuardrailVerdict(False, "prompt_injection")
    if any(re.search(pattern, normalized) for pattern in _SECRET_EXFILTRATION):
        return GuardrailVerdict(False, "secret_exfiltration")
    if _is_destructive(normalized):
        return GuardrailVerdict(False, "destructive_change")
    return GuardrailVerdict(True)


def widens_exposure(source_ranges: list[str] | None) -> list[str]:
    """Returns the ranges that would expose a rule to the whole internet."""
    return [cidr for cidr in source_ranges or [] if classify_cidr(cidr) is SourceClass.INTERNET]


def invalid_ranges(source_ranges: list[str] | None) -> list[str]:
    """Returns ranges that are not valid CIDR notation."""
    return [cidr for cidr in source_ranges or [] if classify_cidr(cidr) is SourceClass.INVALID]
