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
"""Deterministic self-evaluation of the LLM-written report (hallucination guard).

Checks that the report:
  1. lists only real rules in its "Fix first" section, and contains no
     near-miss variants of real rule names anywhere (typical hallucinations);
  2. mentions every CRITICAL and HIGH rule found by the engine;
  3. states the same posture score as the risk engine.

Policy names, networks, tags, service accounts, ports and CIDRs are legitimate
identifiers in a report and are never flagged.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import asdict, dataclass, field
from typing import Any

_BOLD = re.compile(r"\*\*([^*\n]{2,120})\*\*")
_CODE = re.compile(r"`([^`\n]{2,120})`")
_LIST_ITEM = re.compile(r"^\s*\d+[.)]\s+")
_IGNORE = re.compile(r"^(FW-\d{3}|KB-[A-Z-]+|\d+(-\d+)?|\d+(\.\d+){3}(/\d+)?|[0-9a-f:]+/\d+|tcp|udp|icmp|all)$",
                     re.IGNORECASE)
_SCORE = re.compile(r"(\d{1,3})\s*/\s*100")
_NEAR_MISS_RATIO = 0.85


@dataclass
class GroundingVerdict:
    """Outcome of the grounding check."""

    passed: bool
    unknown_rule_names: list[str] = field(default_factory=list)
    uncovered_high_risk_rules: list[str] = field(default_factory=list)
    reported_score: int | None = None
    engine_score: int | None = None
    high_risk_rules_total: int = 0

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable form for session state."""
        return asdict(self)

    def to_markdown(self) -> str:
        """Short message appended to the conversation."""
        if self.passed:
            return (
                f"**Grounding check passed** - all {self.high_risk_rules_total} CRITICAL/HIGH rules are covered, "
                f"the posture score matches the risk engine ({self.engine_score}/100) and no unknown rule names "
                "were cited."
            )
        problems = []
        if self.unknown_rule_names:
            problems.append(f"cites rule names not found in the inventory: {', '.join(self.unknown_rule_names)}")
        if self.uncovered_high_risk_rules:
            problems.append(f"omits high-risk rules: {', '.join(self.uncovered_high_risk_rules)}")
        if self.reported_score is not None and self.reported_score != self.engine_score:
            problems.append(f"reports posture {self.reported_score}/100 but the engine computed {self.engine_score}/100")
        if self.reported_score is None and self.engine_score is not None:
            problems.append("does not state the posture score")
        return "**Grounding check: review needed** - the report " + "; ".join(problems) + "."


def identifiers_from_inventory(inventory: list[dict[str, Any]]) -> set[str]:
    """Every legitimate identifier a report may mention (rules, policies, networks, tags, accounts)."""
    identifiers: set[str] = set()
    for rule in inventory:
        identifiers.update(filter(None, [rule.get("name"), rule.get("policy_name"), rule.get("network"),
                                         rule.get("scope_id")]))
        for key in ("target_tags", "source_tags", "target_service_accounts", "source_service_accounts",
                    "target_secure_tags", "target_resources"):
            identifiers.update(rule.get(key) or [])
    return identifiers


def _fix_first_lines(report_text: str) -> list[str]:
    lines, inside = [], False
    for line in report_text.splitlines():
        if line.lstrip().startswith("#"):
            inside = "fix first" in line.lower()
            continue
        if inside and _LIST_ITEM.match(line):
            lines.append(line)
    return lines


def verify_report_grounding(
    report_text: str,
    rule_names: set[str],
    risk_report: dict[str, Any] | None,
    allowed_identifiers: set[str] | None = None,
) -> GroundingVerdict:
    """Compares an LLM-written report with the deterministic inventory and risk report."""
    report_text = report_text or ""
    names_lower = {name.lower(): name for name in rule_names}
    allowed = {i.lower() for i in (allowed_identifiers or set())} | set(names_lower)
    unknown: list[str] = []

    # 1a. Every "Fix first" item must start with a real rule name.
    for line in _fix_first_lines(report_text):
        match = _BOLD.search(line) or _CODE.search(line)
        if match:
            token = match.group(1).strip()
            if token.lower() not in names_lower and token not in unknown:
                unknown.append(token)
    # 1b. Near-miss variants of real rule names anywhere are likely hallucinations.
    for pattern in (_BOLD, _CODE):
        for match in pattern.finditer(report_text):
            token = match.group(1).strip()
            lowered = token.lower()
            if lowered in allowed or _IGNORE.match(token) or token in unknown:
                continue
            close = difflib.get_close_matches(lowered, list(names_lower), n=1, cutoff=_NEAR_MISS_RATIO)
            if close:
                unknown.append(token)

    # 2. Coverage of high-risk rules.
    findings = (risk_report or {}).get("findings", [])
    high_risk = sorted({f["rule_name"] for f in findings if f.get("severity") in ("CRITICAL", "HIGH")})
    lowered_report = report_text.lower()
    uncovered = [name for name in high_risk if name.lower() not in lowered_report]

    # 3. Posture score consistency.
    engine_score = (risk_report or {}).get("posture_score")
    score_match = _SCORE.search(report_text)
    reported = int(score_match.group(1)) if score_match else None
    passed = not unknown and not uncovered and (engine_score is None or reported == engine_score)
    return GroundingVerdict(passed=passed, unknown_rule_names=unknown, uncovered_high_risk_rules=uncovered,
                            reported_score=reported, engine_score=engine_score,
                            high_risk_rules_total=len(high_risk))
