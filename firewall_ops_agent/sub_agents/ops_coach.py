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
"""Interactive Firewall Ops Coach: explains risks, drafts better rules, stages approved fixes."""

from google.adk.agents import LlmAgent
from google.adk.tools import load_memory

from ..config import TaskProfile, model_for
from ..prompts import COACH_INSTRUCTION
from ..routing import escalate_for_complex_questions
from ..tools.analysis_tools import explain_firewall_risk_check
from ..tools.inventory_tools import get_firewall_rule_details
from ..tools.knowledge_tools import search_firewall_best_practices
from ..tools.remediation_tools import apply_firewall_remediation, propose_least_privilege_rule


def build_ops_coach() -> LlmAgent:
    """Creates the coach agent (fast model, escalates to the reasoning model when complex)."""
    return LlmAgent(
        name="firewall_ops_coach",
        description=(
            "Answers follow-up questions about specific firewall rules and findings, diagnoses how rules interact "
            "across the organization/folder/project hierarchy, drafts least-privilege rules (gcloud + Terraform) "
            "and stages remediations that require human approval."
        ),
        model=model_for(TaskProfile.COACHING),
        instruction=COACH_INSTRUCTION,
        tools=[
            get_firewall_rule_details,
            explain_firewall_risk_check,
            search_firewall_best_practices,
            propose_least_privilege_rule,
            apply_firewall_remediation,
            load_memory,
        ],
        before_model_callback=escalate_for_complex_questions,
    )
