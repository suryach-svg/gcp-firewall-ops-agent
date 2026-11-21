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
"""Sequential audit pipeline: collect -> analyze -> write -> verify.

Pattern: Sequential pipeline. Each step hands its result to the next through
session state (``output_key``), so later steps read compact, structured context
instead of the whole conversation.

Note on ADK 2.x: ``SequentialAgent`` is marked deprecated in favor of
``Workflow`` graphs, but ``Workflow`` cannot yet be used as an ``LlmAgent``
sub-agent - which is exactly how the coordinator delegates here. We therefore
keep ``SequentialAgent`` deliberately and silence only its deprecation warning.
"""

import warnings

from google.adk.agents import LlmAgent, SequentialAgent

from ..config import TaskProfile, model_for, resilient_model
from ..prompts import ANALYST_INSTRUCTION, COLLECTOR_INSTRUCTION, REPORT_WRITER_INSTRUCTION
from ..routing import escalate_for_large_inventories
from ..tools.analysis_tools import analyze_firewall_rule_risks
from ..tools.inventory_tools import list_firewall_rules_for_scope
from ..tools.knowledge_tools import search_firewall_best_practices
from .grounding_verifier import ReportGroundingVerifier

# Deliberate use of SequentialAgent (see module docstring); silence only its deprecation notice,
# which ADK can also emit later when it copies agent trees internally.
warnings.filterwarnings("ignore", message=r".*SequentialAgent is deprecated.*", category=DeprecationWarning)


def build_audit_pipeline() -> SequentialAgent:
    """Creates the four-step audit pipeline (a fresh agent tree each call)."""
    rule_collector = LlmAgent(
        name="rule_collector_agent",
        description="Identifies the audit scope and reads its firewall rules.",
        model=model_for(TaskProfile.COLLECTION),
        instruction=COLLECTOR_INSTRUCTION,
        tools=[list_firewall_rules_for_scope],
        output_key="collection_summary",
        disallow_transfer_to_parent=True,
        disallow_transfer_to_peers=True,
    )
    risk_analyst = LlmAgent(
        name="risk_analyst_agent",
        description="Prioritizes deterministic risk findings and grounds fixes in the knowledge base.",
        model=resilient_model(TaskProfile.RISK_REASONING),
        instruction=ANALYST_INSTRUCTION,
        tools=[analyze_firewall_rule_risks, search_firewall_best_practices],
        output_key="risk_analysis",
        disallow_transfer_to_parent=True,
        disallow_transfer_to_peers=True,
    )
    report_writer = LlmAgent(
        name="report_writer_agent",
        description="Writes the final Markdown risk report from the analysis.",
        model=model_for(TaskProfile.REPORT_WRITING),
        instruction=REPORT_WRITER_INSTRUCTION,
        include_contents="none",  # context engineering: reads only {risk_analysis} from state
        output_key="final_report",
        before_model_callback=escalate_for_large_inventories,
        disallow_transfer_to_parent=True,
        disallow_transfer_to_peers=True,
    )
    verifier = ReportGroundingVerifier(
        name="report_grounding_verifier",
        description="Deterministically checks the report for unknown rule names, missing high risks and score drift.",
    )
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message=r".*SequentialAgent is deprecated.*", category=DeprecationWarning)
        return SequentialAgent(
            name="firewall_audit_pipeline",
            description=(
                "Audits firewall rules for one organization, folder or project: reads the rules, analyzes risk "
                "with a deterministic engine, writes a prioritized report and verifies it is grounded."
            ),
            sub_agents=[rule_collector, risk_analyst, report_writer, verifier],
        )
