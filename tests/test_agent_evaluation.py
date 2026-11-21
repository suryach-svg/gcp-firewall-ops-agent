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
"""ADK AgentEvaluator suites.

* Offline (always runs): the real eval set is executed through ADK's evaluation
  harness with the scripted model, proving the harness, trajectories and eval
  data stay valid in CI.
* Live (opt-in): RUN_LIVE_EVAL=1 runs the same eval set against real Gemini
  models with the full criteria in eval/agent_evalsets/test_config.json.
"""

import json
import os
import shutil
from pathlib import Path

import pytest
from google.adk.evaluation.agent_evaluator import AgentEvaluator

from firewall_ops_agent.agent import build_app, build_root_agent
from tests.fakes import ScriptedFirewallLlm
from tests.test_end_to_end_offline import _use_model

EVAL_DIR = Path(__file__).resolve().parent.parent / "eval" / "agent_evalsets"


async def test_adk_evaluator_runs_eval_set_offline(tmp_path):
    shutil.copy(EVAL_DIR / "firewall_ops.test.json", tmp_path / "firewall_ops.test.json")
    (tmp_path / "test_config.json").write_text(json.dumps({
        "criteria": {"tool_trajectory_avg_score": {"threshold": 1.0, "match_type": "IN_ORDER", "ignore_args": True}}
    }))
    fake = ScriptedFirewallLlm()
    root = build_root_agent()
    _use_model(root, fake)
    await AgentEvaluator.evaluate(
        agent_module=build_app(root, summarizer_llm=fake),
        eval_dataset_file_path_or_dir=str(tmp_path),
        num_runs=1,
        print_detailed_results=False,
    )


@pytest.mark.live
@pytest.mark.skipif(os.environ.get("RUN_LIVE_EVAL") != "1", reason="set RUN_LIVE_EVAL=1 with Google Cloud credentials")
async def test_live_agent_eval_against_gemini():
    from firewall_ops_agent.agent import app

    await AgentEvaluator.evaluate(agent_module=app, eval_dataset_file_path_or_dir=str(EVAL_DIR), num_runs=1)
