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
"""Golden-dataset regression evaluation for the deterministic risk engine.

Compares the engine's findings for every scope in ``eval/golden/golden_findings.json``
with the expected (hand-reviewed) findings and prints precision, recall and
grade accuracy. Exits non-zero if quality drops below the thresholds, so CI
blocks regressions.

Usage:
  python -m eval.run_golden_eval            # evaluate
  python -m eval.run_golden_eval --update   # re-baseline after an intentional change (review the diff!)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from firewall_ops_agent.core.data_sources import SampleFirewallDataSource  # noqa: E402
from firewall_ops_agent.core.risk_engine import analyze_rules  # noqa: E402
from firewall_ops_agent.schemas import ScopeRequest  # noqa: E402

GOLDEN_PATH = ROOT / "eval" / "golden" / "golden_findings.json"
SCOPES = [
    ("project", "prod-payments-app", False),
    ("project", "prod-payments-app", True),
    ("project", "prod-data-platform", False),
    ("project", "dev-sandbox-web", True),
    ("organization", "100000000001", False),
    ("folder", "200000000001", False),
    ("folder", "200000000002", False),
]
MIN_PRECISION = 1.0
MIN_RECALL = 1.0


def _run(scope_type: str, scope_id: str, inherited: bool) -> dict:
    request = ScopeRequest(scope_type=scope_type, scope_id=scope_id, include_inherited_policies=inherited)
    report = analyze_rules(SampleFirewallDataSource().list_rules(request), scope_type, scope_id)
    return {
        "posture_score": report.posture_score,
        "posture_grade": report.posture_grade,
        "findings": sorted([f.check_id, f.rule_name, f.severity.value] for f in report.findings),
    }


def _key(scope_type: str, scope_id: str, inherited: bool) -> str:
    return f"{scope_type}/{scope_id}" + ("+inherited" if inherited else "")


def update_golden() -> None:
    golden = {_key(*scope): _run(*scope) for scope in SCOPES}
    GOLDEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    GOLDEN_PATH.write_text(json.dumps(golden, indent=2) + "\n", encoding="utf-8")
    print(f"Golden dataset written to {GOLDEN_PATH} ({len(golden)} scopes). Review the diff before committing.")


def evaluate() -> int:
    golden = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
    total_tp = total_fp = total_fn = 0
    grade_hits = 0
    print(f"{'scope':42} {'precision':>9} {'recall':>7} {'grade':>11}")
    for scope in SCOPES:
        key = _key(*scope)
        expected = golden[key]
        actual = _run(*scope)
        exp = {tuple(f) for f in expected["findings"]}
        act = {tuple(f) for f in actual["findings"]}
        tp, fp, fn = len(exp & act), len(act - exp), len(exp - act)
        total_tp, total_fp, total_fn = total_tp + tp, total_fp + fp, total_fn + fn
        grade_ok = actual["posture_grade"] == expected["posture_grade"]
        grade_hits += grade_ok
        precision = tp / (tp + fp) if tp + fp else 1.0
        recall = tp / (tp + fn) if tp + fn else 1.0
        print(f"{key:42} {precision:9.2f} {recall:7.2f} {actual['posture_grade']:>5}/{expected['posture_grade']:<5}")
        for item in sorted(act - exp):
            print(f"    unexpected finding: {item}")
        for item in sorted(exp - act):
            print(f"    missed finding:     {item}")
    precision = total_tp / (total_tp + total_fp) if total_tp + total_fp else 1.0
    recall = total_tp / (total_tp + total_fn) if total_tp + total_fn else 1.0
    grade_accuracy = grade_hits / len(SCOPES)
    print(f"\nOVERALL precision={precision:.3f} recall={recall:.3f} grade_accuracy={grade_accuracy:.3f}")
    passed = precision >= MIN_PRECISION and recall >= MIN_RECALL and grade_accuracy == 1.0
    print("RESULT:", "PASS" if passed else "FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update", action="store_true", help="Re-baseline the golden dataset.")
    args = parser.parse_args()
    if args.update:
        update_golden()
        sys.exit(0)
    sys.exit(evaluate())
