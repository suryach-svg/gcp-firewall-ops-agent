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
"""Unit tests for the deterministic risk engine, network utilities and golden dataset."""

import pytest

from eval.run_golden_eval import evaluate as evaluate_golden
from firewall_ops_agent.core.data_sources import SampleFirewallDataSource, ScopeNotFoundError
from firewall_ops_agent.core.network_utils import (
    SourceClass,
    allows_all_ports,
    classify_cidr,
    covers_port,
    ranges_cover,
    widest_port_span,
)
from firewall_ops_agent.core.risk_engine import CHECK_CATALOG, analyze_rules, find_shadowed_rules
from firewall_ops_agent.schemas import FirewallRule, ProtocolPorts, ScopeRequest, Severity


def _report(scope_type: str, scope_id: str, inherited: bool = False):
    request = ScopeRequest(scope_type=scope_type, scope_id=scope_id, include_inherited_policies=inherited)
    rules = SampleFirewallDataSource().list_rules(request)
    return analyze_rules(rules, scope_type, scope_id), rules


def _triples(report) -> set[tuple[str, str, str]]:
    return {(f.check_id, f.rule_name, f.severity.value) for f in report.findings}


@pytest.mark.parametrize(
    ("cidr", "expected"),
    [
        ("0.0.0.0/0", SourceClass.INTERNET),
        ("::/0", SourceClass.INTERNET),
        ("8.0.0.0/7", SourceClass.INTERNET),
        ("35.235.240.0/20", SourceClass.IAP),
        ("35.191.0.0/16", SourceClass.GOOGLE_HEALTH_CHECK),
        ("10.0.0.0/8", SourceClass.INTERNAL_BROAD),
        ("10.10.1.0/24", SourceClass.INTERNAL_NARROW),
        ("203.0.113.0/24", SourceClass.EXTERNAL_SPECIFIC),  # documentation range is NOT internal
        ("not-a-cidr", SourceClass.INVALID),
    ],
)
def test_classify_cidr(cidr, expected):
    assert classify_cidr(cidr) is expected


def test_port_arithmetic():
    rule = FirewallRule(name="r", source_kind="vpc_firewall_rule", scope_type="project", scope_id="p-123456",
                        direction="INGRESS", action="allow", priority=1000, source_ranges=["0.0.0.0/0"],
                        protocols_ports=[ProtocolPorts(protocol="tcp", ports=["22", "1000-2999"])])
    assert covers_port(rule, "tcp", 22) and covers_port(rule, "tcp", 2500)
    assert not covers_port(rule, "udp", 22)
    assert widest_port_span(rule) == 2001
    assert not allows_all_ports(rule)
    rule.protocols_ports = [ProtocolPorts(protocol="all")]
    assert allows_all_ports(rule) and covers_port(rule, "udp", 161)


def test_ranges_cover():
    assert ranges_cover(["10.0.0.0/8"], ["10.1.0.0/16"])
    assert not ranges_cover(["10.1.0.0/16"], ["10.0.0.0/8"])
    assert not ranges_cover(["0.0.0.0/0"], ["2001:db8::/32"])  # different IP versions


def test_internet_ssh_and_database_exposure_are_critical():
    report, _ = _report("project", "prod-payments-app")
    triples = _triples(report)
    assert ("FW-001", "default-allow-ssh", "CRITICAL") in triples
    assert ("FW-002", "allow-mysql-from-anywhere", "CRITICAL") in triples


def test_implicit_source_is_treated_as_internet():
    report, rules = _report("project", "dev-sandbox-web")
    rule = next(r for r in rules if r.name == "allow-all-ingress-dev")
    assert rule.source_ranges == ["0.0.0.0/0"] and rule.implicit_source_note
    finding = next(f for f in report.findings if f.rule_name == "allow-all-ingress-dev" and f.check_id == "FW-003")
    assert finding.severity is Severity.CRITICAL and "implicit source" in finding.evidence


def test_iap_only_admin_rule_is_clean():
    report, _ = _report("project", "prod-payments-app")
    assert not [f for f in report.findings if f.rule_name == "allow-iap-ssh"]
    assert any("Identity-Aware Proxy" in s for s in report.strengths)


def test_shadowed_deny_is_reported_in_project_view():
    report, _ = _report("project", "prod-payments-app")
    assert ("FW-012", "deny-telnet-from-internet", "MEDIUM") in _triples(report)


def test_inherited_org_deny_mitigates_project_exposure():
    report, _ = _report("project", "prod-payments-app", inherited=True)
    telnet = next(f for f in report.findings if f.rule_name == "allow-legacy-telnet" and f.check_id == "FW-005")
    assert telnet.severity is Severity.LOW and telnet.title.startswith("(Mitigated)")
    assert "org-deny-cleartext-protocols" in telnet.evidence
    assert ("FW-012", "deny-telnet-from-internet", "INFO") in _triples(report)


def test_hierarchical_override_severity_depends_on_exposure():
    org_report, _ = _report("organization", "100000000001")
    assert ("FW-011", "org-legacy-break-glass-ssh", "HIGH") in _triples(org_report)
    folder_report, _ = _report("folder", "200000000001")
    assert ("FW-011", "prod-allow-https-to-load-balancers", "MEDIUM") in _triples(folder_report)


def test_posture_is_capped_by_critical_findings():
    report, _ = _report("organization", "100000000001")
    assert report.posture_score <= 59 and report.posture_grade in ("D", "F")
    clean, _ = _report("folder", "200000000001")
    assert clean.posture_grade == "A"


def test_disabled_rule_only_gets_hygiene_finding():
    report, _ = _report("project", "prod-payments-app")
    assert {f.check_id for f in report.findings if f.rule_name == "old-vendor-access-disabled"} == {"FW-010"}


def test_findings_sorted_worst_first_and_catalog_complete():
    report, _ = _report("project", "prod-payments-app", inherited=True)
    ranks = [f.severity.rank for f in report.findings]
    assert ranks == sorted(ranks, reverse=True)
    assert {f.check_id for f in report.findings} <= set(CHECK_CATALOG)


def test_shadow_detection_respects_networks():
    _, rules = _report("project", "prod-payments-app")
    shadowed = find_shadowed_rules(rules)
    assert shadowed["deny-telnet-from-internet"].name == "allow-legacy-telnet"
    assert "default-allow-ssh" not in shadowed  # different network than any deny rule


def test_unknown_scope_raises_helpful_error():
    with pytest.raises(ScopeNotFoundError, match="Known project IDs"):
        SampleFirewallDataSource().list_rules(ScopeRequest(scope_type="project", scope_id="no-such-project"))


def test_scope_request_validation():
    assert ScopeRequest(scope_type="organization", scope_id="organizations/123").scope_id == "123"
    with pytest.raises(ValueError):
        ScopeRequest(scope_type="folder", scope_id="my-folder")
    with pytest.raises(ValueError):
        ScopeRequest(scope_type="organization", scope_id="123", include_inherited_policies=True)


def test_golden_dataset_regression():
    """The engine must reproduce the hand-reviewed golden findings exactly."""
    assert evaluate_golden() == 0


# ---------------------------------------------------------------- network firewall policies
def _rule(name, kind, action, priority, *, network="prod-vpc", scope_type="project", scope_id="prod-payments-app"):
    return FirewallRule(
        name=name, source_kind=kind, scope_type=scope_type, scope_id=scope_id,
        network=None if kind == "hierarchical_policy_rule" else network,
        policy_name=None if kind == "vpc_firewall_rule" else "payments-policy",
        direction="INGRESS", action=action, priority=priority, source_ranges=["0.0.0.0/0"],
        protocols_ports=[ProtocolPorts(protocol="tcp", ports=["22"])])


def test_vpc_rules_are_evaluated_before_network_firewall_policies():
    """Default enforcement order (AFTER_CLASSIC_FIREWALL): a low priority number does not jump levels."""
    vpc_allow = _rule("vpc-allow-ssh", "vpc_firewall_rule", "allow", 65000)
    policy_deny = _rule("net-deny-ssh", "network_policy_rule", "deny", 10)
    shadowed = find_shadowed_rules([policy_deny, vpc_allow])
    assert shadowed["net-deny-ssh"].name == "vpc-allow-ssh"
    assert "vpc-allow-ssh" not in shadowed


def test_hierarchical_policies_win_over_network_policies():
    org_deny = _rule("org-deny-ssh", "hierarchical_policy_rule", "deny", 1000,
                     scope_type="organization", scope_id="100000000001")
    net_allow = _rule("net-allow-ssh", "network_policy_rule", "allow", 1)
    assert find_shadowed_rules([net_allow, org_deny])["net-allow-ssh"].name == "org-deny-ssh"


def test_network_policy_on_another_network_does_not_shadow():
    vpc_allow = _rule("vpc-allow-ssh", "vpc_firewall_rule", "allow", 1000, network="other-vpc")
    policy_deny = _rule("net-deny-ssh", "network_policy_rule", "deny", 10)
    assert find_shadowed_rules([vpc_allow, policy_deny]) == {}


def test_network_policy_findings_name_the_policy_and_network():
    report = analyze_rules([_rule("net-allow-ssh", "network_policy_rule", "allow", 100)], "project",
                           "prod-payments-app")
    finding = next(f for f in report.findings if f.check_id == "FW-001")
    assert finding.severity is Severity.CRITICAL
    assert "network firewall policy 'payments-policy'" in finding.evidence and "prod-vpc" in finding.evidence
