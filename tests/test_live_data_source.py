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
"""Live data source tests: real Compute Engine messages, fake API clients (no network).

The fake clients return genuine ``google.cloud.compute_v1`` protobuf messages,
so these tests exercise the exact ``to_dict`` -> normalizer path used against
real Google Cloud, including the partial-permission and network-policy cases.
"""

from types import SimpleNamespace

from google.api_core import exceptions as api_exceptions
from google.cloud import compute_v1 as c

from firewall_ops_agent.core.data_sources import LiveGcpFirewallDataSource
from firewall_ops_agent.core.risk_engine import analyze_rules
from firewall_ops_agent.schemas import ScopeRequest

PROJECT = "prod-payments-app"
NETWORK_URL = f"https://www.googleapis.com/compute/v1/projects/{PROJECT}/global/networks/"


def _policy_rule(name, priority, action, ports, sources=("0.0.0.0/0",), **extra):
    return c.FirewallPolicyRule(
        rule_name=name, priority=priority, direction="INGRESS", action=action,
        match=c.FirewallPolicyRuleMatcher(
            src_ip_ranges=list(sources),
            layer4_configs=[c.FirewallPolicyRuleMatcherLayer4Config(ip_protocol="tcp", ports=ports)]),
        **extra)


def _effective(network):
    org = c.NetworksGetEffectiveFirewallsResponseEffectiveFirewallPolicy(
        name="111", short_name="org-baseline", type_="HIERARCHY",
        rules=[_policy_rule("org-deny-telnet", 100, "deny", ["23"], enable_logging=True)])
    folder = c.NetworksGetEffectiveFirewallsResponseEffectiveFirewallPolicy(
        name="222", short_name="prod-folder", type_="HIERARCHY",
        rules=[_policy_rule("prod-goto-next", 1000, "goto_next", ["443"])])
    network_policy = c.NetworksGetEffectiveFirewallsResponseEffectiveFirewallPolicy(
        name="payments-policy", type_="NETWORK",
        rules=[_policy_rule("net-allow-ssh-tagged", 500, "allow", ["22"],
                            target_secure_tags=[c.FirewallPolicyRuleSecureTag(name="tagValues/987")])])
    return c.NetworksGetEffectiveFirewallsResponse(firewall_policys=[org, folder, network_policy])


class _Firewalls:
    def list(self, *, project):
        return [c.Firewall(name="default-allow-ssh", network=NETWORK_URL + "prod-vpc", direction="INGRESS",
                           priority=65534, source_ranges=["0.0.0.0/0"],
                           allowed=[c.Allowed(I_p_protocol="tcp", ports=["22"])])]


class _Networks:
    networks = ("prod-vpc", "shared-vpc")
    unreadable: tuple[str, ...] = ()

    def list(self, *, project):
        return [c.Network(name=name) for name in self.networks]

    def get_effective_firewalls(self, *, project, network):
        if network in self.unreadable:
            raise api_exceptions.PermissionDenied("compute.networks.getEffectiveFirewalls denied")
        return _effective(network)


class _Policies:
    def get(self, *, firewall_policy):
        if firewall_policy == "111":
            return c.FirewallPolicy(parent="organizations/100000000001")
        raise api_exceptions.PermissionDenied("compute.firewallPolicies.get denied")  # folder not granted

    def list(self, *, request):
        assert request.parent_id == "folders/200000000001"
        return [c.FirewallPolicy(name="222", short_name="prod-folder",
                                 rules=[_policy_rule("prod-goto-next", 1000, "goto_next", ["443"])])]


def _source(networks=_Networks):
    source = LiveGcpFirewallDataSource()
    source._compute = SimpleNamespace(
        FirewallsClient=_Firewalls, NetworksClient=networks, FirewallPoliciesClient=_Policies,
        ListFirewallPoliciesRequest=c.ListFirewallPoliciesRequest)
    return source


def test_project_scope_reads_vpc_rules_inherited_and_network_policies():
    rules, warnings = _source().list_rules_with_warnings(
        ScopeRequest(scope_type="project", scope_id=PROJECT, include_inherited_policies=True))
    by_name = {rule.name: rule for rule in rules}
    assert sorted(by_name) == ["default-allow-ssh", "net-allow-ssh-tagged", "org-deny-telnet", "prod-goto-next"]

    vpc = by_name["default-allow-ssh"]
    assert (vpc.source_kind, vpc.network, vpc.short_ports()) == ("vpc_firewall_rule", "prod-vpc", "tcp:22")
    org = by_name["org-deny-telnet"]
    assert (org.scope_type, org.scope_id, org.action, org.logging_enabled) == ("organization", "100000000001", "deny", True)
    # The folder's parent could not be read: its level is inferred from evaluation order, with a warning.
    folder = by_name["prod-goto-next"]
    assert (folder.scope_type, folder.action) == ("folder", "goto_next")
    assert len(warnings) == 1 and "inferred" in warnings[0] and "orgFirewallPolicyUser" in warnings[0]


def test_network_policy_rules_are_kept_per_network_and_hierarchy_is_deduplicated():
    rules, _ = _source().list_rules_with_warnings(
        ScopeRequest(scope_type="project", scope_id=PROJECT, include_inherited_policies=True))
    network_rules = [r for r in rules if r.source_kind == "network_policy_rule"]
    assert sorted(r.network for r in network_rules) == ["prod-vpc", "shared-vpc"]
    assert all(r.target_secure_tags == ["tagValues/987"] and r.has_targets for r in network_rules)
    assert sum(r.name == "org-deny-telnet" for r in rules) == 1, "inherited policies are listed once"


def test_without_inherited_policies_network_policies_are_still_included():
    rules, _ = _source().list_rules_with_warnings(ScopeRequest(scope_type="project", scope_id=PROJECT))
    assert {r.source_kind for r in rules} == {"vpc_firewall_rule", "network_policy_rule"}


def test_one_unreadable_network_produces_a_warning_not_a_failure():
    class PartlyReadable(_Networks):
        unreadable = ("shared-vpc",)

    rules, warnings = _source(PartlyReadable).list_rules_with_warnings(
        ScopeRequest(scope_type="project", scope_id=PROJECT, include_inherited_policies=True))
    assert any("shared-vpc" in w and "PermissionDenied" in w for w in warnings)
    assert {r.network for r in rules if r.source_kind == "network_policy_rule"} == {"prod-vpc"}


def test_folder_scope_lists_policies_attached_to_the_folder():
    rules, warnings = _source().list_rules_with_warnings(ScopeRequest(scope_type="folder", scope_id="200000000001"))
    assert [(r.name, r.scope_type, r.scope_id) for r in rules] == [("prod-goto-next", "folder", "200000000001")]
    assert warnings == []


def test_live_rules_flow_through_the_risk_engine():
    rules, _ = _source().list_rules_with_warnings(
        ScopeRequest(scope_type="project", scope_id=PROJECT, include_inherited_policies=True))
    report = analyze_rules(rules, "project", PROJECT)
    assert ("FW-001", "default-allow-ssh") in {(f.check_id, f.rule_name) for f in report.findings}
