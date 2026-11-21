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
"""Firewall data sources: bundled sample inventory or live Google Cloud APIs.

``FIREWALL_DATA_MODE=sample`` (default) reads a fictional org/folder/project
hierarchy shipped with the repo, so the agent, tests and evaluations run with
zero cloud access. ``FIREWALL_DATA_MODE=live`` reads real rules with the
``google-cloud-compute`` client using Application Default Credentials.
"""

from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Any, Protocol

from ..schemas import FirewallRule, ScopeRequest
from .normalization import normalize_policy_rule, normalize_vpc_rule

logger = logging.getLogger(__name__)

SAMPLE_INVENTORY_PATH = Path(__file__).resolve().parent.parent / "data" / "sample_firewall_inventory.json"


class ScopeNotFoundError(LookupError):
    """Raised when an organization, folder or project cannot be found."""


class FirewallDataSource(Protocol):
    """Interface every firewall data source implements."""

    mode: str

    def list_rules(self, request: ScopeRequest) -> list[FirewallRule]:
        """Returns normalized rules for the requested scope."""
        ...

    def list_rules_with_warnings(self, request: ScopeRequest) -> tuple[list[FirewallRule], list[str]]:
        """Returns rules plus non-fatal warnings (e.g. a policy that could not be read)."""
        ...


class SampleFirewallDataSource:
    """Reads the bundled fictional inventory (no cloud access required)."""

    mode = "sample"

    def __init__(self, path: Path = SAMPLE_INVENTORY_PATH) -> None:
        self._data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))

    def known_scopes(self) -> dict[str, list[str]]:
        """Lists the scope IDs available in the sample inventory."""
        hierarchy = self._data["hierarchy"]
        return {
            "organization": sorted(hierarchy["organizations"]),
            "folder": sorted(hierarchy["folders"]),
            "project": sorted(hierarchy["projects"]),
        }

    def _policy_rules(self, attached_to: str) -> list[FirewallRule]:
        scope_type, scope_id = attached_to.split("/", 1)
        scope_type = "organization" if scope_type == "organizations" else "folder"
        rules: list[FirewallRule] = []
        for policy in self._data["hierarchical_firewall_policies"]:
            if policy["attached_to"] != attached_to:
                continue
            for raw in policy["rules"]:
                rules.append(normalize_policy_rule(raw, policy["name"], scope_type, scope_id))
        return rules

    def _ancestors(self, project_id: str) -> list[str]:
        """Returns ancestor resource names from the closest folder up to the org."""
        hierarchy = self._data["hierarchy"]
        chain: list[str] = []
        parent = hierarchy["projects"][project_id]["parent"]
        while parent:
            chain.append(parent)
            kind, node_id = parent.split("/", 1)
            if kind == "folders":
                parent = hierarchy["folders"][node_id].get("parent")
            else:
                parent = None
        return chain

    def list_rules(self, request: ScopeRequest) -> list[FirewallRule]:
        """Returns rules for one scope from the sample inventory.

        Raises:
          ScopeNotFoundError: if the scope is not in the sample inventory.
        """
        known = self.known_scopes()
        if request.scope_id not in known[request.scope_type]:
            raise ScopeNotFoundError(
                f"{request.scope_type} '{request.scope_id}' is not in the sample inventory. "
                f"Known {request.scope_type} IDs: {', '.join(known[request.scope_type])}."
            )
        if request.scope_type == "organization":
            return self._policy_rules(f"organizations/{request.scope_id}")
        if request.scope_type == "folder":
            return self._policy_rules(f"folders/{request.scope_id}")

        rules = [
            normalize_vpc_rule(raw, request.scope_id)
            for raw in self._data["vpc_firewall_rules"].get(request.scope_id, [])
        ]
        if request.include_inherited_policies:
            for ancestor in reversed(self._ancestors(request.scope_id)):
                rules.extend(self._policy_rules(ancestor))
        return rules

    def list_rules_with_warnings(self, request: ScopeRequest) -> tuple[list[FirewallRule], list[str]]:
        """Sample data never produces partial-read warnings."""
        return self.list_rules(request), []


class LiveGcpFirewallDataSource:
    """Reads real firewall rules with the google-cloud-compute client (read-only).

    Required read permissions (least privilege):
      * project scope: compute.firewalls.list, compute.networks.list and
        compute.networks.getEffectiveFirewalls (all in roles/compute.networkViewer)
      * exact org/folder attribution of inherited policies: compute.firewallPolicies.get
        on the organization/folder (roles/compute.orgFirewallPolicyUser); without it the
        level is inferred from evaluation order and a warning is returned
      * organization/folder scope: compute.firewallPolicies.list
    """

    mode = "live"

    def __init__(self) -> None:
        # Imported lazily so sample mode and unit tests never need cloud libraries.
        from google.cloud import compute_v1

        self._compute = compute_v1

    def _to_dict(self, message: Any) -> dict[str, Any]:
        return type(message).to_dict(message, preserving_proto_field_name=False)

    def _hierarchical_rules(self, parent_id: str) -> list[FirewallRule]:
        compute = self._compute
        scope_type, scope_id = parent_id.split("/", 1)
        scope_type = "organization" if scope_type == "organizations" else "folder"
        client = compute.FirewallPoliciesClient()
        rules: list[FirewallRule] = []
        request = compute.ListFirewallPoliciesRequest(parent_id=parent_id)
        for policy in client.list(request=request):
            policy_name = policy.short_name or policy.display_name or policy.name
            for rule in policy.rules:
                rules.append(normalize_policy_rule(self._to_dict(rule), policy_name, scope_type, scope_id))
        return rules

    def _policy_parent(self, policies_client: Any, policy: Any, hierarchy_index: int,
                       warnings: list[str]) -> tuple[str, str]:
        """Returns (scope_type, scope_id) for an inherited policy, inferring it if not permitted."""
        try:
            parent = policies_client.get(firewall_policy=policy.name).parent  # e.g. folders/123
            kind, node_id = parent.split("/", 1)
            return ("organization" if kind == "organizations" else "folder"), node_id
        except Exception as exc:  # noqa: BLE001 - attribution is best-effort, the audit must continue
            warnings.append(
                f"Could not read the parent of firewall policy '{policy.short_name or policy.name}' "
                f"({type(exc).__name__}); its level was inferred from evaluation order. Grant "
                "roles/compute.orgFirewallPolicyUser on the organization/folder for exact attribution."
            )
            # Effective firewalls are returned in evaluation order: organization first, then folders.
            return ("organization" if hierarchy_index == 0 else "folder"), str(policy.name)

    def _effective_policy_rules(
        self, project_id: str, include_hierarchical: bool, warnings: list[str]
    ) -> list[FirewallRule]:
        compute = self._compute
        networks_client = compute.NetworksClient()
        policies_client = compute.FirewallPoliciesClient()
        rules: list[FirewallRule] = []
        seen: set[tuple[str, str]] = set()
        networks = [network.name for network in networks_client.list(project=project_id)]
        for network in networks:
            try:
                response = networks_client.get_effective_firewalls(project=project_id, network=network)
            except Exception as exc:  # noqa: BLE001 - one unreadable network must not hide the others
                warnings.append(f"Could not read effective firewall policies for network '{network}' "
                                f"({type(exc).__name__}); policy rules for that network are missing.")
                continue
            hierarchy_index = 0
            for policy in response.firewall_policys:
                policy_name = policy.short_name or policy.display_name or policy.name
                if policy.type_ == "HIERARCHY":
                    index, hierarchy_index = hierarchy_index, hierarchy_index + 1
                    if not include_hierarchical or ("hierarchy", policy.name) in seen:
                        continue
                    seen.add(("hierarchy", policy.name))
                    scope_type, node_id = self._policy_parent(policies_client, policy, index, warnings)
                    rules.extend(normalize_policy_rule(self._to_dict(r), policy_name, scope_type, node_id)
                                 for r in policy.rules)
                elif policy.type_ == "NETWORK" and (policy.name, network) not in seen:
                    seen.add((policy.name, network))
                    rules.extend(
                        normalize_policy_rule(self._to_dict(r), policy_name, "project", project_id,
                                              source_kind="network_policy_rule", network=network)
                        for r in policy.rules
                    )
        return rules

    def list_rules_with_warnings(self, request: ScopeRequest) -> tuple[list[FirewallRule], list[str]]:
        """Returns live rules for one scope plus non-fatal warnings.

        Raises:
          google.api_core.exceptions.GoogleAPIError: on fatal API failures (handled by tools).
        """
        warnings: list[str] = []
        if request.scope_type == "organization":
            return self._hierarchical_rules(f"organizations/{request.scope_id}"), warnings
        if request.scope_type == "folder":
            return self._hierarchical_rules(f"folders/{request.scope_id}"), warnings

        client = self._compute.FirewallsClient()
        rules = [normalize_vpc_rule(self._to_dict(fw), request.scope_id) for fw in client.list(project=request.scope_id)]
        rules.extend(self._effective_policy_rules(request.scope_id, request.include_inherited_policies, warnings))
        return rules, warnings

    def list_rules(self, request: ScopeRequest) -> list[FirewallRule]:
        """Returns live rules for one scope (warnings are logged)."""
        rules, warnings = self.list_rules_with_warnings(request)
        for warning in warnings:
            logger.warning(warning)
        return rules


@lru_cache(maxsize=2)
def get_data_source(mode: str) -> FirewallDataSource:
    """Returns a cached data source for ``mode`` ('sample' or 'live')."""
    if mode == "live":
        logger.info("Using live Google Cloud firewall data source")
        return LiveGcpFirewallDataSource()
    logger.info("Using bundled sample firewall inventory")
    return SampleFirewallDataSource()
