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
"""Converts Compute Engine REST-shaped dicts into normalized FirewallRule models.

Both the bundled sample inventory and the live ``google-cloud-compute`` client
(via ``Message.to_dict(..., preserving_proto_field_name=False)``) produce the
same camelCase REST shape, so one normalizer serves both data sources.
"""

from __future__ import annotations

from typing import Any

from ..schemas import FirewallRule, ProtocolPorts, ScopeType, SourceKind
from .network_utils import normalize_protocol

_IMPLICIT_SOURCE_NOTE = (
    "No source was specified, so Google Cloud applies the implicit source "
    "0.0.0.0/0 (the entire internet) to this ingress rule."
)
_OTHER_POLICY_SOURCE_MATCHERS = (
    "srcSecureTags",
    "srcAddressGroups",
    "srcFqdns",
    "srcRegionCodes",
    "srcThreatIntelligences",
    "srcNetworks",
)


def _last_segment(value: str | None) -> str | None:
    """Returns 'default' for '.../global/networks/default' style URLs."""
    if not value:
        return None
    return value.rstrip("/").split("/")[-1]


def _protocol_entries(entries: list[dict[str, Any]] | None, protocol_key: str) -> list[ProtocolPorts]:
    result = []
    for entry in entries or []:
        result.append(
            ProtocolPorts(
                protocol=normalize_protocol(entry.get(protocol_key)),
                ports=[str(p) for p in entry.get("ports", []) or []],
            )
        )
    return result


def normalize_vpc_rule(raw: dict[str, Any], project_id: str) -> FirewallRule:
    """Normalizes one VPC firewall rule (``compute.firewalls`` REST resource).

    Args:
      raw: camelCase dict as returned by the Compute Engine API.
      project_id: Project that owns the rule.

    Returns:
      A validated FirewallRule.
    """
    direction = (raw.get("direction") or "INGRESS").upper()
    allowed = raw.get("allowed") or []
    denied = raw.get("denied") or []
    action = "deny" if denied and not allowed else "allow"
    protocols = _protocol_entries(denied if action == "deny" else allowed, "IPProtocol")

    source_ranges = list(raw.get("sourceRanges") or [])
    source_tags = list(raw.get("sourceTags") or [])
    source_sas = list(raw.get("sourceServiceAccounts") or [])
    destination_ranges = list(raw.get("destinationRanges") or [])
    implicit_note = None
    if direction == "INGRESS" and not (source_ranges or source_tags or source_sas):
        source_ranges = ["0.0.0.0/0"]
        implicit_note = _IMPLICIT_SOURCE_NOTE
    if direction == "EGRESS" and not destination_ranges:
        destination_ranges = ["0.0.0.0/0"]

    return FirewallRule(
        name=raw["name"],
        source_kind="vpc_firewall_rule",
        scope_type="project",
        scope_id=project_id,
        network=_last_segment(raw.get("network")),
        direction=direction,
        action=action,
        priority=int(raw.get("priority", 1000)),
        source_ranges=source_ranges,
        destination_ranges=destination_ranges,
        source_tags=source_tags,
        source_service_accounts=source_sas,
        target_tags=list(raw.get("targetTags") or []),
        target_service_accounts=list(raw.get("targetServiceAccounts") or []),
        protocols_ports=protocols,
        logging_enabled=bool((raw.get("logConfig") or {}).get("enable", False)),
        disabled=bool(raw.get("disabled", False)),
        description=raw.get("description") or "",
        implicit_source_note=implicit_note,
    )


def normalize_policy_rule(
    raw: dict[str, Any],
    policy_name: str,
    scope_type: ScopeType,
    scope_id: str,
    *,
    source_kind: SourceKind = "hierarchical_policy_rule",
    network: str | None = None,
) -> FirewallRule:
    """Normalizes one firewall *policy* rule (hierarchical or network firewall policy).

    Args:
      raw: camelCase ``FirewallPolicyRule`` dict.
      policy_name: Short or display name of the parent firewall policy.
      scope_type: 'organization' or 'folder' for hierarchical policies; 'project'
        for network firewall policies.
      scope_id: Numeric organization/folder ID, or the project ID.
      source_kind: 'hierarchical_policy_rule' or 'network_policy_rule'.
      network: VPC network the policy is associated with (network policies only).

    Returns:
      A validated FirewallRule.
    """
    match = raw.get("match") or {}
    direction = (raw.get("direction") or "INGRESS").upper()
    priority = int(raw.get("priority", 0))
    source_ranges = list(match.get("srcIpRanges") or [])
    destination_ranges = list(match.get("destIpRanges") or [])
    implicit_note = None
    has_other_source = any(match.get(key) for key in _OTHER_POLICY_SOURCE_MATCHERS)
    if direction == "INGRESS" and not source_ranges and not has_other_source:
        source_ranges = ["0.0.0.0/0"]
        implicit_note = _IMPLICIT_SOURCE_NOTE
    if direction == "EGRESS" and not destination_ranges:
        destination_ranges = ["0.0.0.0/0"]

    return FirewallRule(
        name=raw.get("ruleName") or f"{policy_name}/priority-{priority}",
        source_kind=source_kind,
        scope_type=scope_type,
        scope_id=scope_id,
        policy_name=policy_name,
        network=network,
        direction=direction,
        action=(raw.get("action") or "allow").lower(),
        priority=priority,
        source_ranges=source_ranges,
        destination_ranges=destination_ranges,
        source_tags=[t.get("name", "") for t in match.get("srcSecureTags") or [] if t.get("name")],
        target_resources=[_last_segment(r) or r for r in raw.get("targetResources") or []],
        target_service_accounts=list(raw.get("targetServiceAccounts") or []),
        target_secure_tags=[t.get("name", "") for t in raw.get("targetSecureTags") or [] if t.get("name")],
        protocols_ports=_protocol_entries(match.get("layer4Configs"), "ipProtocol"),
        logging_enabled=bool(raw.get("enableLogging", False)),
        disabled=bool(raw.get("disabled", False)),
        description=raw.get("description") or "",
        implicit_source_note=implicit_note,
    )
