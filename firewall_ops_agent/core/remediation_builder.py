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
"""Builds least-privilege replacements for risky rules (deterministic).

The output is a proposal only: a hardened rule, the exact ``gcloud`` command
and a Terraform snippet. Applying it always requires human approval (see
``tools/remediation_tools.py``).
"""

from __future__ import annotations

import re

from ..schemas import FirewallRule, ProtocolPorts, RemediationProposal
from .network_utils import (
    GOOGLE_HEALTH_CHECK_RANGES,
    IAP_TCP_FORWARDING_RANGE,
    PORT_PROTOCOLS,
    SourceClass,
    allows_all_ports,
    classify_cidr,
    covers_port,
    internet_ranges,
    normalize_protocol,
    ranges_of_class,
    widest_port_span,
)

_ADMIN_PORTS = (("tcp", 22), ("tcp", 3389))
_WEB_PORTS = {80, 443, 8080, 8443}


class RemediationInputError(ValueError):
    """Raised when a safe proposal needs information only the engineer has."""

    def __init__(self, message: str, recovery_hint: str) -> None:
        super().__init__(message)
        self.recovery_hint = recovery_hint


def _only_web_ports(rule: FirewallRule) -> bool:
    if allows_all_ports(rule):
        return False
    for entry in rule.protocols_ports:
        if normalize_protocol(entry.protocol) != "tcp" or not entry.ports:
            return False
        for port in entry.ports:
            if "-" in port or int(port) not in _WEB_PORTS:
                return False
    return bool(rule.protocols_ports)


def _validate_ranges(ranges: list[str]) -> None:
    invalid = [c for c in ranges if classify_cidr(c) is SourceClass.INVALID]
    if invalid:
        raise RemediationInputError(f"Invalid CIDR ranges: {invalid}.", "Use CIDR notation such as 10.10.0.0/24.")
    wide = [c for c in ranges if classify_cidr(c) is SourceClass.INTERNET]
    if wide:
        raise RemediationInputError(
            f"{wide} would expose the rule to the whole internet.",
            "Provide the specific client ranges that need access (for admin access use 35.235.240.0/20).",
        )


def _validate_ports(ports: list[str]) -> None:
    for port in ports:
        bounds = port.split("-", 1)
        if not all(b.isdigit() and 0 <= int(b) <= 65535 for b in bounds):
            raise RemediationInputError(f"Invalid port '{port}'.", "Use port numbers or ranges such as '443' or '8000-8010'.")


def _rules_arg(entries: list[ProtocolPorts]) -> str:
    parts = []
    for entry in entries:
        if entry.ports:
            parts.extend(f"{entry.protocol}:{port}" for port in entry.ports)
        else:
            parts.append(entry.protocol)
    return ",".join(parts)


def gcloud_update_command(rule: FirewallRule) -> str:
    """gcloud command that makes the live rule match ``rule``."""
    if rule.source_kind in ("hierarchical_policy_rule", "network_policy_rule"):
        if rule.source_kind == "network_policy_rule":
            cmd = [
                f"gcloud compute network-firewall-policies rules update {rule.priority}",
                f"--firewall-policy={rule.policy_name}",
                "--global-firewall-policy",
                f"--project={rule.scope_id}",
            ]
        else:
            cmd = [
                f"gcloud compute firewall-policies rules update {rule.priority}",
                f"--firewall-policy={rule.policy_name}",
            ]
        if rule.source_kind == "hierarchical_policy_rule" and rule.scope_type == "organization":
            cmd.append(f"--organization={rule.scope_id}")
        peers_flag = "--src-ip-ranges" if rule.direction == "INGRESS" else "--dest-ip-ranges"
        peers = rule.source_ranges if rule.direction == "INGRESS" else rule.destination_ranges
        if peers:
            cmd.append(f"{peers_flag}={','.join(peers)}")
        cmd.append(f"--layer4-configs={_rules_arg(rule.protocols_ports)}")
        if rule.target_service_accounts:
            cmd.append(f"--target-service-accounts={','.join(rule.target_service_accounts)}")
        cmd.append("--enable-logging" if rule.logging_enabled else "--no-enable-logging")
        command = " \\\n    ".join(cmd)
        if rule.source_kind == "hierarchical_policy_rule" and rule.scope_type == "folder":
            command += "\n# Folder-level policy: reference it by policy ID, or add --organization=ORG_ID if using its short name."
        return command

    cmd = [f"gcloud compute firewall-rules update {rule.name}", f"--project={rule.scope_id}"]
    if rule.direction == "INGRESS" and rule.source_ranges:
        cmd.append(f"--source-ranges={','.join(rule.source_ranges)}")
    if rule.direction == "EGRESS" and rule.destination_ranges:
        cmd.append(f"--destination-ranges={','.join(rule.destination_ranges)}")
    cmd.append(f"--rules={_rules_arg(rule.protocols_ports)}")
    if rule.target_service_accounts:
        cmd.append(f"--target-service-accounts={','.join(rule.target_service_accounts)}")
    elif rule.target_tags:
        cmd.append(f"--target-tags={','.join(rule.target_tags)}")
    cmd.append(f"--priority={rule.priority}")
    cmd.append("--enable-logging" if rule.logging_enabled else "--no-enable-logging")
    return " \\\n    ".join(cmd)


def gcloud_delete_command(rule: FirewallRule) -> str:
    """gcloud command that deletes ``rule``."""
    if rule.source_kind == "network_policy_rule":
        return (f"gcloud compute network-firewall-policies rules delete {rule.priority} "
                f"--firewall-policy={rule.policy_name} --global-firewall-policy --project={rule.scope_id}")
    if rule.source_kind == "hierarchical_policy_rule":
        org = f" --organization={rule.scope_id}" if rule.scope_type == "organization" else ""
        return f"gcloud compute firewall-policies rules delete {rule.priority} --firewall-policy={rule.policy_name}{org}"
    return f"gcloud compute firewall-rules delete {rule.name} --project={rule.scope_id}"


def _hcl_list(values: list[str]) -> str:
    return "[" + ", ".join(f'"{v}"' for v in values) + "]"


def terraform_snippet(rule: FirewallRule) -> str:
    """Terraform (hashicorp/google provider) resource for ``rule``."""
    resource_name = re.sub(r"[^a-z0-9_]", "_", rule.name.lower()).strip("_") or "firewall_rule"
    if rule.source_kind in ("hierarchical_policy_rule", "network_policy_rule"):
        resource_type = ("google_compute_network_firewall_policy_rule" if rule.source_kind == "network_policy_rule"
                         else "google_compute_firewall_policy_rule")
        project_line = f'  project         = "{rule.scope_id}"\n' if rule.source_kind == "network_policy_rule" else ""
        peers_attr = "src_ip_ranges" if rule.direction == "INGRESS" else "dest_ip_ranges"
        peers = rule.source_ranges if rule.direction == "INGRESS" else rule.destination_ranges
        l4 = "\n".join(
            "    layer4_configs {\n"
            f'      ip_protocol = "{e.protocol}"\n'
            + (f"      ports       = {_hcl_list(e.ports)}\n" if e.ports else "")
            + "    }"
            for e in rule.protocols_ports
        )
        targets = (f"  target_service_accounts = {_hcl_list(rule.target_service_accounts)}\n"
                   if rule.target_service_accounts else "")
        return (
            f'resource "{resource_type}" "{resource_name}" {{\n'
            f"{project_line}"
            f'  firewall_policy = "{rule.policy_name}" # policy ID\n'
            f"  priority        = {rule.priority}\n"
            f'  direction       = "{rule.direction}"\n'
            f'  action          = "{rule.action}"\n'
            f"  enable_logging  = {str(rule.logging_enabled).lower()}\n"
            f"{targets}"
            "  match {\n"
            f"    {peers_attr} = {_hcl_list(peers)}\n"
            f"{l4}\n"
            "  }\n"
            "}"
        )

    block = "allow" if rule.action == "allow" else "deny"
    proto_blocks = "\n".join(
        f"  {block} {{\n"
        f'    protocol = "{e.protocol}"\n'
        + (f"    ports    = {_hcl_list(e.ports)}\n" if e.ports else "")
        + "  }"
        for e in rule.protocols_ports
    )
    lines = [
        f'resource "google_compute_firewall" "{resource_name}" {{',
        f'  project   = "{rule.scope_id}"',
        f'  name      = "{rule.name}"',
        f'  network   = "{rule.network or "default"}"',
        f'  direction = "{rule.direction}"',
        f"  priority  = {rule.priority}",
    ]
    if rule.direction == "INGRESS":
        lines.append(f"  source_ranges = {_hcl_list(rule.source_ranges)}")
    else:
        lines.append(f"  destination_ranges = {_hcl_list(rule.destination_ranges)}")
    if rule.target_service_accounts:
        lines.append(f"  target_service_accounts = {_hcl_list(rule.target_service_accounts)}")
    elif rule.target_tags:
        lines.append(f"  target_tags = {_hcl_list(rule.target_tags)}")
    if rule.disabled:
        lines.append("  disabled = true")
    lines.append(proto_blocks)
    if rule.logging_enabled:
        lines.append('  log_config {\n    metadata = "INCLUDE_ALL_METADATA"\n  }')
    lines.append("}")
    return "\n".join(lines)


def build_least_privilege_proposal(
    rule: FirewallRule,
    *,
    shadowed_by: FirewallRule | None = None,
    allowed_source_ranges: list[str] | None = None,
    allowed_ports: list[str] | None = None,
    target_service_account: str | None = None,
    target_tags: list[str] | None = None,
) -> RemediationProposal:
    """Creates a least-privilege version of ``rule``.

    Raises:
      RemediationInputError: when a safe value (e.g. the legitimate client
        range for a database) cannot be inferred and must come from the engineer.
    """
    changes: list[str] = []
    residual: list[str] = []
    hardened = rule.model_copy(deep=True)

    if allowed_source_ranges:
        _validate_ranges(allowed_source_ranges)
    if allowed_ports:
        _validate_ports(allowed_ports)

    if rule.disabled:
        return RemediationProposal(
            rule_name=rule.name, scope_type=rule.scope_type, scope_id=rule.scope_id,
            summary_of_changes=["Delete the disabled rule (it has no effect and can be re-enabled by mistake)."],
            hardened_rule=hardened, gcloud_command=gcloud_delete_command(rule),
            terraform_snippet="# Remove the corresponding resource block from your Terraform configuration.",
        )

    if rule.action == "deny":
        if (shadowed_by is not None and shadowed_by.source_kind == rule.source_kind
                and rule.source_kind != "hierarchical_policy_rule"):
            hardened.priority = max(0, shadowed_by.priority - 1)
            changes.append(
                f"Lower the priority number from {rule.priority} to {hardened.priority} so the deny is evaluated "
                f"before allow rule '{shadowed_by.name}' (priority {shadowed_by.priority})."
            )
        elif shadowed_by is not None:
            residual.append(
                f"The conflicting allow rule '{shadowed_by.name}' lives in a higher-level firewall policy, so the "
                "fix must be made there (tighten it or change it to goto_next)."
            )
        if not rule.logging_enabled:
            hardened.logging_enabled = True
            changes.append("Enable Firewall Rules Logging to see what this deny blocks.")
    elif rule.direction == "EGRESS":
        hardened.protocols_ports = [ProtocolPorts(protocol="tcp", ports=allowed_ports or ["443"])]
        changes.append(f"Restrict egress to tcp:{','.join(allowed_ports or ['443'])} instead of all protocols.")
        if allowed_source_ranges:
            hardened.destination_ranges = allowed_source_ranges
            changes.append(f"Restrict destinations to {', '.join(allowed_source_ranges)}.")
        else:
            residual.append("Destinations are still 0.0.0.0/0; pass approved destination ranges to narrow further.")
        residual.append("Add a low-priority (e.g. 65000) deny-all egress rule so only explicitly allowed egress passes.")
        if not rule.logging_enabled:
            hardened.logging_enabled = True
            changes.append("Enable Firewall Rules Logging.")
    else:
        internet = internet_ranges(rule)
        broad_internal = ranges_of_class(rule, SourceClass.INTERNAL_BROAD)
        exposes_admin = any(covers_port(rule, proto, port) for proto, port in _ADMIN_PORTS)
        if allowed_source_ranges:
            hardened.source_ranges = allowed_source_ranges
            changes.append(f"Replace sources {rule.source_ranges} with {allowed_source_ranges}.")
        elif internet:
            if exposes_admin and not allows_all_ports(rule):
                hardened.source_ranges = [IAP_TCP_FORWARDING_RANGE]
                changes.append(
                    f"Replace {', '.join(internet)} with the IAP TCP forwarding range {IAP_TCP_FORWARDING_RANGE}; "
                    "connect with 'gcloud compute ssh --tunnel-through-iap'."
                )
                residual.append("Grant engineers roles/iap.tunnelResourceAccessor on the target instances.")
            elif _only_web_ports(rule):
                hardened.source_ranges = list(GOOGLE_HEALTH_CHECK_RANGES)
                changes.append(
                    "Accept web traffic only from Google Front End / load balancer ranges "
                    f"({', '.join(GOOGLE_HEALTH_CHECK_RANGES)})."
                )
                residual.append("Requires an external Application Load Balancer in front of the VMs; protect it with Cloud Armor.")
            else:
                raise RemediationInputError(
                    f"'{rule.name}' exposes {rule.short_ports()} to the internet and the safe source depends on "
                    "who legitimately needs access.",
                    "Ask the engineer which client CIDR ranges need this service (for example the application "
                    "subnet), then call propose_least_privilege_rule again with allowed_source_ranges.",
                )
        elif broad_internal and not (target_service_account or target_tags or allowed_ports):
            raise RemediationInputError(
                f"'{rule.name}' allows the broad internal range(s) {broad_internal}.",
                "Ask which subnet or service account needs access, then call again with allowed_source_ranges "
                "(e.g. the app tier /24) or target_service_account.",
            )

        if allows_all_ports(rule) or widest_port_span(rule) >= 1000:
            if not allowed_ports:
                raise RemediationInputError(
                    f"'{rule.name}' allows {widest_port_span(rule)} ports ({rule.short_ports()}).",
                    "Ask which ports the application actually listens on, then call again with "
                    "allowed_ports (for example ['443'] or ['8443','9443']).",
                )
        if allowed_ports:
            protocol = next(
                (normalize_protocol(e.protocol) for e in rule.protocols_ports
                 if normalize_protocol(e.protocol) in PORT_PROTOCOLS), "tcp",
            )
            hardened.protocols_ports = [ProtocolPorts(protocol=protocol, ports=allowed_ports)]
            changes.append(f"Limit ports to {protocol}:{','.join(allowed_ports)} (was {rule.short_ports()}).")

        if target_service_account:
            hardened.target_service_accounts = [target_service_account]
            hardened.target_tags = []
            changes.append(f"Scope the rule to target service account {target_service_account}.")
        elif target_tags:
            hardened.target_tags = target_tags
            changes.append(f"Scope the rule to target tags {target_tags}.")
        elif not rule.has_targets:
            residual.append(
                "The rule still applies to every instance; pass target_service_account (preferred) or target_tags."
            )
        if not rule.logging_enabled:
            hardened.logging_enabled = True
            changes.append("Enable Firewall Rules Logging.")

    if not changes:
        changes.append("No configuration change required; see residual risks.")
    return RemediationProposal(
        rule_name=rule.name,
        scope_type=rule.scope_type,
        scope_id=rule.scope_id,
        summary_of_changes=changes,
        hardened_rule=hardened,
        gcloud_command=gcloud_update_command(hardened),
        terraform_snippet=terraform_snippet(hardened),
        residual_risks=residual,
    )
