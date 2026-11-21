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
"""Deterministic firewall risk engine.

The LLM never decides *whether* a rule is risky: these checks do. The agent's
job is to explain findings, prioritize them and coach the engineer. Keeping the
detection logic deterministic makes the agent auditable and lets us regression
test it against a golden dataset (see ``eval/golden``).

Hierarchy semantics modelled here (Google Cloud firewall evaluation order):
  1. Organization firewall policy rules (lowest priority number first)
  2. Folder firewall policy rules
  3. Project VPC firewall rules (deny wins ties at equal priority)
An ``allow`` or ``deny`` at a higher level ends evaluation; ``goto_next``
delegates to the next level.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from ..schemas import FirewallRule, RiskFinding, RiskReport, Severity
from .network_utils import (
    SourceClass,
    allows_all_ports,
    covers_port,
    internet_ranges,
    peer_ranges,
    ports_cover,
    ranges_cover,
    ranges_of_class,
    widest_port_span,
)


@dataclass(frozen=True)
class ServicePort:
    """A well-known service port and its closest Security Command Center category."""

    protocol: str
    port: int
    service: str
    scc_category: str | None = None


REMOTE_ADMIN_PORTS = (
    ServicePort("tcp", 22, "SSH", "OPEN_SSH_PORT"),
    ServicePort("tcp", 3389, "RDP", "OPEN_RDP_PORT"),
    ServicePort("tcp", 5985, "WinRM (HTTP)"),
    ServicePort("tcp", 5986, "WinRM (HTTPS)"),
    ServicePort("tcp", 5900, "VNC"),
)
DATA_SERVICE_PORTS = (
    ServicePort("tcp", 3306, "MySQL", "OPEN_MYSQL_PORT"),
    ServicePort("tcp", 5432, "PostgreSQL", "OPEN_POSTGRESQL_PORT"),
    ServicePort("tcp", 1433, "Microsoft SQL Server"),
    ServicePort("tcp", 1521, "Oracle Database", "OPEN_ORACLEDB_PORT"),
    ServicePort("tcp", 27017, "MongoDB", "OPEN_MONGODB_PORT"),
    ServicePort("tcp", 6379, "Redis", "OPEN_REDIS_PORT"),
    ServicePort("tcp", 9200, "Elasticsearch HTTP", "OPEN_ELASTICSEARCH_PORT"),
    ServicePort("tcp", 9300, "Elasticsearch transport", "OPEN_ELASTICSEARCH_PORT"),
    ServicePort("tcp", 11211, "Memcached", "OPEN_MEMCACHED_PORT"),
    ServicePort("udp", 11211, "Memcached (UDP)", "OPEN_MEMCACHED_PORT"),
    ServicePort("tcp", 9042, "Cassandra CQL", "OPEN_CASSANDRA_PORT"),
    ServicePort("tcp", 5984, "CouchDB"),
    ServicePort("tcp", 2379, "etcd"),
)
CLEARTEXT_LEGACY_PORTS = (
    ServicePort("tcp", 21, "FTP", "OPEN_FTP_PORT"),
    ServicePort("tcp", 23, "Telnet", "OPEN_TELNET_PORT"),
    ServicePort("udp", 69, "TFTP"),
    ServicePort("tcp", 110, "POP3", "OPEN_POP3_PORT"),
    ServicePort("tcp", 139, "NetBIOS session", "OPEN_NETBIOS_PORT"),
    ServicePort("udp", 137, "NetBIOS name service", "OPEN_NETBIOS_PORT"),
    ServicePort("tcp", 143, "IMAP"),
    ServicePort("udp", 161, "SNMP"),
    ServicePort("udp", 162, "SNMP trap"),
    ServicePort("tcp", 389, "LDAP", "OPEN_LDAP_PORT"),
    ServicePort("tcp", 445, "SMB"),
    ServicePort("tcp", 512, "rexec"),
    ServicePort("tcp", 513, "rlogin"),
    ServicePort("tcp", 514, "rsh"),
)
WIDE_PORT_RANGE_THRESHOLD = 1000

CHECK_CATALOG: dict[str, dict[str, str]] = {
    "FW-001": {"title": "Remote administration exposed to the internet", "default_severity": "CRITICAL",
               "detects": "Ingress allow from internet-wide sources (e.g. 0.0.0.0/0) to SSH 22, RDP 3389, WinRM 5985/5986 or VNC 5900."},
    "FW-002": {"title": "Database or cache service exposed to the internet", "default_severity": "CRITICAL",
               "detects": "Ingress allow from the internet to MySQL, PostgreSQL, SQL Server, Oracle, MongoDB, Redis, Elasticsearch, Memcached, Cassandra, CouchDB or etcd ports."},
    "FW-003": {"title": "All protocols/ports open to the internet", "default_severity": "CRITICAL",
               "detects": "Ingress allow from the internet for protocol 'all' or every tcp/udp port."},
    "FW-004": {"title": "Overly broad port range", "default_severity": "HIGH (external sources) / MEDIUM (internal)",
               "detects": f"Allow rules spanning {WIDE_PORT_RANGE_THRESHOLD} or more ports."},
    "FW-005": {"title": "Insecure cleartext/legacy protocol exposed to the internet", "default_severity": "HIGH",
               "detects": "Internet exposure of Telnet, FTP, TFTP, SNMP, SMB, NetBIOS, rsh/rlogin/rexec, LDAP, POP3 or IMAP."},
    "FW-006": {"title": "Internet-facing rule applies to every instance", "default_severity": "MEDIUM",
               "detects": "Internet-facing allow rules with no target tags, service accounts or target resources."},
    "FW-007": {"title": "Firewall Rules Logging disabled on internet-facing rule", "default_severity": "LOW",
               "detects": "Internet-facing allow rules without Firewall Rules Logging."},
    "FW-008": {"title": "Unrestricted egress to the internet", "default_severity": "LOW",
               "detects": "Egress allow rules to 0.0.0.0/0 on all protocols/ports."},
    "FW-009": {"title": "Permissive default-network rule still present", "default_severity": "LOW",
               "detects": "Auto-created default-allow-* rules from the default VPC network."},
    "FW-010": {"title": "Disabled rule left in place", "default_severity": "INFO",
               "detects": "Rules that are disabled but not deleted."},
    "FW-011": {"title": "Hierarchical policy allow overrides lower-level controls", "default_severity": "HIGH / MEDIUM",
               "detects": "Organization or folder firewall policy rules that allow internet traffic; they are evaluated before project rules and cannot be overridden by project denies."},
    "FW-012": {"title": "Shadowed rule", "default_severity": "MEDIUM (shadowed deny) / INFO (shadowed allow)",
               "detects": "A rule fully covered by a higher-precedence rule with the opposite action, so it never takes effect."},
    "FW-013": {"title": "Broad internal access to sensitive services", "default_severity": "LOW",
               "detects": "Large RFC 1918 source ranges (/16 or wider) allowed to admin or database ports (lateral movement risk)."},
}

# Posture scoring: points deducted per finding, capped per rule so one bad rule
# cannot dominate the score.
SEVERITY_WEIGHTS = {Severity.CRITICAL: 15, Severity.HIGH: 8, Severity.MEDIUM: 4, Severity.LOW: 1, Severity.INFO: 0}
PER_RULE_DEDUCTION_CAP = 20
_EXPOSURE_CHECKS = {"FW-001", "FW-002", "FW-003", "FW-004", "FW-005", "FW-006", "FW-007", "FW-013"}
_LEVEL_RANK = {"organization": 0, "folder": 1, "project": 2}


def _where(rule: FirewallRule) -> str:
    if rule.source_kind == "hierarchical_policy_rule":
        return f"{rule.scope_type} {rule.scope_id} policy '{rule.policy_name}' (priority {rule.priority})"
    if rule.source_kind == "network_policy_rule":
        return (f"project {rule.scope_id} network firewall policy '{rule.policy_name}' on network "
                f"'{rule.network}' (priority {rule.priority})")
    return f"project {rule.scope_id}, network '{rule.network}' (priority {rule.priority})"


def _finding(rule: FirewallRule, check_id: str, title: str, severity: Severity, evidence: str,
             explanation: str, recommendation: str, scc: str | None = None) -> RiskFinding:
    if rule.implicit_source_note and rule.direction == "INGRESS":
        evidence = f"{evidence} NOTE: {rule.implicit_source_note}"
    return RiskFinding(
        check_id=check_id,
        title=title,
        severity=severity,
        rule_name=rule.name,
        scope_type=rule.scope_type,
        scope_id=rule.scope_id,
        evidence=evidence,
        risk_explanation=explanation,
        recommendation=recommendation,
        scc_category=scc,
    )


def _exposed_services(rule: FirewallRule, catalog: tuple[ServicePort, ...]) -> list[ServicePort]:
    return [svc for svc in catalog if covers_port(rule, svc.protocol, svc.port)]


def _describe(services: list[ServicePort]) -> str:
    return ", ".join(f"{s.service} ({s.protocol}:{s.port})" for s in services)


def _check_single_rule(rule: FirewallRule) -> list[RiskFinding]:
    """Runs every per-rule check (FW-001 .. FW-011, FW-013) on one rule."""
    findings: list[RiskFinding] = []
    if rule.disabled:
        findings.append(_finding(
            rule, "FW-010", "Disabled rule left in place", Severity.INFO,
            f"Rule '{rule.name}' in {_where(rule)} is disabled.",
            "Disabled rules add clutter, hide intent and can be re-enabled by mistake during an incident.",
            "Delete the rule if it is no longer needed, or document why it must stay.",
        ))
        return findings
    if rule.action != "allow":
        return findings

    internet = internet_ranges(rule)
    all_ports = allows_all_ports(rule)
    ports = rule.short_ports()

    if rule.direction == "EGRESS":
        if internet and all_ports:
            findings.append(_finding(
                rule, "FW-008", "Unrestricted egress to the internet", Severity.LOW,
                f"Allows EGRESS to {', '.join(internet)} on {ports} from {_where(rule)}.",
                "If a workload is compromised, unrestricted egress lets an attacker exfiltrate data or "
                "reach command-and-control servers on any port.",
                "Add a low-priority deny-all egress rule and allow only required destinations and ports "
                "(for example tcp:443 to approved ranges or Private Google Access).",
                "EGRESS_DENY_RULE_NOT_SET",
            ))
        return findings

    # ---------------- INGRESS allow rules ----------------
    if internet and all_ports:
        findings.append(_finding(
            rule, "FW-003", "All protocols/ports open to the internet", Severity.CRITICAL,
            f"Allows INGRESS from {', '.join(internet)} on {ports} in {_where(rule)}.",
            "Every listening service on the targeted VMs (including admin and database ports) is reachable "
            "from anywhere, which invites scanning, brute force and exploitation.",
            "Replace with explicit allow rules for only the ports the workload serves, restricted to known sources.",
            "OPEN_FIREWALL",
        ))
    if internet and not all_ports:
        admin = _exposed_services(rule, REMOTE_ADMIN_PORTS)
        if admin:
            findings.append(_finding(
                rule, "FW-001", "Remote administration exposed to the internet", Severity.CRITICAL,
                f"Allows INGRESS from {', '.join(internet)} to {_describe(admin)} in {_where(rule)}.",
                "Internet-exposed SSH/RDP is continuously brute-forced and is a top initial-access vector.",
                "Allow admin ports only from the IAP TCP forwarding range 35.235.240.0/20 to tagged instances "
                "and use 'gcloud compute ssh --tunnel-through-iap'.",
                admin[0].scc_category,
            ))
        data = _exposed_services(rule, DATA_SERVICE_PORTS)
        if data:
            findings.append(_finding(
                rule, "FW-002", "Database or cache service exposed to the internet", Severity.CRITICAL,
                f"Allows INGRESS from {', '.join(internet)} to {_describe(data)} in {_where(rule)}.",
                "Data stores reachable from the internet are a leading cause of data breaches and ransomware.",
                "Restrict the source to the application tier's subnet or service account, and prefer private "
                "connectivity (Private Service Connect, Cloud SQL Auth Proxy).",
                data[0].scc_category,
            ))
        legacy = _exposed_services(rule, CLEARTEXT_LEGACY_PORTS)
        if legacy:
            findings.append(_finding(
                rule, "FW-005", "Insecure cleartext/legacy protocol exposed to the internet", Severity.HIGH,
                f"Allows INGRESS from {', '.join(internet)} to {_describe(legacy)} in {_where(rule)}.",
                "These protocols send credentials or data in cleartext and have a long history of exploits.",
                "Retire the protocol (SSH instead of Telnet, SFTP instead of FTP, SNMPv3) or restrict it to "
                "a narrow trusted range over private connectivity.",
                legacy[0].scc_category,
            ))

    span = widest_port_span(rule)
    if span >= WIDE_PORT_RANGE_THRESHOLD and not (internet and all_ports):
        external = bool(internet or ranges_of_class(rule, SourceClass.EXTERNAL_SPECIFIC))
        findings.append(_finding(
            rule, "FW-004", "Overly broad port range", Severity.HIGH if external else Severity.MEDIUM,
            f"Allows {span} ports ({ports}) from {', '.join(peer_ranges(rule)) or 'tagged sources'} "
            f"in {_where(rule)}.",
            "Wide port ranges expose services nobody intended to publish and make the rule's purpose unclear.",
            "Narrow the rule to the exact ports the application needs; split unrelated services into separate rules.",
        ))

    if internet and not rule.has_targets:
        findings.append(_finding(
            rule, "FW-006", "Internet-facing rule applies to every instance", Severity.MEDIUM,
            f"Rule has no target tags, service accounts or resources, so it applies to all VMs covered by "
            f"{_where(rule)}.",
            "A network-wide rule silently exposes every current and future VM, not just the intended workload.",
            "Scope the rule with a target service account (preferred) or secure tag/network tag.",
        ))

    if internet and not rule.logging_enabled:
        findings.append(_finding(
            rule, "FW-007", "Firewall Rules Logging disabled on internet-facing rule", Severity.LOW,
            f"Logging is disabled on '{rule.name}', which allows traffic from {', '.join(internet)}.",
            "Without logs you cannot detect scanning or investigate an incident involving this rule.",
            "Enable Firewall Rules Logging (consider metadata exclusion to control cost).",
            "FIREWALL_RULE_LOGGING_DISABLED",
        ))

    if rule.name.startswith("default-allow-"):
        findings.append(_finding(
            rule, "FW-009", "Permissive default-network rule still present", Severity.LOW,
            f"'{rule.name}' is one of the auto-created default network rules in {_where(rule)}.",
            "Default rules are broad by design and are rarely reviewed after a project is created.",
            "Delete the default network (or its default-allow-* rules) and enforce the organization policy "
            "constraint compute.skipDefaultNetworkCreation.",
        ))

    if rule.source_kind == "hierarchical_policy_rule" and internet:
        sensitive = all_ports or any(
            _exposed_services(rule, catalog)
            for catalog in (REMOTE_ADMIN_PORTS, DATA_SERVICE_PORTS, CLEARTEXT_LEGACY_PORTS)
        )
        findings.append(_finding(
            rule, "FW-011", "Hierarchical policy allow overrides lower-level controls",
            Severity.HIGH if sensitive or not rule.has_targets else Severity.MEDIUM,
            f"{rule.scope_type.title()}-level policy '{rule.policy_name}' allows {ports} from "
            f"{', '.join(internet)} (priority {rule.priority}).",
            "Organization and folder policy rules are evaluated before project VPC firewall rules, and an allow "
            "ends evaluation. Project teams therefore cannot block this traffic with their own deny rules.",
            "Tighten the source and targets of this rule, or change the action to 'goto_next' so lower levels decide.",
        ))

    internal_broad = ranges_of_class(rule, SourceClass.INTERNAL_BROAD)
    if internal_broad and not all_ports:
        sensitive = _exposed_services(rule, REMOTE_ADMIN_PORTS + DATA_SERVICE_PORTS)
        if sensitive:
            findings.append(_finding(
                rule, "FW-013", "Broad internal access to sensitive services", Severity.LOW,
                f"Allows {', '.join(internal_broad)} to {_describe(sensitive)} in {_where(rule)}.",
                "Any compromised workload in that large internal range can move laterally to these services.",
                "Restrict the source to the specific subnet or service account that needs access.",
            ))
    return findings


def _precedence(rule: FirewallRule) -> tuple[int, int, int]:
    """Evaluation order key: lower sorts first (wins).

    Network firewall policies are evaluated after VPC firewall rules, which is
    Google Cloud's default enforcement order (AFTER_CLASSIC_FIREWALL).
    """
    if rule.source_kind == "vpc_firewall_rule":
        level = 2
    elif rule.source_kind == "network_policy_rule":
        level = 3
    else:
        level = _LEVEL_RANK[rule.scope_type]
    return (level, rule.priority, 0 if rule.action == "deny" else 1)


def _targets_cover(outer: FirewallRule, inner: FirewallRule) -> bool:
    if outer.source_kind != "vpc_firewall_rule":
        return not outer.has_targets  # policy rule without targets applies to every VM it governs
    if not outer.has_targets:
        return True
    if outer.target_tags and inner.target_tags and not inner.target_service_accounts:
        return set(inner.target_tags) <= set(outer.target_tags)
    if outer.target_service_accounts and inner.target_service_accounts and not inner.target_tags:
        return set(inner.target_service_accounts) <= set(outer.target_service_accounts)
    return False


def _peers_cover(outer: FirewallRule, inner: FirewallRule) -> bool:
    if internet_ranges(outer) and any(r in ("0.0.0.0/0", "::/0") for r in peer_ranges(outer)):
        if inner.direction == "INGRESS" and (inner.source_tags or inner.source_service_accounts):
            return True
    if inner.direction == "INGRESS" and (inner.source_tags or inner.source_service_accounts):
        return False
    return ranges_cover(peer_ranges(outer), peer_ranges(inner))


def _same_network(outer: FirewallRule, inner: FirewallRule) -> bool:
    if "hierarchical_policy_rule" in (outer.source_kind, inner.source_kind):
        return True  # org/folder policies govern every network below them
    return outer.network == inner.network and outer.scope_id == inner.scope_id


def find_shadowed_rules(rules: list[FirewallRule]) -> dict[str, FirewallRule]:
    """Maps rule name -> the higher-precedence rule (opposite action) that fully covers it."""
    candidates = [r for r in rules if not r.disabled and r.action in ("allow", "deny")]
    ordered = sorted(candidates, key=_precedence)
    shadowed: dict[str, FirewallRule] = {}
    for index, inner in enumerate(ordered):
        for outer in ordered[:index]:
            if (
                outer.action != inner.action
                and outer.direction == inner.direction
                and _precedence(outer) < _precedence(inner)
                and _same_network(outer, inner)
                and _targets_cover(outer, inner)
                and _peers_cover(outer, inner)
                and ports_cover(outer, inner)
            ):
                shadowed[inner.name] = outer
                break
    return shadowed


def _shadow_findings(rules: list[FirewallRule], shadowed: dict[str, FirewallRule]) -> list[RiskFinding]:
    findings = []
    by_name = {r.name: r for r in rules}
    for name, outer in shadowed.items():
        inner = by_name[name]
        if inner.action == "deny":
            upstream = shadowed.get(outer.name)
            if upstream is not None and upstream.action == "deny":
                findings.append(_finding(
                    inner, "FW-012", "Deny rule is shadowed (traffic already blocked upstream)", Severity.INFO,
                    f"Deny rule '{inner.name}' ({inner.short_ports()}, priority {inner.priority}) is covered by "
                    f"allow rule '{outer.name}', but that allow is itself blocked by higher-precedence deny "
                    f"'{upstream.name}' in {_where(upstream)}.",
                    "The traffic is blocked today by the upstream deny, not by this rule.",
                    f"Remove the conflicting allow rule '{outer.name}' so the intent is explicit at every level.",
                ))
                continue
            findings.append(_finding(
                inner, "FW-012", "Deny rule is shadowed and never takes effect", Severity.MEDIUM,
                f"Deny rule '{inner.name}' ({inner.short_ports()}, priority {inner.priority}) is fully covered by "
                f"higher-precedence allow rule '{outer.name}' in {_where(outer)}.",
                "The team believes this traffic is blocked, but the earlier allow rule always matches first.",
                f"Give the deny rule a lower priority number than '{outer.name}', or tighten/remove the allow rule.",
            ))
        else:
            findings.append(_finding(
                inner, "FW-012", "Allow rule is shadowed by a higher-precedence deny", Severity.INFO,
                f"Allow rule '{inner.name}' ({inner.short_ports()}) is fully blocked by deny rule '{outer.name}' "
                f"in {_where(outer)}.",
                "The rule has no effect today; it becomes live (and risky) if the deny rule is ever removed.",
                "Delete the dead allow rule, or document why it exists.",
            ))
    return findings


def _mitigate(findings: list[RiskFinding], shadowed: dict[str, FirewallRule], rules: list[FirewallRule]) -> None:
    """Downgrades exposure findings on allow rules that a higher-precedence deny fully blocks."""
    by_name = {r.name: r for r in rules}
    for i, finding in enumerate(findings):
        blocker = shadowed.get(finding.rule_name)
        rule = by_name.get(finding.rule_name)
        if (
            blocker is not None and rule is not None and rule.action == "allow"
            and finding.check_id in _EXPOSURE_CHECKS and finding.severity.rank > Severity.LOW.rank
        ):
            findings[i] = finding.model_copy(update={
                "severity": Severity.LOW,
                "title": f"(Mitigated) {finding.title}",
                "evidence": (
                    f"{finding.evidence} Currently mitigated: higher-precedence deny rule '{blocker.name}' blocks "
                    "the same traffic, so the exposure returns if that deny is removed."
                ),
            })


def _strengths(rules: list[FirewallRule]) -> list[str]:
    strengths = []
    active = [r for r in rules if not r.disabled]
    iap_rules = [
        r.name for r in active
        if r.action == "allow" and r.direction == "INGRESS" and r.source_ranges
        and all(c == "35.235.240.0/20" for c in r.source_ranges)
    ]
    if iap_rules:
        strengths.append(f"Admin access through Identity-Aware Proxy (35.235.240.0/20): {', '.join(iap_rules)}.")
    explicit_denies = [r.name for r in active if r.action == "deny" and internet_ranges(r)]
    if explicit_denies:
        strengths.append(f"Explicit deny rules for internet traffic: {', '.join(explicit_denies)}.")
    internet_allows = [r for r in active if r.action == "allow" and r.direction == "INGRESS" and internet_ranges(r)]
    if internet_allows:
        logged = sum(1 for r in internet_allows if r.logging_enabled)
        strengths.append(f"Firewall logging enabled on {logged} of {len(internet_allows)} internet-facing allow rules.")
    allows = [r for r in active if r.action == "allow"]
    if allows:
        scoped = sum(1 for r in allows if r.has_targets)
        strengths.append(f"{scoped} of {len(allows)} allow rules are scoped to specific targets.")
    return strengths


def _posture(findings: list[RiskFinding]) -> tuple[int, str]:
    """Scores 0-100 (higher is better) and grades A-F.

    Any CRITICAL finding caps the score at 59 (grade D or F) and any HIGH
    finding caps it at 74 (grade C or lower), so one severe exposure can never
    hide behind an otherwise clean rule set.
    """
    per_rule: Counter[str] = Counter()
    for finding in findings:
        per_rule[finding.rule_name] += SEVERITY_WEIGHTS[finding.severity]
    deduction = sum(min(points, PER_RULE_DEDUCTION_CAP) for points in per_rule.values())
    score = max(0, 100 - deduction)
    severities = {f.severity for f in findings}
    if Severity.CRITICAL in severities:
        score = min(score, 59)
    elif Severity.HIGH in severities:
        score = min(score, 74)
    grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    return score, grade


def analyze_rules(rules: list[FirewallRule], scope_type: str, scope_id: str) -> RiskReport:
    """Runs all checks and returns a deterministic RiskReport.

    Args:
      rules: Normalized rules for the scope (optionally including inherited policies).
      scope_type: 'organization', 'folder' or 'project'.
      scope_id: The scope identifier.

    Returns:
      RiskReport with findings sorted by severity (worst first).
    """
    findings: list[RiskFinding] = []
    for rule in rules:
        findings.extend(_check_single_rule(rule))
    shadowed = find_shadowed_rules(rules)
    findings.extend(_shadow_findings(rules, shadowed))
    _mitigate(findings, shadowed, rules)
    findings.sort(key=lambda f: (-f.severity.rank, f.check_id, f.rule_name))

    counts = {sev.value: 0 for sev in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    score, grade = _posture(findings)
    return RiskReport(
        scope_type=scope_type,
        scope_id=scope_id,
        rules_analyzed=len(rules),
        findings=findings,
        severity_counts=counts,
        posture_score=score,
        posture_grade=grade,
        strengths=_strengths(rules),
    )


def filter_findings(report: RiskReport, min_severity: Severity) -> list[RiskFinding]:
    """Returns findings at or above ``min_severity``."""
    return [f for f in report.findings if f.severity.rank >= min_severity.rank]
