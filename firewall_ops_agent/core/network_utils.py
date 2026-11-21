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
"""CIDR classification and port arithmetic used by the risk engine."""

from __future__ import annotations

import ipaddress
from enum import Enum
from functools import lru_cache

from ..schemas import FirewallRule, ProtocolPorts

# Google Cloud Identity-Aware Proxy TCP forwarding source range.
IAP_TCP_FORWARDING_RANGE = "35.235.240.0/20"
# Google Front End / load balancer health-check source ranges.
GOOGLE_HEALTH_CHECK_RANGES = ("35.191.0.0/16", "130.211.0.0/22")

_INTERNAL_RANGES = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")
)
_IAP_NETWORK = ipaddress.ip_network(IAP_TCP_FORWARDING_RANGE)
_HEALTH_CHECK_NETWORKS = tuple(ipaddress.ip_network(c) for c in GOOGLE_HEALTH_CHECK_RANGES)

PORT_PROTOCOLS = frozenset({"tcp", "udp", "sctp"})
ALL_PORTS = (0, 65535)
_PROTOCOL_NUMBERS = {"1": "icmp", "6": "tcp", "17": "udp", "50": "esp", "51": "ah", "132": "sctp"}


class SourceClass(str, Enum):
    """How exposed a source CIDR is."""

    INTERNET = "internet"
    EXTERNAL_SPECIFIC = "external_specific"
    IAP = "iap"
    GOOGLE_HEALTH_CHECK = "google_health_check"
    INTERNAL_BROAD = "internal_broad"
    INTERNAL_NARROW = "internal_narrow"
    INVALID = "invalid"


def normalize_protocol(protocol: str | None) -> str:
    """Maps protocol names or IANA numbers to a lowercase name ('6' -> 'tcp')."""
    value = (protocol or "all").strip().lower()
    return _PROTOCOL_NUMBERS.get(value, value)


@lru_cache(maxsize=4096)
def classify_cidr(cidr: str) -> SourceClass:
    """Classifies a CIDR by exposure level.

    Python's ``ipaddress.is_private`` also treats documentation ranges such as
    203.0.113.0/24 as private, so internal ranges are matched explicitly.

    Args:
      cidr: An IPv4 or IPv6 CIDR such as '0.0.0.0/0' or '10.0.0.0/8'.

    Returns:
      The SourceClass for the range.
    """
    try:
        net = ipaddress.ip_network(cidr.strip(), strict=False)
    except ValueError:
        return SourceClass.INVALID
    if net.prefixlen == 0:
        return SourceClass.INTERNET
    if net.version == 4 and net.subnet_of(_IAP_NETWORK):
        return SourceClass.IAP
    if net.version == 4 and any(net.subnet_of(hc) for hc in _HEALTH_CHECK_NETWORKS):
        return SourceClass.GOOGLE_HEALTH_CHECK
    for internal in _INTERNAL_RANGES:
        if internal.version == net.version and net.subnet_of(internal):
            broad_limit = 16 if net.version == 4 else 48
            return SourceClass.INTERNAL_BROAD if net.prefixlen <= broad_limit else SourceClass.INTERNAL_NARROW
    wide_limit = 8 if net.version == 4 else 16
    if net.prefixlen <= wide_limit:
        return SourceClass.INTERNET
    return SourceClass.EXTERNAL_SPECIFIC


def is_valid_cidr(cidr: str) -> bool:
    """True if ``cidr`` parses as an IPv4/IPv6 network."""
    return classify_cidr(cidr) is not SourceClass.INVALID


def peer_ranges(rule: FirewallRule) -> list[str]:
    """The 'other side' of the connection: sources for ingress, destinations for egress."""
    return rule.source_ranges if rule.direction == "INGRESS" else rule.destination_ranges


def internet_ranges(rule: FirewallRule) -> list[str]:
    """Peer ranges of the rule that represent the whole (or most of the) internet."""
    return [c for c in peer_ranges(rule) if classify_cidr(c) is SourceClass.INTERNET]


def ranges_of_class(rule: FirewallRule, *classes: SourceClass) -> list[str]:
    """Peer ranges of the rule that fall in any of ``classes``."""
    return [c for c in peer_ranges(rule) if classify_cidr(c) in classes]


def port_ranges(entry: ProtocolPorts) -> list[tuple[int, int]]:
    """Expands an entry's port strings into inclusive (low, high) tuples.

    Protocols without ports (icmp, esp, ...) return an empty list. A port
    protocol with no explicit ports, or protocol 'all', covers every port.
    """
    protocol = normalize_protocol(entry.protocol)
    if protocol == "all":
        return [ALL_PORTS]
    if protocol not in PORT_PROTOCOLS:
        return []
    if not entry.ports:
        return [ALL_PORTS]
    ranges: list[tuple[int, int]] = []
    for raw in entry.ports:
        text = str(raw).strip()
        if "-" in text:
            low, high = text.split("-", 1)
            ranges.append((int(low), int(high)))
        else:
            ranges.append((int(text), int(text)))
    return ranges


def entry_span(entry: ProtocolPorts) -> int:
    """Number of distinct ports allowed by one protocol entry."""
    return sum(high - low + 1 for low, high in port_ranges(entry))


def widest_port_span(rule: FirewallRule) -> int:
    """Largest port span across the rule's port-based protocol entries."""
    spans = [entry_span(e) for e in rule.protocols_ports if normalize_protocol(e.protocol) in PORT_PROTOCOLS | {"all"}]
    return max(spans, default=0)


def allows_all_ports(rule: FirewallRule) -> bool:
    """True for 'all protocols' rules or tcp/udp entries covering every port."""
    for entry in rule.protocols_ports:
        protocol = normalize_protocol(entry.protocol)
        if protocol == "all":
            return True
        if protocol in PORT_PROTOCOLS and entry_span(entry) >= 65535:
            return True
    return False


def covers_port(rule: FirewallRule, protocol: str, port: int) -> bool:
    """True if the rule matches ``protocol``/``port`` (e.g. 'tcp', 22)."""
    for entry in rule.protocols_ports:
        entry_protocol = normalize_protocol(entry.protocol)
        if entry_protocol == "all":
            return True
        if entry_protocol == protocol and any(low <= port <= high for low, high in port_ranges(entry)):
            return True
    return False


def ranges_cover(outer: list[str], inner: list[str]) -> bool:
    """True if every CIDR in ``inner`` is contained in some CIDR of ``outer``."""
    if not inner or not outer:
        return False
    outer_nets = []
    for cidr in outer:
        try:
            outer_nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    for cidr in inner:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False
        if not any(o.version == net.version and net.subnet_of(o) for o in outer_nets):
            return False
    return True


def ports_cover(outer: FirewallRule, inner: FirewallRule) -> bool:
    """True if ``outer`` matches every protocol/port that ``inner`` matches."""
    if not inner.protocols_ports:
        return False
    for inner_entry in inner.protocols_ports:
        inner_protocol = normalize_protocol(inner_entry.protocol)
        inner_ranges = port_ranges(inner_entry)
        covered = False
        for outer_entry in outer.protocols_ports:
            outer_protocol = normalize_protocol(outer_entry.protocol)
            if outer_protocol == "all":
                covered = True
                break
            if inner_protocol == "all" or outer_protocol != inner_protocol:
                continue
            if inner_protocol not in PORT_PROTOCOLS:
                covered = True
                break
            outer_ranges = port_ranges(outer_entry)
            if all(any(ol <= il and ih <= oh for ol, oh in outer_ranges) for il, ih in inner_ranges):
                covered = True
                break
        if not covered:
            return False
    return True
