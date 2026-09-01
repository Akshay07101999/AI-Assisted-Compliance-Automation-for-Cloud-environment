"""
ComplianceGuard — CIDR Classifier

Utility shared by the Remediation Safety Gate to classify IP ranges by exposure level.
Used by Security Group (CIS-5.2) and RDS (CIS-2.3.2) gate decisions.

Classification buckets:
  'internet'    — 0.0.0.0/0 or ::/0  (globally reachable)
  'private'     — RFC 1918 ranges    (VPC / corporate LAN only)
  'restricted'  — narrow, specific   (corporate VPN, single IP, etc.)
"""

import ipaddress
import logging

logger = logging.getLogger(__name__)

# RFC 1918 private address ranges
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

# RFC 4193 Unique Local IPv6 Unicast Addresses
_PRIVATE_NETWORKS_V6 = [
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"), # Link-Local
    ipaddress.ip_network("::1/128"),   # Localhost
]

# Well-known internet-exposure sentinel CIDRs
_INTERNET_CIDRS = {"0.0.0.0/0", "::/0"}


def classify_cidr(cidr: str) -> str:
    """
    Classify a CIDR string into one of three exposure buckets.

    Returns:
      'internet'   — globally reachable (0.0.0.0/0 or ::/0)
      'private'    — RFC 1918 internal range (safe internal access)
      'restricted' — specific external range (corporate VPN, narrow block)
    """
    if not cidr:
        return "internet"  # unknown = fail-safe worst case

    if cidr in _INTERNET_CIDRS:
        return "internet"

    try:
        # Handle IPv6 — ::/0 is the only sentinel we track for IPv6
        if ":" in cidr:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                for private in _PRIVATE_NETWORKS_V6:
                    if network.subnet_of(private):
                        return "private"
            except (ValueError, TypeError):
                pass
            return "restricted"  # Any specific IPv6 range = restricted external

        network = ipaddress.ip_network(cidr, strict=False)

        for private in _PRIVATE_NETWORKS:
            if network.subnet_of(private):
                return "private"

        return "restricted"

    except ValueError:
        logger.warning(f"CIDRClassifier: could not parse '{cidr}' — treating as internet")
        return "internet"


def classify_cidr_list(cidrs: list) -> str:
    """
    Classify a list of CIDRs and return the WORST (most dangerous) classification.
    Used when a single Security Group rule has multiple IP ranges.

    Priority: internet > restricted > private
    """
    result = "private"
    for cidr in cidrs:
        classification = classify_cidr(cidr)
        if classification == "internet":
            return "internet"  # Short circuit — can't get worse
        if classification == "restricted":
            result = "restricted"
    return result


def extract_all_cidrs(ip_permissions: list) -> list:
    """
    Flatten all CIDRs (IPv4 + IPv6) from a describe_security_groups IpPermissions list.
    Returns a flat list of CIDR strings.
    """
    cidrs = []
    for rule in ip_permissions:
        for ipv4 in rule.get("IpRanges", []):
            cidrs.append(ipv4.get("CidrIp", ""))
        for ipv6 in rule.get("Ipv6Ranges", []):
            cidrs.append(ipv6.get("CidrIpv6", ""))
    return [c for c in cidrs if c]
