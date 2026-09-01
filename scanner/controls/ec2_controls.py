"""
EC2 / Security Group CIS Controls
  CIS-5.2  — Ensure no security group allows unrestricted inbound SSH/RDP
              from 0.0.0.0/0 or ::/0  (port-aware + CIDR-aware)
  CIS-5.3  — Ensure the default security group of every VPC restricts all traffic
              (inbound AND outbound rules must be empty on the default SG)
  Org-SG-DB— Ensure no security group exposes database ports to 0.0.0.0/0
              (MySQL/PostgreSQL/MongoDB/Redis/Elasticsearch)
  Org-5    — Ensure EC2 production instances are not directly internet-exposed
              via a public IP without an intermediary ALB or CloudFront
              (CIS Section 5 network security principle)
"""

from dataclasses import dataclass, field
from typing import Optional, List
import logging
from decision.cidr_classifier import classify_cidr_list, classify_cidr

logger = logging.getLogger(__name__)

# Ports that create lockout risk if blindly revoked (SSH/RDP)
LOCKOUT_PORTS = {22, 3389}

# Ports that are intentionally public (HTTP/HTTPS web traffic)
INTENTIONAL_PUBLIC_PORTS = {80, 443}

# Database ports — should never be exposed to 0.0.0.0/0
# Map of port → service name for clear findings
DATABASE_PORTS: dict[int, str] = {
    3306:  "MySQL/MariaDB",
    5432:  "PostgreSQL",
    27017: "MongoDB",
    6379:  "Redis",
    9200:  "Elasticsearch",
    1521:  "Oracle DB",
    1433:  "MSSQL",
}


@dataclass
class Finding:
    control_id:    str
    control_name:  str
    resource_id:   str
    resource_type: str  = "AWS::EC2::SecurityGroup"
    status:        str  = "NON_COMPLIANT"
    details:       dict = field(default_factory=dict)
    region:        str  = "us-east-1"


import ipaddress

def is_non_compliant_cidr(cidr: str) -> bool:
    """
    CIS-5.2 checks for unrestricted public internet exposure (0.0.0.0/0 or ::/0).
    Internal RFC1918 private network ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    and specific host APIs are compliant internal/Bastion rules.
    Will correctly map /24 public office IP blocks to 'restricted' instead of 'internet'.
    """
    if not cidr:
        return True
    return classify_cidr(cidr) == "internet"

# ── CIS-5.2: Security Group SSH/RDP Unrestricted ─────────────────────────────

def check_sg_open_ports(sg_id: str, ec2_client) -> list:
    """
    CIS-5.2 — No Security Group should allow unrestricted inbound access
    on high-risk ports from 0.0.0.0/0, ::/0, or broad network ranges.
    """
    findings = []
    try:
        response = ec2_client.describe_security_groups(GroupIds=[sg_id])
        sg = response["SecurityGroups"][0]

        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", 0)
            to_port   = rule.get("ToPort",   65535)
            protocol  = rule.get("IpProtocol", "")

            # Collect all source CIDRs for this rule
            ipv4_cidrs = [r.get("CidrIp", "")  for r in rule.get("IpRanges", [])]
            ipv6_cidrs = [r.get("CidrIpv6", "") for r in rule.get("Ipv6Ranges", [])]
            all_cidrs  = [c for c in ipv4_cidrs + ipv6_cidrs if c]

            if not all_cidrs:
                continue  # No IP ranges on this rule (SG-referenced rule — safe)

            # Filter for non-compliant (wildcard or broad) CIDRs
            non_compliant_cidrs = [c for c in all_cidrs if is_non_compliant_cidr(c)]
            if not non_compliant_cidrs:
                continue  # All CIDRs are specific (/24 to /32) — rule is COMPLIANT!

            # Check every port in the rule's range
            port_range = range(from_port, to_port + 1) if protocol != "-1" else range(0, 65536)
            offending_ports = set()

            if protocol == "-1":
                # All traffic rule — catches everything
                offending_ports = set(LOCKOUT_PORTS)  # SSH + RDP are covered
            else:
                for p in LOCKOUT_PORTS:
                    if from_port <= p <= to_port:
                        offending_ports.add(p)

            for port in offending_ports:
                findings.append(Finding(
                    control_id="CIS-5.2",
                    control_name="Security Group Unrestricted Port Access",
                    resource_id=sg_id,
                    details={
                        "sg_name":      sg.get("GroupName"),
                        "sg_id":        sg_id,
                        "port":         port,
                        "protocol":     protocol,
                        "cidrs":        all_cidrs,
                        # Pre-classify for the Remediation Safety Gate — avoids duplicate parsing
                        "cidr_exposure": classify_cidr_list(all_cidrs),
                        "violation":    (
                            f"Inbound port {port} "
                            f"({'SSH' if port == 22 else 'RDP'}) open to: "
                            f"{', '.join(all_cidrs)}"
                        ),
                    }
                ))

    except Exception as e:
        logger.error(f"Error checking CIS-5.2 for {sg_id}: {e}")

    return findings


# ── CIS-5.3: Default VPC Security Group Allows Traffic ───────────────────────

def check_default_sg_rules(sg_id: str, sg_obj: dict) -> Optional[Finding]:
    """
    CIS-5.3 — The default VPC Security Group must have NO inbound or outbound rules.

    If resources are accidentally placed in the default SG (common in non-hardened
    accounts), they inherit whatever rules exist. CIS requires the default SG to be
    a hard wall — zero rules — so accidental attachment causes access denial, not
    silent exposure.

    Uses the sg_obj already fetched by the paginator — no extra API call.

    Context enrichment for the Remediation Safety Gate:
      - attached_instances: populated by ContextCollector via network-interface lookup
      - inbound_rule_count / outbound_rule_count: scope for LLM context
    """
    if sg_obj.get("GroupName") != "default":
        return None  # Not the default SG — skip

    inbound_rules  = sg_obj.get("IpPermissions", [])
    outbound_rules = sg_obj.get("IpPermissionsEgress", [])

    # Compliant: default SG has no rules at all
    if not inbound_rules and not outbound_rules:
        return None

    return Finding(
        control_id="CIS-5.3",
        control_name="Default Security Group Restricts All Traffic",
        resource_id=sg_id,
        details={
            "sg_name":             "default",
            "vpc_id":              sg_obj.get("VpcId", ""),
            "inbound_rule_count":  len(inbound_rules),
            "outbound_rule_count": len(outbound_rules),
            "inbound_rules":       inbound_rules,
            "outbound_rules":      outbound_rules,
            # ContextCollector will populate attached_instances via
            # describe_network_interfaces(Filters=[{Name: group-id, Values: [sg_id]}])
            "attached_instances":  [],
            "violation": (
                f"Default SG has {len(inbound_rules)} inbound and "
                f"{len(outbound_rules)} outbound rules. "
                "CIS-5.3 requires the default SG to have zero rules in both directions."
            ),
            "remediation_note": (
                "SAFE if no instances attached: auto-revoke all rules. "
                "BLOCK if instances use this SG: move instances to a dedicated SG first."
            ),
        }
    )


# ── Org-SG-DB: Database Ports Exposed to 0.0.0.0/0 ──────────────────────────

def check_sg_database_exposure(sg_id: str, ec2_client, sg_obj: dict = None) -> list:
    """
    Org-SG-DB — No Security Group should allow unrestricted inbound access
    to database ports from 0.0.0.0/0 or ::/0.

    Databases should never be directly internet-accessible. Even when the DB
    sits in a private subnet, an internet-facing SG rule is a latent risk
    if the topology ever changes (new IGW, new peering, route table edit).

    Context enrichment for the Remediation Safety Gate:
      - port / service: which database engine is exposed
      - cidrs:          source CIDRs on the offending rule
      - cidr_exposure:  'internet' (only emitted when internet-facing)

    Bug #1 fix: Accepts optional sg_obj so the caller (evaluate_sg) can pass the
    already-fetched SG dict from the paginator, avoiding a duplicate
    describe_security_groups API call per SG.
    """
    findings = []
    try:
        if sg_obj is None:
            response = ec2_client.describe_security_groups(GroupIds=[sg_id])
            sg = response["SecurityGroups"][0]
        else:
            sg = sg_obj

        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", 0)
            to_port   = rule.get("ToPort",   65535)
            protocol  = rule.get("IpProtocol", "")

            ipv4_cidrs = [r.get("CidrIp", "")   for r in rule.get("IpRanges",  [])]
            ipv6_cidrs = [r.get("CidrIpv6", "") for r in rule.get("Ipv6Ranges", [])]
            all_cidrs  = [c for c in ipv4_cidrs + ipv6_cidrs if c]

            if not all_cidrs:
                continue

            # Only flag rules that are genuinely internet-facing
            if classify_cidr_list(all_cidrs) != "internet":
                continue

            if protocol == "-1":
                findings.append(Finding(
                    control_id="Org-SG-DB",
                    control_name="Database Port Exposed to Internet",
                    resource_id=sg_id,
                    details={
                        "sg_name":       sg.get("GroupName"),
                        "sg_id":         sg_id,
                        "port":          "ALL",
                        "service":       "All Databases (Wildcard)",
                        "protocol":      protocol,
                        "cidrs":         all_cidrs,
                        "cidr_exposure": "internet",
                        "violation": (
                            f"All traffic (protocol -1) open to: "
                            f"{', '.join(all_cidrs)}. "
                            "Database ports must never be directly internet-accessible."
                        ),
                    }
                ))
            else:
                for db_port, service_name in DATABASE_PORTS.items():
                    if from_port <= db_port <= to_port:
                        findings.append(Finding(
                            control_id="Org-SG-DB",
                            control_name="Database Port Exposed to Internet",
                            resource_id=sg_id,
                            details={
                                "sg_name":       sg.get("GroupName"),
                                "sg_id":         sg_id,
                                "port":          db_port,
                                "service":       service_name,
                                "protocol":      protocol,
                                "cidrs":         all_cidrs,
                                "cidr_exposure": "internet",
                                "violation": (
                                    f"{service_name} port {db_port} open to: "
                                    f"{', '.join(all_cidrs)}. "
                                    "Database ports must never be directly internet-accessible."
                                ),
                            }
                        ))

    except Exception as e:
        logger.error(f"Error checking Org-SG-DB for {sg_id}: {e}")

    return findings


# ── Org-5: EC2 Direct Public IP in Production ─────────────────────────────────

def check_ec2_public_ip(instance_id: str, ec2_client) -> Optional[Finding]:
    """
    Org-5 (CIS Section 5 Principle) — EC2 instances must not have a direct public
    IP without a clear architectural justification (bastion, NAT instance).

    Surfaces findings for ALL environments. Environment-based urgency triage is
    handled by the Risk Scorer (env_score), NOT the scanner. Hard-coding a
    production-only filter here conflates policy enforcement with risk scoring.

    Context enrichment for the Remediation Safety Gate + Operational Risk Scorer:
      - instance_state: 'running' | 'stopped'
      - env_tag:        the env tag value (dev / prod / staging etc.)
      - is_bastion:     True if role/name tag indicates intentional public access
      - public_ip:      actual IP for audit log
      - subnet_id:      for context_collector subnet topology lookup
      - vpc_id:         for context_collector route table lookup
    """
    try:
        response     = ec2_client.describe_instances(InstanceIds=[instance_id])
        reservations = response.get("Reservations", [])
        if not reservations:
            return None

        instance       = reservations[0]["Instances"][0]
        public_ip      = instance.get("PublicIpAddress")
        instance_state = instance.get("State", {}).get("Name", "unknown")

        if not public_ip:
            return None  # No public IP — compliant

        # Resolve tags
        tags     = {t["Key"].lower(): t["Value"].lower() for t in instance.get("Tags", [])}
        env_tag  = tags.get("env", tags.get("environment", "unknown"))
        role_tag = tags.get("role", "")
        name_tag = tags.get("name", "")

        is_bastion = (
            role_tag in ("bastion", "jump-server", "jumpbox")
            or "bastion" in name_tag
            or "jump" in name_tag
        )

        return Finding(
            control_id="Org-5",
            control_name="EC2 Direct Public IP Exposure",
            resource_id=instance_id,
            resource_type="AWS::EC2::Instance",
            details={
                "instance_id":    instance_id,
                "public_ip":      public_ip,
                "instance_state": instance_state,
                "env_tag":        env_tag,
                "role_tag":       role_tag,
                "is_bastion":     is_bastion,
                # Pass subnet/vpc IDs so ContextCollector can evaluate route table topology
                "subnet_id":      instance.get("SubnetId", ""),
                "vpc_id":         instance.get("VpcId", ""),
                "violation": (
                    f"EC2 instance {instance_id} has a direct public IP ({public_ip}) "
                    f"in {env_tag} environment. All internet-facing compute should sit "
                    f"behind an ALB or CloudFront."
                ),
            }
        )

    except Exception as e:
        logger.error(f"Error checking Org-5 for {instance_id}: {e}")
        return None


def evaluate_sg(sg_id: str, ec2_client, sg_obj: dict = None) -> list:
    """Run all Security Group CIS checks for a given SG ID.

    Args:
        sg_id:     The SG GroupId.
        ec2_client: Boto3 EC2 client.
        sg_obj:    Optional — the full SG dict from describe_security_groups.
                   Pass this to avoid extra API calls in check_default_sg_rules
                   and check_sg_database_exposure (Bug #1 fix).
    """
    findings = []
    # CIS-5.2: SSH/RDP open to internet
    findings.extend(check_sg_open_ports(sg_id, ec2_client))
    # CIS-5.3: default SG has rules (only flags if sg_obj.GroupName == 'default')
    if sg_obj is not None:
        result = check_default_sg_rules(sg_id, sg_obj)
        if result:
            findings.append(result)
    # Org-SG-DB: database ports open to internet — pass sg_obj to avoid 2nd API call
    findings.extend(check_sg_database_exposure(sg_id, ec2_client, sg_obj=sg_obj))
    return findings


def evaluate_instance(instance_id: str, ec2_client) -> list:
    """Run all EC2 instance CIS checks."""
    findings = []
    result = check_ec2_public_ip(instance_id, ec2_client)
    if result:
        findings.append(result)
    return findings


def evaluate_all(instance_id: str, ec2_client) -> list:
    """Alias for evaluate_instance to match scanner.py control module interface."""
    return evaluate_instance(instance_id, ec2_client)

