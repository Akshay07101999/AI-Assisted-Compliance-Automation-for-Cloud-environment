"""
RDS CIS Controls
  CIS-2.3.1   — Ensure RDS instances have storage encryption enabled
  CIS-2.3.2   — Ensure RDS instances are not publicly accessible
  Org-RDS-SG-Chain — Ensure RDS Security Groups use SG-chaining (UserIdGroupPairs)
                     instead of raw IP CIDRs for database port access.
                     Internet/restricted CIDRs → NON_COMPLIANT.
                     Private CIDRs → INFO (best-practice advisory, not a hard violation).

Both CIS controls enrich their findings with attached Security Group CIDR data
so the Remediation Safety Gate can determine actual internet exposure, not just the
PubliclyAccessible flag (which can be set True while SGs are still private).
"""

from dataclasses import dataclass, field
from typing import Optional
import logging
from decision.cidr_classifier import classify_cidr_list

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    control_id:    str
    control_name:  str
    resource_id:   str
    resource_type: str  = "AWS::RDS::DBInstance"
    status:        str  = "NON_COMPLIANT"
    details:       dict = field(default_factory=dict)
    region:        str  = "us-east-1"


# ── CIS-2.3.2: RDS Publicly Accessible ───────────────────────────────────────

def check_rds_public_access(db_instance_id: str, rds_client, ec2_client=None) -> Optional[Finding]:
    """
    CIS-2.3.2 — RDS instances must not be publicly accessible.

    Context enrichment for the Remediation Safety Gate:
      - sg_cidrs: list of all CIDRs allowing inbound traffic on DB port
        from the attached Security Groups
      - sg_cidr_exposure: worst-case CIDR classification
        ('internet' | 'private' | 'restricted')

    This allows the gate to distinguish:
      - PubliclyAccessible=True + SG allows 0.0.0.0/0  → genuinely exposed (BLOCK)
      - PubliclyAccessible=True + SG allows 10.0.0.0/8 → effectively private (PROCEED)
    """
    try:
        response = rds_client.describe_db_instances(DBInstanceIdentifier=db_instance_id)
        instance = response["DBInstances"][0]

        if not instance.get("PubliclyAccessible", False):
            return None  # Compliant

        engine    = instance.get("Engine", "unknown")
        db_port   = instance.get("DbInstancePort") or _default_port(engine)
        sg_groups = instance.get("VpcSecurityGroups", [])
        sg_ids    = [sg["VpcSecurityGroupId"] for sg in sg_groups
                     if sg.get("Status") == "active"]

        # Collect all CIDRs from attached SGs for the database port
        sg_cidrs      = []
        cidr_exposure = "private"   # Assume private until proven otherwise

        if ec2_client and sg_ids:
            sg_cidrs, cidr_exposure = _collect_sg_cidrs(sg_ids, db_port, ec2_client)

        return Finding(
            control_id="CIS-2.3.2",
            control_name="RDS Not Publicly Accessible",
            resource_id=db_instance_id,
            details={
                "engine":              engine,
                "engine_version":      instance.get("EngineVersion"),
                "db_instance_class":   instance.get("DBInstanceClass"),
                "multi_az":            instance.get("MultiAZ", False),
                "db_port":             db_port,
                "sg_ids":              sg_ids,
                "sg_cidrs":            sg_cidrs,
                "sg_cidr_exposure":    cidr_exposure,   # Key field for Remediation Safety Gate
                # Flaw 3 fix: db_instance_status now populated so gate can detect
                # stopped/stopping/modifying states and block accordingly.
                "db_instance_status":  instance.get("DBInstanceStatus", "unknown"),
                "violation":           "PubliclyAccessible is set to True",
                "remediation_note": (
                    "BLOCK: internet-facing SG detected — audit all external consumers first."
                    if cidr_exposure == "internet"
                    else "PROCEED: SG restricts to private/restricted CIDRs — Risk Scorer decides."
                ),
            }
        )

    except Exception as e:
        logger.error(f"Error checking CIS-2.3.2 for {db_instance_id}: {e}")
        return None


def _default_port(engine: str) -> int:
    """Return the default port for a given RDS engine."""
    ports = {
        "mysql": 3306, "mariadb": 3306,
        "postgres": 5432, "aurora-postgresql": 5432,
        "oracle-ee": 1521, "oracle-se2": 1521,
        "sqlserver-ex": 1433, "sqlserver-se": 1433,
    }
    return ports.get(engine.lower(), 3306)


def _collect_sg_cidrs(sg_ids: list, db_port: int, ec2_client) -> tuple:
    """
    Query attached Security Groups and extract all source CIDRs that
    allow inbound traffic on the database port.

    Returns: (list_of_cidrs, worst_exposure_classification)
    """
    all_cidrs = []
    try:
        response = ec2_client.describe_security_groups(GroupIds=sg_ids)
        for sg in response.get("SecurityGroups", []):
            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port   = rule.get("ToPort",   65535)
                protocol  = rule.get("IpProtocol", "")

                allows_db_port = (
                    protocol == "-1" or
                    (from_port <= db_port <= to_port)
                )
                if not allows_db_port:
                    continue

                for ipv4 in rule.get("IpRanges", []):
                    cidr = ipv4.get("CidrIp", "")
                    if cidr:
                        all_cidrs.append(cidr)

                for ipv6 in rule.get("Ipv6Ranges", []):
                    cidr = ipv6.get("CidrIpv6", "")
                    if cidr:
                        all_cidrs.append(cidr)

        worst = classify_cidr_list(all_cidrs) if all_cidrs else "private"

    except Exception as e:
        logger.warning(f"Could not fetch SG details: {e} — defaulting to 'internet'")
        worst = "internet"   # Fail-safe

    return all_cidrs, worst


# ── CIS-2.3.1: RDS Storage Encryption ────────────────────────────────────────

def check_rds_encryption(db_instance_id: str, rds_client) -> Optional[Finding]:
    """
    CIS-2.3.1 — RDS storage encryption must be enabled.
    StorageEncrypted = False is non-compliant.

    NOTE: Encryption cannot be enabled in-place.
    Requires: stop DB → take snapshot → copy snapshot (encrypted)
              → restore new DB from encrypted snapshot → redirect all connections.
    Estimated downtime: 30-60 minutes per database.
    Remediation Safety Gate always returns BLOCK for this control.
    """
    try:
        response = rds_client.describe_db_instances(DBInstanceIdentifier=db_instance_id)
        instance = response["DBInstances"][0]

        if instance.get("StorageEncrypted", False):
            return None  # Compliant

        return Finding(
            control_id="CIS-2.3.1",
            control_name="RDS Storage Encryption Enabled",
            resource_id=db_instance_id,
            details={
                "engine":            instance.get("Engine"),
                "db_instance_class": instance.get("DBInstanceClass"),
                "multi_az":          instance.get("MultiAZ", False),
                "read_replicas":     len(instance.get("ReadReplicaDBInstanceIdentifiers", [])),
                "violation":         "StorageEncrypted is False",
                "remediation_note":  (
                    "BLOCK: RDS encryption cannot be enabled in-place. Requires "
                    "snapshot-copy-restore workflow causing ~45 min downtime. "
                    "A DBA must schedule a maintenance window."
                ),
            }
        )

    except Exception as e:
        logger.error(f"Error checking CIS-2.3.1 for {db_instance_id}: {e}")
        return None


# ── Org-RDS-SG-Chain: Zero-Trust SG Chaining Check ──────────────────────────

def check_rds_sg_chaining(db_instance_id: str, rds_client, ec2_client) -> list:
    """
    Org-RDS-SG-Chain — RDS database port access must be controlled via
    Security Group references (UserIdGroupPairs), NOT raw IP CIDRs (IpRanges).

    Security Group Chaining is the AWS-recommended zero-trust pattern:
      GOOD: Allow inbound MySQL from sg-0abc123 (the App EC2 Security Group)
      BAD:  Allow inbound MySQL from 10.0.0.0/8  (any host in the whole VPC)

    Classification using the existing cidr_classifier:
      - IpRanges with 'internet'    exposure → NON_COMPLIANT  (critical risk)
      - IpRanges with 'restricted'  exposure → NON_COMPLIANT  (specific public IP — must use SG)
      - IpRanges with 'private'     exposure → INFO           (advisory, not a hard block)
      - UserIdGroupPairs only       →           COMPLIANT     (correct pattern)

    Remediation Safety Gate: always BLOCK (cannot safely guess the correct
    replacement SG — a human architect must identify the source application).
    """
    findings = []
    try:
        response  = rds_client.describe_db_instances(DBInstanceIdentifier=db_instance_id)
        instance  = response["DBInstances"][0]
        engine    = instance.get("Engine", "unknown")
        db_port   = instance.get("DbInstancePort") or _default_port(engine)
        sg_groups = instance.get("VpcSecurityGroups", [])
        sg_ids    = [sg["VpcSecurityGroupId"] for sg in sg_groups
                     if sg.get("Status") == "active"]

        if not sg_ids or not ec2_client:
            return findings

        sg_response = ec2_client.describe_security_groups(GroupIds=sg_ids)

        for sg in sg_response.get("SecurityGroups", []):
            sg_id   = sg.get("GroupId")
            sg_name = sg.get("GroupName", "")

            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port   = rule.get("ToPort",   65535)
                protocol  = rule.get("IpProtocol", "")

                # Check if this rule covers the database port
                allows_db_port = (
                    protocol == "-1" or
                    (isinstance(from_port, int) and isinstance(to_port, int)
                     and from_port <= db_port <= to_port)
                )
                if not allows_db_port:
                    continue

                # ── Collect all raw CIDR-based ranges from this rule ────────
                ipv4_cidrs = [r.get("CidrIp", "")  for r in rule.get("IpRanges",  [])]
                ipv6_cidrs = [r.get("CidrIpv6", "") for r in rule.get("Ipv6Ranges", [])]
                all_cidrs  = [c for c in ipv4_cidrs + ipv6_cidrs if c]

                # ── Check how many SG-chained peers exist (the good pattern) ──
                sg_peer_refs = rule.get("UserIdGroupPairs", [])

                if not all_cidrs:
                    # Rule uses only SG references — this is the correct pattern
                    continue

                # Classify the worst-case CIDR exposure
                exposure = classify_cidr_list(all_cidrs)

                if exposure in ("internet", "restricted"):
                    # Hard violation: public or specific external IP used instead of SG
                    status = "NON_COMPLIANT"
                    violation_msg = (
                        f"RDS {engine} port {db_port} on SG {sg_name} ({sg_id}) allows "
                        f"DB access via raw CIDR(s) {all_cidrs} ({exposure} exposure). "
                        f"Zero-trust architecture requires using a Security Group reference "
                        f"(e.g., the app EC2 SG) instead of IP ranges."
                    )
                elif exposure == "private":
                    # Advisory: private CIDRs are safer but still not best practice
                    status = "INFO"
                    violation_msg = (
                        f"RDS {engine} port {db_port} on SG {sg_name} ({sg_id}) uses "
                        f"private CIDR(s) {all_cidrs} — not internet-exposed, but "
                        f"SG chaining (referencing the app EC2 SG) is the recommended "
                        f"zero-trust practice to prevent lateral movement within the VPC."
                    )
                else:
                    continue  # Unknown — skip

                findings.append(Finding(
                    control_id="Org-RDS-SG-Chain",
                    control_name="RDS Security Group Chaining",
                    resource_id=db_instance_id,
                    status=status,
                    details={
                        "engine":         engine,
                        "db_port":        db_port,
                        "sg_id":          sg_id,
                        "sg_name":        sg_name,
                        "cidr_exposure":  exposure,
                        "offending_cidrs": all_cidrs,
                        "sg_peer_refs":   [p.get("GroupId") for p in sg_peer_refs],
                        "violation":      violation_msg,
                        "remediation_note": (
                            "BLOCK: A human architect must identify the source application SG "
                            "and replace the CIDR-based rule with a Security Group reference. "
                            "Cannot auto-remediate — wrong SG guess causes DB connectivity outage."
                        ),
                    }
                ))

    except Exception as e:
        logger.error(f"Error checking Org-RDS-SG-Chain for {db_instance_id}: {e}")

    return findings


def evaluate_all(db_instance_id: str, rds_client, ec2_client=None) -> list:
    """Run in-scope RDS CIS checks for a single DB instance (CIS-2.3.2 and Org-RDS-SG-Chain)."""
    findings = []
    result = check_rds_public_access(db_instance_id, rds_client, ec2_client)
    if result:
        findings.append(result)
    # Org-RDS-SG-Chain: zero-trust SG chaining check (requires ec2_client)
    if ec2_client:
        findings.extend(check_rds_sg_chaining(db_instance_id, rds_client, ec2_client))
    return findings
