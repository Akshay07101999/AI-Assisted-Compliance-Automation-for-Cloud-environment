"""
S3 CIS Controls
  CIS 2.1.4 — Ensure S3 Block Public Access is enabled
"""

from dataclasses import dataclass, field
from typing import Optional
import logging
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    control_id: str
    control_name: str
    resource_id: str
    resource_type: str = "AWS::S3::Bucket"
    status: str = "NON_COMPLIANT"
    details: dict = field(default_factory=dict)
    region: str = "us-east-1"


def check_s3_block_public_access(bucket_name: str, s3_client) -> Optional[Finding]:
    """
    CIS 2.1.4 — S3 Block Public Access
    All four Block Public Access settings must be enabled.
    """
    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        cfg = response["PublicAccessBlockConfiguration"]

        all_blocked = all([
            cfg.get("BlockPublicAcls", False),
            cfg.get("IgnorePublicAcls", False),
            cfg.get("BlockPublicPolicy", False),
            cfg.get("RestrictPublicBuckets", False),
        ])

        if not all_blocked:
            return Finding(
                control_id="CIS-2.1.4",
                control_name="S3 Block Public Access",
                resource_id=bucket_name,
                details={
                    "BlockPublicAcls": cfg.get("BlockPublicAcls", False),
                    "IgnorePublicAcls": cfg.get("IgnorePublicAcls", False),
                    "BlockPublicPolicy": cfg.get("BlockPublicPolicy", False),
                    "RestrictPublicBuckets": cfg.get("RestrictPublicBuckets", False),
                }
            )
        return None  # Compliant

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "")
        if error_code == "NoSuchPublicAccessBlockConfiguration":
            # No config means ALL public access is allowed — definitely non-compliant
            return Finding(
                control_id="CIS-2.1.4",
                control_name="S3 Block Public Access",
                resource_id=bucket_name,
                details={"reason": "No Block Public Access configuration found — all public access allowed"}
            )
        logger.error(f"Error checking CIS-2.1.4 for {bucket_name}: {e}")
        return None
    except Exception as e:
        logger.error(f"Error checking CIS-2.1.4 for {bucket_name}: {e}")
        return None


def evaluate_all(bucket_name: str, s3_client) -> list[Finding]:
    """Run all S3 CIS checks for a single bucket. Returns list of findings."""
    findings = []

    result = check_s3_block_public_access(bucket_name, s3_client)
    if result:
        findings.append(result)

    return findings
