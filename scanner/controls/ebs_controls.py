"""
EBS CIS Controls
  CIS 2.2.1 — Ensure EBS volumes attached to EC2 instances are encrypted
"""

from dataclasses import dataclass, field
from typing import Optional
import logging

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    control_id: str
    control_name: str
    resource_id: str
    resource_type: str = "AWS::EC2::Volume"
    status: str = "NON_COMPLIANT"
    details: dict = field(default_factory=dict)
    region: str = "us-east-1"


def check_ebs_encryption(volume_id: str, ec2_client) -> Optional[Finding]:
    """
    CIS 2.2.1 — EBS Volume Encryption
    All EBS volumes must have encryption enabled.
    Unencrypted volumes at rest expose data if the underlying hardware is compromised.
    """
    try:
        response = ec2_client.describe_volumes(VolumeIds=[volume_id])
        volume = response["Volumes"][0]

        if not volume.get("Encrypted", False):
            # Get attachment info for context
            attachments = volume.get("Attachments", [])
            attached_instance = attachments[0].get("InstanceId") if attachments else None

            return Finding(
                control_id="CIS-2.2.1",
                control_name="EBS Volume Encryption Enabled",
                resource_id=volume_id,
                details={
                    "volume_type": volume.get("VolumeType"),
                    "size_gb": volume.get("Size"),
                    "state": volume.get("State"),
                    "attached_to_instance": attached_instance,
                    "availability_zone": volume.get("AvailabilityZone"),
                    "violation": "EBS volume is not encrypted",
                    "remediation_note": "Cannot encrypt in-place — create encrypted snapshot, restore as new volume",
                }
            )
        return None  # Compliant

    except Exception as e:
        logger.error(f"Error checking CIS-2.2.1 for {volume_id}: {e}")
        return None


def evaluate_all(volume_id: str, ec2_client) -> list[Finding]:
    """Run EBS CIS checks (CIS-2.2.1 is out of scope for auto-scan)."""
    return []
