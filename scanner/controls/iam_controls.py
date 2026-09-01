"""
IAM CIS Controls
  CIS-1.14 — Ensure IAM access keys are rotated every 90 days or less

Scan logic:
  1. List all IAM users
  2. For each user, list access keys
  3. If any active key is older than 90 days  → Finding
  4. For each stale key, fetch the last-used date to determine blast radius:
       - Not used in 15+ days  → safe to auto-deactivate (dormant key)
       - Used within 15 days   → BLOCK (active live key, human must rotate)
       - Never used            → safe to auto-deactivate (never activated)
       - Last-used unknown     → BLOCK (fail-safe worst case)
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import logging

logger = logging.getLogger(__name__)

# Policy thresholds
ACCESS_KEY_MAX_AGE_DAYS = 90   # CIS-1.14: flag keys older than 90 days
KEY_DORMANT_DAYS        = 15   # Keys unused for this many days are safe to deactivate
KEY_NEW_GRACE_DAYS      = 2    # Keys created within this many days are never auto-deactivated


@dataclass
class Finding:
    control_id:    str
    control_name:  str
    resource_id:   str                      # Format: {username}/key/{access_key_id}
    resource_type: str = "AWS::IAM::User"
    status:        str = "NON_COMPLIANT"
    details:       dict = field(default_factory=dict)
    region:        str  = "global"          # IAM is a global service


def _days_old(dt: datetime) -> int:
    """Return how many days ago a datetime was (UTC-aware)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - dt).days


def check_access_key_rotation(username: str, iam_client) -> list:
    """
    CIS-1.14 — IAM Access Key Rotation (90 days)

    Returns a list of Findings (one per stale, active key on the user).
    Each finding carries:
      - is_dormant: True  → gate will AUTO deactivate
      - is_dormant: False → gate will BLOCK and escalate to human
    """
    findings = []
    try:
        response = iam_client.list_access_keys(UserName=username)
        keys = response.get("AccessKeyMetadata", [])

        for key in keys:
            key_id  = key["AccessKeyId"]
            status  = key["Status"]      # 'Active' or 'Inactive'
            created = key["CreateDate"]
            key_age = _days_old(created)

            # Only flag Active keys — inactive keys are already disabled
            if status != "Active":
                continue

            if key_age <= ACCESS_KEY_MAX_AGE_DAYS:
                continue    # Compliant — within rotation window

            # ── Key is stale — determine last-used date for blast radius ──
            last_used_days    = None   # None means never used
            last_used_service = None
            fetch_failed      = False

            try:
                lu_resp    = iam_client.get_access_key_last_used(AccessKeyId=key_id)
                lu_info    = lu_resp.get("AccessKeyLastUsed", {})
                lu_date    = lu_info.get("LastUsedDate")
                if lu_date:
                    last_used_days    = _days_old(lu_date)
                    last_used_service = lu_info.get("ServiceName", "unknown")
                # If lu_date is None, the key was never used → last_used_days stays None
            except Exception as e:
                logger.warning(f"Could not fetch last-used for key {key_id}: {e}")
                fetch_failed = True

            # Determine dormancy:
            #   brand-new (<= 2d)    → NOT dormant (grace period — key hasn't had time to be used)
            #   never used   (None)  → dormant (safe) — but only if old enough
            #   used > 15d ago       → dormant (safe)
            #   used < 15d ago       → active  (BLOCK)
            #   fetch failed         → treat as active (fail-safe)
            if fetch_failed:
                is_dormant = False
            elif key_age <= KEY_NEW_GRACE_DAYS:
                # Brand-new key — never auto-deactivate, it hasn't had time to be used
                is_dormant = False
            elif last_used_days is None:
                is_dormant = True    # Never used AND old enough — safe to deactivate
            else:
                is_dormant = last_used_days >= KEY_DORMANT_DAYS

            findings.append(Finding(
                control_id="CIS-1.14",
                control_name="IAM Access Key Rotation",
                resource_id=f"{username}/key/{key_id}",
                details={
                    "username":          username,
                    "access_key_id":     key_id,
                    "key_age_days":      key_age,
                    "last_used_days":    last_used_days,
                    "last_used_service": last_used_service,
                    "is_dormant":        is_dormant,
                    "violation": (
                        f"Active access key is {key_age} days old "
                        f"(max allowed: {ACCESS_KEY_MAX_AGE_DAYS} days)."
                    ),
                    "remediation_note": (
                        (
                            # Flaw 5 fix: branched string — never-used vs dormant
                            "SAFE TO AUTO-DEACTIVATE: key was never used — zero disruption risk."
                            if last_used_days is None
                            else f"SAFE TO AUTO-DEACTIVATE: key has not been used in {last_used_days} days."
                        )
                        if is_dormant
                        else (
                            f"BLOCK: key was used {last_used_days} day(s) ago "
                            f"by service '{last_used_service}'. "
                            "Auto-deactivation would break a live application."
                        )
                    ),
                }
            ))

    except Exception as e:
        logger.error(f"Error checking CIS-1.14 for user {username}: {e}")

    return findings


def evaluate_all(username: str, iam_client) -> list:
    """Run all IAM CIS checks for a single IAM user."""
    return check_access_key_rotation(username, iam_client)
