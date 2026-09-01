"""
ComplianceGuard — Exception Registry

Replaces hardcoded business exceptions in the Remediation Safety Gate with a formally
governed lookup. Every exception requires:
  - A named business owner
  - A documented justification
  - A named approver (CISO / Security Lead)
  - A hard expiry date (time-bound)

In production: backed by DynamoDB.
In this capstone: backed by exceptions.json in the governance/ directory.

Format of exceptions.json:
[
  {
    "resource_id":   "arn:aws:s3:::marketing-site",
    "control_id":    "CIS-2.1.4",
    "justification": "Public marketing website serving static HTML",
    "business_owner": "john.doe@company.com",
    "approved_by":   "ciso@company.com",
    "approved_date": "2026-07-01",
    "expiry_date":   "2026-10-01"
  }
]
"""

import json
import logging
import os
from datetime import date, datetime, timezone
from typing import Optional


logger = logging.getLogger(__name__)

# Path to the flat-file exception store (simulates DynamoDB for capstone)
_REGISTRY_PATH = os.path.join(os.path.dirname(__file__), "exceptions.json")


class ExceptionRegistry:
    """
    Governs compliance exceptions formally.
    Exceptions are time-bound. Expired entries are automatically treated
    as live violations — the Remediation Safety Gate will no longer suppress them.
    """

    def __init__(self, registry_path: str = _REGISTRY_PATH):
        self.registry_path = registry_path
        self._exceptions: list = []
        self._load()

    # ── Internal ──────────────────────────────────────────────────────────

    def _load(self):
        """Load exceptions from the JSON store."""
        if not os.path.exists(self.registry_path):
            self._exceptions = []
            return
        try:
            with open(self.registry_path, "r") as f:
                self._exceptions = json.load(f)
        except Exception as e:
            logger.error(f"ExceptionRegistry: failed to load {self.registry_path}: {e}")
            self._exceptions = []

    def _today(self) -> date:
        return datetime.now(timezone.utc).date()


    # ── Public API ────────────────────────────────────────────────────────

    def get_active_exception(
        self, resource_id: str, control_id: str
    ) -> Optional[dict]:
        """
        Returns the active (non-expired) exception record for this
        resource + control combination, or None if no valid exception exists.

        An exception is INACTIVE if:
          - It does not exist in the registry, OR
          - Its expiry_date has passed (auto-promoted back to live violation)
        """
        self._load()  # Reload on every call so changes to JSON are live
        today = self._today()

        for exc in self._exceptions:
            if exc.get("resource_id") == resource_id and exc.get("control_id") == control_id:
                try:
                    expiry = date.fromisoformat(exc["expiry_date"])
                except (KeyError, ValueError):
                    logger.warning(
                        f"ExceptionRegistry: malformed expiry_date for "
                        f"{resource_id}/{control_id} — treating as expired."
                    )
                    return None

                if expiry >= today:
                    logger.info(
                        f"ExceptionRegistry: active exception found for "
                        f"{resource_id}/{control_id} "
                        f"(expires {exc['expiry_date']}, "
                        f"approved by {exc.get('approved_by', 'unknown')})"
                    )
                    return exc
                else:
                    logger.warning(
                        f"ExceptionRegistry: EXPIRED exception for "
                        f"{resource_id}/{control_id} "
                        f"(expired {exc['expiry_date']}) — "
                        f"treating as live violation."
                    )
                    return None  # Expired = no longer an exception

        return None  # No record = no exception

    def build_exception_reason(self, exc: dict) -> str:
        """Format a human-readable reason string for audit logs."""
        return (
            f"Approved exception: \"{exc.get('justification', 'N/A')}\" "
            f"| Owner: {exc.get('business_owner', 'N/A')} "
            f"| Approved by: {exc.get('approved_by', 'N/A')} "
            f"| Expires: {exc.get('expiry_date', 'N/A')}"
        )

    # ── Write API ─────────────────────────────────────────────────────────

    def _save(self):
        """Persist the in-memory exception list back to the JSON store."""
        try:
            with open(self.registry_path, "w", encoding="utf-8") as f:
                json.dump(self._exceptions, f, indent=2)
        except Exception as e:
            logger.error(f"ExceptionRegistry: failed to save {self.registry_path}: {e}")

    def add_exception(
        self,
        resource_id:    str,
        control_id:     str,
        justification:  str,
        business_owner: str  = "admin",
        approved_by:    str  = "admin",
        days:           int  = 30,
    ) -> dict:
        """
        Create a new time-bound exception and persist it to exceptions.json.

        Returns the newly created exception dict.
        """
        from datetime import timedelta
        today       = self._today()
        expiry      = today + timedelta(days=days)
        exception_id = (
            f"EXC-{today.strftime('%Y%m%d')}-"
            f"{str(len(self._exceptions) + 1).zfill(3)}"
        )

        new_exc = {
            "exception_id":   exception_id,
            "resource_id":    resource_id,
            "control_id":     control_id,
            "justification":  justification,
            "business_owner": business_owner,
            "approved_by":    approved_by,
            "approved_date":  today.isoformat(),
            "expiry_date":    expiry.isoformat(),
            "status":         "active",
        }

        # Remove any previous (expired) entry for the same resource+control
        self._exceptions = [
            e for e in self._exceptions
            if not (e.get("resource_id") == resource_id
                    and e.get("control_id") == control_id)
        ]
        self._exceptions.append(new_exc)
        self._save()

        logger.info(
            f"ExceptionRegistry: new exception {exception_id} granted for "
            f"{resource_id}/{control_id} — expires {expiry.isoformat()}"
        )
        return new_exc

    def revoke_exception(self, exception_id: str) -> bool:
        """
        Mark an exception as revoked by ID.
        Returns True if found and revoked, False if not found.
        """
        self._load()
        for exc in self._exceptions:
            if exc.get("exception_id") == exception_id:
                exc["status"] = "revoked"
                self._save()
                logger.info(f"ExceptionRegistry: exception {exception_id} revoked.")
                return True
        logger.warning(f"ExceptionRegistry: exception {exception_id} not found.")
        return False

    def list_all(self) -> list:
        """
        Return all exceptions (active, expired, revoked) with their
        computed live status (auto-refreshes expiry check).
        """
        self._load()
        today = self._today()
        result = []
        for exc in self._exceptions:
            if exc.get("_comment"):   # skip example/comment entries
                continue
            exc_copy = dict(exc)
            try:
                expiry = date.fromisoformat(exc["expiry_date"])
                if exc_copy.get("status") != "revoked":
                    exc_copy["status"] = "active" if expiry >= today else "expired"
            except (KeyError, ValueError):
                exc_copy["status"] = "unknown"
            result.append(exc_copy)
        return result

