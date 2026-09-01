"""
ComplianceGuard — Governance & Audit Logger

Validation and Governance Layer (as per architecture diagram):
  - Validates remediation effectiveness
  - Maintains audit trail of all findings and actions
  - Updates compliance status per resource
  - Emits structured records for downstream alerting / dashboards
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# ── Audit log path ────────────────────────────────────────────────────────────
ROOT      = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUDIT_LOG = os.path.join(ROOT, "audit_log.json")


class AuditLogger:
    """
    Maintains a structured JSON audit trail for every compliance finding
    processed by the pipeline — regardless of risk level or outcome.
    """

    def __init__(self, log_path: str = AUDIT_LOG):
        self.log_path = log_path
        self._records: list[dict] = self._load_existing()
        logger.info(
            f"[AuditLogger] Initialised — {len(self._records)} existing records "
            f"loaded from {self.log_path}"
        )

    # ── Public API ────────────────────────────────────────────────────────────

    def record(self, processed_finding: dict) -> dict:
        """
        Record a processed finding into the audit log.

        Args:
            processed_finding: Enriched finding dict from the orchestrator

        Returns:
            The audit record that was written
        """
        risk       = processed_finding.get("risk", {})
        auto_rem   = processed_finding.get("auto_remediation")
        llm_anal   = processed_finding.get("llm_analysis")

        # Determine action taken
        if llm_anal is not None:
            action = "LLM_ESCALATION"
        elif auto_rem is not None:
            status = auto_rem.get("status", "unknown")
            action = f"AUTO_REMEDIATION_{status.upper()}"
        else:
            action = "NO_ACTION"

        audit_record = {
            "audit_id":         self._generate_audit_id(),
            "timestamp":        datetime.now(timezone.utc).isoformat(),
            "control_id":       processed_finding.get("control_id", ""),
            "control_name":     processed_finding.get("control_name", ""),
            "resource_id":      processed_finding.get("resource_id", ""),
            "resource_type":    processed_finding.get("resource_type", ""),
            "region":           processed_finding.get("region", ""),
            "status":           processed_finding.get("status", "NON_COMPLIANT"),
            "risk_level":       risk.get("risk_level", "UNKNOWN"),
            "risk_pct":         risk.get("risk_pct", 0),
            "raw_score":        risk.get("raw_score", 0),
            "score_breakdown":  risk.get("breakdown", {}),
            "action_taken":     action,
            "remediation_msg":  (auto_rem or {}).get("message", ""),
            "llm_invoked":      llm_anal is not None,
            "compliance_status": self._derive_compliance_status(action, auto_rem),
        }

        self._records.append(audit_record)
        self._persist()

        logger.info(
            f"[AuditLogger] Recorded: {audit_record['audit_id']} — "
            f"{audit_record['control_id']} on {audit_record['resource_id']} "
            f"({audit_record['risk_level']}) → {action}"
        )
        return audit_record

    def record_batch(self, processed_findings: list) -> list:
        """Record all findings from a pipeline run."""
        return [self.record(f) for f in processed_findings]

    def get_compliance_summary(self) -> dict:
        """
        Return a summary of current compliance posture across all
        resources seen in the audit log.
        """
        if not self._records:
            return {"total_records": 0, "message": "No audit records yet."}

        by_level    = {}
        by_action   = {}
        by_resource = {}

        for rec in self._records:
            level  = rec.get("risk_level", "UNKNOWN")
            action = rec.get("action_taken", "UNKNOWN")
            rid    = rec.get("resource_id", "unknown")

            by_level[level]   = by_level.get(level, 0) + 1
            by_action[action] = by_action.get(action, 0) + 1

            # Track last known status per resource
            by_resource[rid] = {
                "resource_type":     rec.get("resource_type", ""),
                "last_control_id":   rec.get("control_id", ""),
                "last_risk_level":   level,
                "last_action":       action,
                "compliance_status": rec.get("compliance_status", "NON_COMPLIANT"),
                "last_seen":         rec.get("timestamp", ""),
            }

        return {
            "total_records":      len(self._records),
            "by_risk_level":      by_level,
            "by_action":          by_action,
            "resources_tracked":  len(by_resource),
            "resource_statuses":  by_resource,
        }

    def get_records(
        self,
        risk_level: Optional[str] = None,
        resource_id: Optional[str] = None,
    ) -> list:
        """Query audit records with optional filters."""
        records = self._records
        if risk_level:
            records = [r for r in records if r.get("risk_level") == risk_level.upper()]
        if resource_id:
            records = [r for r in records if r.get("resource_id") == resource_id]
        return records

    # ── Private helpers ───────────────────────────────────────────────────────

    def _derive_compliance_status(
        self, action: str, auto_rem: Optional[dict]
    ) -> str:
        """
        Derive the post-action compliance status for the resource.

        - AUTO_REMEDIATION_SUCCESS  → REMEDIATED
        - AUTO_REMEDIATION_FAILED   → NON_COMPLIANT (still)
        - LLM_ESCALATION            → PENDING_REVIEW
        - NO_ACTION                 → NON_COMPLIANT
        """
        if action.startswith("AUTO_REMEDIATION"):
            if auto_rem and auto_rem.get("status") == "success":
                return "REMEDIATED"
            return "NON_COMPLIANT"
        if action == "LLM_ESCALATION":
            return "PENDING_REVIEW"
        return "NON_COMPLIANT"

    def _generate_audit_id(self) -> str:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
        return f"AUDIT-{ts}"

    def _load_existing(self) -> list:
        """Load any pre-existing audit records from disk."""
        if not os.path.exists(self.log_path):
            return []
        try:
            with open(self.log_path, "r") as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except (json.JSONDecodeError, IOError):
            return []

    def _persist(self):
        """Write current records back to disk."""
        try:
            with open(self.log_path, "w") as f:
                json.dump(self._records, f, indent=2, default=str)
        except IOError as e:
            logger.error(f"[AuditLogger] Failed to persist audit log: {e}")
