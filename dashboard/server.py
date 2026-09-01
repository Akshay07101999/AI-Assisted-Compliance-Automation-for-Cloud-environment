"""
ComplianceGuard Dashboard Server
=================================
Flask API bridge between the frontend dashboard and the live AWS pipeline.

Endpoints:
  GET  /              → Serve the dashboard HTML
  GET  /api/report    → Return the latest scan_report.json
  POST /api/scan      → Trigger the full orchestrator pipeline against AWS
  GET  /api/status    → Return current scan status (idle / running)

Usage:
  python dashboard/server.py
Then open: http://localhost:5050
"""

import os
import sys
import json
import logging
import threading
import subprocess
import traceback
from datetime import datetime, timezone
from pathlib import Path
from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS

# ── Paths ────────────────────────────────────────────────────────────────────
ROOT          = Path(__file__).resolve().parent.parent   # d:\capstone02
DASHBOARD_DIR = Path(__file__).resolve().parent          # d:\capstone02\dashboard
REPORT_PATH   = ROOT / "scan_report.json"

sys.path.insert(0, str(ROOT))

from decision.remediator import AutoRemediator

# ── Flask App ─────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder=str(DASHBOARD_DIR), static_url_path="")
CORS(app)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ── Scan State ────────────────────────────────────────────────────────────────
scan_state = {
    "status": "idle",          # idle | running | done | error
    "started_at": None,
    "finished_at": None,
    "log_lines": [],
    "error": None,
}
scan_lock = threading.Lock()


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the dashboard index page."""
    return send_from_directory(DASHBOARD_DIR, "index.html")


@app.route("/api/report", methods=["GET"])
def get_report():
    """Return the latest scan_report.json or a 404 with a helpful message."""
    if not REPORT_PATH.exists():
        return jsonify({
            "error": "No report found. Click 'Run Scan' to generate one.",
            "report_path": str(REPORT_PATH)
        }), 404

    try:
        with open(REPORT_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)

        # ── Annotate with current-scan count ─────────────────────────────────
        # _save_report() merges historical findings into every report for audit
        # purposes. The dashboard KPI should show only the CURRENT scan count,
        # not the inflated historical total.
        # We identify current-scan findings as those whose recorded_at / processed_at
        # falls within 5 minutes of the report's generated_at timestamp.
        generated_at = data.get("generated_at", "")
        current_count = 0
        if generated_at:
            from datetime import datetime, timezone, timedelta
            try:
                rpt_ts  = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
                # Findings are always processed BEFORE the report is written.
                # Use a directional 60-minute lookback (finding_ts <= rpt_ts and
                # within 60 minutes) to capture all findings from the current scan
                # regardless of how long the scan took.
                window  = timedelta(minutes=60)
                for f in data.get("findings", []):
                    ts_str = f.get("recorded_at") or f.get("processed_at") or ""
                    if ts_str:
                        try:
                            f_ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                            if f_ts <= rpt_ts and (rpt_ts - f_ts) <= window:
                                current_count += 1
                        except (ValueError, TypeError):
                            pass
            except (ValueError, TypeError):
                pass
        data["current_scan_findings"] = current_count

        return jsonify(data), 200
    except Exception as e:
        logger.error(f"Failed to read report: {e}")
        return jsonify({"error": str(e)}), 500



@app.route("/api/history", methods=["GET"])
def get_history():
    """Return historical audit log entries from audit_log.json."""
    audit_path = ROOT / "audit_log.json"
    if not audit_path.exists():
        return jsonify([]), 200
    try:
        with open(audit_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return jsonify(data), 200
    except Exception as e:
        logger.error(f"Failed to read audit log: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/scan", methods=["POST"])
def trigger_scan():
    """
    Trigger a full orchestrator scan against AWS in a background thread.
    Returns immediately with status 202 Accepted. Poll /api/status for updates.
    """
    with scan_lock:
        if scan_state["status"] == "running":
            return jsonify({"message": "Scan already in progress.", "status": "running"}), 409

        # Reset state
        scan_state["status"]      = "running"
        scan_state["started_at"]  = datetime.now(timezone.utc).isoformat()
        scan_state["finished_at"] = None
        scan_state["log_lines"]   = []
        scan_state["error"]       = None

    thread = threading.Thread(target=_run_orchestrator, daemon=True)
    thread.start()

    return jsonify({"message": "Scan triggered.", "status": "running"}), 202


@app.route("/api/status", methods=["GET"])
def get_status():
    """Return the current scan state."""
    with scan_lock:
        return jsonify(dict(scan_state)), 200


@app.route("/api/remediate", methods=["POST"])
def trigger_remediation():
    """Invoke live AWS remediation for a specific finding."""
    data = request.json or {}
    resource_id = data.get("resource_id")
    finding_id  = data.get("finding_id")   # preferred: pin to exact finding

    if not resource_id:
        return jsonify({"error": "Missing resource_id"}), 400

    try:
        with open(REPORT_PATH, "r", encoding="utf-8") as f:
            report_data = json.load(f)
    except Exception as e:
        return jsonify({"error": f"Failed to load scan_report.json: {e}"}), 500

    findings = report_data.get("findings", [])

    # PIN to the exact finding if finding_id provided (prevents hitting a stale
    # historical record when the same resource appears in multiple past scans).
    if finding_id:
        finding = next((f for f in findings if f.get("finding_id") == finding_id), None)
        if not finding:
            # Caller sent an ID that no longer exists — fall back to resource_id match
            logger.warning(f"[Remediate] finding_id {finding_id!r} not found, falling back to resource_id match")
            finding = next((f for f in findings if f.get("resource_id") == resource_id), None)
    else:
        # Legacy: match on resource_id alone (picks the newest due to sort order in _save_report)
        finding = next((f for f in findings if f.get("resource_id") == resource_id), None)

    if not finding:
        return jsonify({"error": f"Finding not found for {resource_id}"}), 404

    remediator = AutoRemediator()
    try:
        success, msg = remediator.remediate(finding)
        return jsonify({
            "success": success,
            "message": msg
        }), 200 if success else 400
    except Exception as e:
        logger.error(f"[Remediation Error] {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/approve", methods=["POST"])
def approve_finding():
    """
    Administrator approves a PENDING_APPROVAL finding.
    Runs: pre-snapshot → remediate → post-verify → updates scan_report.json.
    """
    data       = request.json or {}
    finding_id = data.get("finding_id")
    if not finding_id:
        return jsonify({"error": "Missing finding_id"}), 400

    try:
        with open(REPORT_PATH, "r", encoding="utf-8") as f:
            report_data = json.load(f)
    except Exception as e:
        return jsonify({"error": f"Failed to load scan_report.json: {e}"}), 500

    findings = report_data.get("findings", [])
    finding  = next((f for f in findings if f.get("finding_id") == finding_id), None)
    if not finding:
        return jsonify({"error": f"Finding {finding_id} not found"}), 404

    if finding.get("status") not in ("PENDING_APPROVAL", "NON_COMPLIANT"):
        return jsonify({"error": f"Finding is not pending approval (status={finding.get('status')})"}), 409

    remediator  = AutoRemediator()
    control_id  = finding.get("control_id", "")
    resource_id = finding.get("resource_id", "")
    context     = finding.get("context", {})
    approved_at = datetime.now(timezone.utc).isoformat()

    try:
        # ── 1. Pre-Change Snapshot ────────────────────────────────────────────
        pre_state = remediator.capture_pre_remediation_state(control_id, resource_id)

        # ── 2. Execute Remediation ────────────────────────────────────────────
        success, msg = remediator.remediate(finding)

        # ── 3. Post-Remediation Re-Verification ──────────────────────────────
        post_compliant, post_state = (False, {}) if not success else \
            remediator.verify_post_remediation(control_id, resource_id, context=context)

        # ── 4. Update finding in report ───────────────────────────────────────
        final_status = "COMPLIANT" if (success and post_compliant) else "VERIFICATION_FAILED"

        finding["status"]          = final_status
        finding["approved_by"]     = data.get("approved_by", "dashboard-admin")
        finding["approved_at"]     = approved_at
        finding["auto_remediation"] = {
            "status":                 final_status,
            "message":                msg,
            "pre_remediation_state":  pre_state,
            "post_remediation_state": post_state,
        }

        with open(REPORT_PATH, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, default=str)

        return jsonify({
            "success":         success and post_compliant,
            "status":          final_status,
            "message":               msg,
            "post_compliant":        post_compliant,
            "observed_state":        post_state.get("observed_state", {}),
            "verified_at":           post_state.get("verified_at", ""),
            "pre_remediation_state": pre_state,
        }), 200

    except Exception as e:
        logger.error(f"[Approve Error] {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/rollback", methods=["POST"])
def rollback_finding():
    """
    Administrator rolls back a remediated finding to its pre-remediation state.
    Executes reverse AWS API calls and updates scan_report.json.
    """
    data        = request.json or {}
    finding_id  = data.get("finding_id")
    resource_id = data.get("resource_id")

    if not finding_id and not resource_id:
        return jsonify({"error": "Missing finding_id or resource_id"}), 400

    try:
        with open(REPORT_PATH, "r", encoding="utf-8") as f:
            report_data = json.load(f)
    except Exception as e:
        return jsonify({"error": f"Failed to load scan_report.json: {e}"}), 500

    findings = report_data.get("findings", [])
    finding = None
    if finding_id:
        finding = next((f for f in findings if f.get("finding_id") == finding_id), None)
    if not finding and resource_id:
        finding = next((f for f in findings if f.get("resource_id") == resource_id), None)

    if not finding:
        return jsonify({"error": f"Finding not found for {finding_id or resource_id}"}), 404

    remediator = AutoRemediator()
    try:
        success, msg = remediator.rollback(finding)
        if success:
            finding["status"] = "ROLLED_BACK"
            if "auto_remediation" not in finding or not isinstance(finding["auto_remediation"], dict):
                finding["auto_remediation"] = {}
            finding["auto_remediation"]["status"] = "ROLLED_BACK"
            finding["auto_remediation"]["message"] = f"Rolled back: {msg}"
            finding["rolled_back_at"] = datetime.now(timezone.utc).isoformat()
            finding["rolled_back_by"] = data.get("rolled_back_by", "dashboard-admin")

            with open(REPORT_PATH, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2, default=str)

            return jsonify({
                "success": True,
                "message": msg,
                "status":  "ROLLED_BACK"
            }), 200
        else:
            return jsonify({
                "success": False,
                "error":   msg
            }), 400
    except Exception as e:
        logger.error(f"[Rollback Error] {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/deny", methods=["POST"])
def deny_finding():
    """
    Administrator denies a PENDING_APPROVAL finding.
    Marks the finding as DENIED and persists the decision.
    """
    data       = request.json or {}
    finding_id = data.get("finding_id")
    reason     = data.get("reason", "Denied by administrator.")
    if not finding_id:
        return jsonify({"error": "Missing finding_id"}), 400

    try:
        with open(REPORT_PATH, "r", encoding="utf-8") as f:
            report_data = json.load(f)
    except Exception as e:
        return jsonify({"error": f"Failed to load scan_report.json: {e}"}), 500

    findings = report_data.get("findings", [])
    finding  = next((f for f in findings if f.get("finding_id") == finding_id), None)
    if not finding:
        return jsonify({"error": f"Finding {finding_id} not found"}), 404

    finding["status"]    = "DENIED"
    finding["denied_by"] = data.get("denied_by", "dashboard-admin")
    finding["denied_at"] = datetime.now(timezone.utc).isoformat()
    finding["deny_reason"] = reason

    try:
        with open(REPORT_PATH, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, default=str)
        return jsonify({"success": True, "status": "DENIED"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Exception Registry Endpoints ──────────────────────────────────────────────

@app.route("/api/exceptions", methods=["GET"])
def get_exceptions():
    """Return all exceptions registered in the governance store."""
    try:
        from governance.exception_registry import ExceptionRegistry
        reg = ExceptionRegistry()
        items = reg.list_all()
        return jsonify(items), 200
    except Exception as e:
        logger.error(f"Failed to fetch exceptions: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/exceptions", methods=["POST"])
def create_exception():
    """
    Create a new compliance waiver/exception and persist to exceptions.json.
    Optionally updates the corresponding finding in scan_report.json.
    """
    data          = request.json or {}
    resource_id   = data.get("resource_id", "").strip()
    control_id    = data.get("control_id", "").strip()
    justification = data.get("justification", "").strip()
    business_owner = data.get("business_owner", "secops@company.com").strip()
    approved_by   = data.get("approved_by", "ciso@company.com").strip()
    finding_id    = data.get("finding_id")

    try:
        days = int(data.get("days", 30))
    except (ValueError, TypeError):
        days = 30

    if not resource_id or not control_id or not justification:
        return jsonify({"error": "Missing required fields: resource_id, control_id, and justification are mandatory."}), 400

    try:
        from governance.exception_registry import ExceptionRegistry
        reg = ExceptionRegistry()
        new_exc = reg.add_exception(
            resource_id=resource_id,
            control_id=control_id,
            justification=justification,
            business_owner=business_owner or "secops@company.com",
            approved_by=approved_by or "ciso@company.com",
            days=days,
        )

        # Update finding status in scan_report.json if it exists
        if REPORT_PATH.exists():
            try:
                with open(REPORT_PATH, "r", encoding="utf-8") as f:
                    report_data = json.load(f)

                updated = False
                for finding in report_data.get("findings", []):
                    matched = False
                    if finding_id and finding.get("finding_id") == finding_id:
                        matched = True
                    elif finding.get("resource_id") == resource_id and finding.get("control_id") == control_id:
                        matched = True

                    if matched:
                        finding["status"] = "EXCEPTED"
                        finding["exception"] = new_exc
                        finding["auto_remediation"] = {
                            "status": "skipped",
                            "message": f"Active exception granted: {justification} (Expires {new_exc.get('expiry_date')})"
                        }
                        updated = True

                if updated:
                    with open(REPORT_PATH, "w", encoding="utf-8") as f:
                        json.dump(report_data, f, indent=2, default=str)
            except Exception as err:
                logger.warning(f"Could not update scan_report.json finding to EXCEPTED: {err}")

        return jsonify({
            "success": True,
            "message": f"Exception {new_exc.get('exception_id')} successfully granted.",
            "exception": new_exc
        }), 201

    except Exception as e:
        logger.error(f"Failed to create exception: {traceback.format_exc()}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/exceptions/revoke", methods=["POST"])
def revoke_exception_route():
    """Revoke an active compliance exception by exception_id."""
    data = request.json or {}
    exception_id = data.get("exception_id")
    if not exception_id:
        return jsonify({"error": "Missing exception_id"}), 400

    try:
        from governance.exception_registry import ExceptionRegistry
        reg = ExceptionRegistry()
        success = reg.revoke_exception(exception_id)
        if success:
            return jsonify({"success": True, "message": f"Exception {exception_id} revoked."}), 200
        else:
            return jsonify({"error": f"Exception {exception_id} not found."}), 404
    except Exception as e:
        logger.error(f"Failed to revoke exception: {e}")
        return jsonify({"error": str(e)}), 500




# ── Background Task ───────────────────────────────────────────────────────────

def _run_orchestrator():
    """
    Executes the ComplianceGuard orchestrator in a subprocess so it doesn't
    block the Flask server. Captures stdout/stderr for the status endpoint.
    """
    cmd = [sys.executable, str(ROOT / "decision" / "orchestrator.py")]
    logger.info(f"[Scan] Starting: {' '.join(cmd)}")

    try:
        # Ensure Python forces UTF-8 output to stdout so Windows doesn't crash on arrows (→)
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"

        proc = subprocess.Popen(
            cmd,
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env
        )

        for line in proc.stdout:
            line = line.rstrip()
            if line:
                logger.info(f"[Orchestrator] {line}")
                with scan_lock:
                    scan_state["log_lines"].append(line)

        proc.wait()

        with scan_lock:
            scan_state["finished_at"] = datetime.now(timezone.utc).isoformat()
            if proc.returncode == 0:
                scan_state["status"] = "done"
                logger.info("[Scan] Completed successfully.")
            else:
                scan_state["status"] = "error"
                scan_state["error"]  = f"Orchestrator exited with code {proc.returncode}"
                logger.error(f"[Scan] Failed. Exit code: {proc.returncode}")

    except Exception as e:
        logger.error(f"[Scan] Exception: {e}")
        logger.error(traceback.format_exc())
        with scan_lock:
            scan_state["status"]      = "error"
            scan_state["finished_at"] = datetime.now(timezone.utc).isoformat()
            scan_state["error"]       = str(e)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  ComplianceGuard Dashboard Server")
    print("  http://localhost:5050")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5050, debug=False)
