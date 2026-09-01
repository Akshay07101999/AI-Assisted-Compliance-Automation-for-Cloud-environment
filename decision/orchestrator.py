"""

ComplianceGuard — Decision Orchestrator



Pipeline per finding:

  1. Scanner detects a CIS violation

  2. ContextCollector queries AWS APIs for full resource snapshot

  3. Operational Risk Score deterministically scores using the formula:

        Risk % = (Severity + Environment + Data Sensitivity) / 50 × 100   [MAX_SCORE=50]

        Bands: 0–25% → LOW | >25–50% → MEDIUM | >50–75% → HIGH | >75–100% → CRITICAL

        Dependencies are NOT in the score — they feed the Safety Gate only.

  4. Remediation Safety Gate evaluates operational safety of auto-fixing

  5. Decision:

        LOW / MEDIUM  (0–50%)  → Auto-remediate via boto3 + notify user

        HIGH / CRITICAL(51%+)  → LLM Root Cause Analysis → Alert admin for review



No RAG. No vector store. Context comes directly from live AWS APIs.

"""



import sys

if sys.stdout and not sys.stdout.encoding.lower().startswith('utf-8'):

    sys.stdout.reconfigure(encoding='utf-8')

import os

import json

import logging

from datetime import datetime, timezone



ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

if ROOT not in sys.path:

    sys.path.insert(0, ROOT)



from scanner.scanner import ComplianceScanner

from context.context_collector import ContextCollector

from decision.remediator import AutoRemediator

from ai import risk_scorer

from ai.llm_client import LLMClient



class CleanCLIFormatter(logging.Formatter):

    def format(self, record):

        if record.levelno == logging.INFO:

            return record.getMessage()

        return super().format(record)



root_logger = logging.getLogger()

root_logger.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)

handler.setFormatter(CleanCLIFormatter("%(asctime)s [%(levelname)s] %(module)s — %(message)s"))

root_logger.handlers = [handler]



# Suppress verbose third-party credentials logs

logging.getLogger("botocore").setLevel(logging.WARNING)

logging.getLogger("boto3").setLevel(logging.WARNING)

logging.getLogger("urllib3").setLevel(logging.WARNING)



logger = logging.getLogger(__name__)



# ── Constants ─────────────────────────────────────────────────────────────────

SERVICES_IN_SCOPE = ["s3", "iam", "ec2", "rds"]

REPORT_PATH = os.path.join(ROOT, "scan_report.json")



# Risk levels that trigger LLM analysis (not auto-remediated)

LLM_ESCALATION_LEVELS = {"HIGH", "CRITICAL"}





class Orchestrator:

    """

    Main ComplianceGuard pipeline orchestrator.



    Runs a compliance scan and routes each finding:

    - LOW/MEDIUM  → AutoRemediator (boto3) + user notification

    - HIGH/CRITICAL → LLMClient (RCA + remediation plan) + admin alert

    """



    def __init__(

        self,

        region: str = "us-east-1",

        profile: str = None,

        services: list = None,

        dry_run: bool = False,

    ):

        self.region    = region

        self.services  = services or SERVICES_IN_SCOPE

        self.dry_run   = dry_run

        self.skip_scan = getattr(self, 'skip_scan', False) # Set below if passed



        logger.info(

            f"Initialising ComplianceGuard Orchestrator — "

            f"region={region}, services={self.services}, dry_run={dry_run}"

        )



        import boto3

        session = (

            boto3.Session(profile_name=profile, region_name=region)

            if profile

            else boto3.Session(region_name=region)

        )



        self.scanner    = ComplianceScanner(region=region, profile=profile)

        self.collector  = ContextCollector(region=region, session=session)

        self.remediator = AutoRemediator(region=region)

        self.llm        = LLMClient()



    # ═══════════════════════════════════════════════════════════════════════════

    #  MAIN ENTRY POINT

    # ═══════════════════════════════════════════════════════════════════════════



    def run(self) -> dict:

        """Execute the full end-to-end compliance pipeline."""

        logger.info("=" * 65)

        logger.info("ComplianceGuard Pipeline — START")

        logger.info("=" * 65)



        # Step 1: Scan

        if getattr(self, 'skip_scan', False):

            logger.info(f"\n[STEP 1] Skipping scan: loading existing {REPORT_PATH}")

            if not os.path.exists(REPORT_PATH):

                logger.error(f"Cannot skip scan: {REPORT_PATH} not found.")

                return {}

            with open(REPORT_PATH, 'r', encoding='utf-8') as fh:

                existing_report = json.load(fh)

            raw_findings = [f for f in existing_report.get("findings", []) if f.get("status") == "NON_COMPLIANT"]

            scan_result = None  # Handled in _build_report

            logger.info(f"[STEP 1] Complete — Loaded {len(raw_findings)} existing finding(s)")

        else:

            logger.info(f"\n[STEP 1] Scanning: {self.services}")

            scan_result  = self.scanner.run_full_scan(services=self.services)

            raw_findings = scan_result.findings

            logger.info(f"[STEP 1] Complete — {len(raw_findings)} finding(s) detected")



            if not raw_findings:

                logger.info("No findings — environment is fully compliant \u2713")

                return self._build_report([], scan_result)



        # Step 2: Pre-process — detect combined violations on the same resource

        self._inject_coexisting_violations(raw_findings)



        # ── Step 3: Process findings — PARALLEL via ThreadPoolExecutor ──────────
        #
        # boto3 (EC2, S3, RDS, CloudTrail, CloudWatch Logs) and NVIDIA NIM HTTP
        # calls are IO-bound and release the GIL. Running MAX_WORKERS findings
        # concurrently compresses wall-clock time from sum(all) → max(single).
        #
        # Thread safety:
        #  • _process_finding writes only to its own local `enriched` dict.
        #  • boto3 clients are thread-safe (per-call connection pooling).
        #  • remediator.followup_findings is shared; protected by _followup_lock.

        import threading
        from concurrent.futures import ThreadPoolExecutor, as_completed

        MAX_WORKERS = 4
        logger.info(
            f"\n[STEP 2] Processing {len(raw_findings)} finding(s) "
            f"(parallel, max_workers={MAX_WORKERS})..."
        )

        _followup_lock = threading.Lock()
        processed = []

        def _process_one(idx_finding):
            idx, finding = idx_finding
            logger.info(
                f"\n  [{idx}/{len(raw_findings)}] "
                f"{finding['control_id']} on {finding['resource_id']}"
            )
            result = self._process_finding(finding)

            # Drain followup_findings raised during this call (thread-safe)
            with _followup_lock:
                followups = list(self.remediator.followup_findings)
                self.remediator.followup_findings.clear()

            fup_built = []
            for followup in followups:
                fup = self._build_followup_finding(followup)
                fup_built.append(fup)
                logger.info(
                    f"  \u2139 [FOLLOWUP] {followup['control_id']} raised for "
                    f"{followup['resource_id']} — "
                    f"{followup.get('details', {}).get('migration_action', '')}"
                )
            return result, fup_built

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(_process_one, (i, finding)): i
                for i, finding in enumerate(raw_findings, 1)
            }
            results_by_idx = {}
            followups_by_idx = {}
            for future in as_completed(futures):
                idx = futures[future]
                try:
                    result, fups = future.result()
                    results_by_idx[idx] = result
                    followups_by_idx[idx] = fups
                except Exception as exc:
                    logger.error(f"  [PARALLEL] Finding {idx} raised an exception: {exc}")

        # Reassemble in original submission order so report is deterministic
        for idx in sorted(results_by_idx):
            processed.append(results_by_idx[idx])
            processed.extend(followups_by_idx.get(idx, []))

        # Step 4: Build & save report

        logger.info("\n[STEP 3] Building report...")

        report = self._build_report(processed, scan_result)

        self._save_report(report)

        self._print_summary(report)

        return report


    def _inject_coexisting_violations(self, findings: list):

        """

        Pre-scan all findings to detect when the same resource has multiple

        active violations. Injects a 'coexisting_violations' list into each

        finding so the risk scorer can apply a compound-risk modifier.



        Example: An S3 bucket that is BOTH public (CIS-2.1.4) AND unencrypted

        (CIS-2.1.1) represents a higher combined risk than either alone —

        sensitive data is both exposed and unprotected at rest.

        """

        from collections import defaultdict



        # Group findings by resource_id

        resource_findings = defaultdict(list)

        for f in findings:

            resource_findings[f.get("resource_id", "")].append(f.get("control_id", ""))



        # Inject coexisting violations into each finding

        for f in findings:

            rid = f.get("resource_id", "")

            siblings = [cid for cid in resource_findings[rid] if cid != f.get("control_id", "")]

            f["coexisting_violations"] = siblings



            if siblings:

                logger.info(

                    f"  ⚠ Combined violations on {rid}: "

                    f"{f.get('control_id')} + {siblings}"

                )



    # ═══════════════════════════════════════════════════════════════════════════

    #  FOLLOW-UP FINDING BUILDER

    # ═══════════════════════════════════════════════════════════════════════════



    def _build_followup_finding(self, followup: dict) -> dict:

        """

        Wrap a raw follow-up finding dict (raised by the remediator) into the

        full processed finding schema that the report builder and audit logger expect.



        Follow-up findings have status=INFO and risk_level=INFO — they are NOT

        violations requiring immediate action, but architectural debt items that

        the system raised automatically to prevent silent self-violation.

        """

        now_iso = datetime.now(timezone.utc).isoformat()

        return {

            "finding_id":    f"FND-FOLLOWUP-{followup['control_id']}-{followup['resource_id'].replace(':', '_')}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",

            "control_id":    followup.get("control_id", "Org-RDS-SG-Chain"),

            "control_name":  followup.get("control_name", "Zero-Trust SG Chaining Migration Required"),

            "resource_id":   followup.get("resource_id", ""),

            "resource_type": followup.get("resource_type", "AWS::EC2::SecurityGroup"),

            "status":        "INFO",

            "region":        followup.get("region", self.region),

            "processed_at":  now_iso,

            "recorded_at":   now_iso,

            "details":       followup.get("details", {}),

            "auto_raised_by": followup.get("auto_raised_by", "ComplianceGuard"),

            "risk": {

                "risk_level":  "INFO",

                "risk_pct":    0,

                "raw_score":   0,

                "breakdown":   {},

                "note":        "Auto-raised follow-up finding — no risk score assigned. Requires architectural migration.",

            },

            "safety_gate":     {"action": "PROCEED", "reason": "INFO finding — auto-raised, not a hard violation."},

            "llm_analysis":    None,

            "auto_remediation": {

                "status":  "followup_required",

                "message": followup.get("details", {}).get("violation", ""),

            },

        }



    # ═══════════════════════════════════════════════════════════════════════════

    #  FINDING PROCESSOR

    # ═══════════════════════════════════════════════════════════════════════════



    def _process_finding(self, finding: dict) -> dict:

        """

        Process one CIS finding through the full pipeline:

          Context → Risk Score → Auto-remediate OR LLM escalation

        """

        control_id    = finding.get("control_id", "")

        resource_id   = finding.get("resource_id", "")

        resource_type = finding.get("resource_type", "")



        now_iso = datetime.now(timezone.utc).isoformat()

        enriched = {

            "finding_id":    f"FND-{control_id}-{resource_id.replace(':', '_')}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",

            "control_id":    control_id,

            "control_name":  finding.get("control_name", ""),

            "resource_id":   resource_id,

            "resource_type": resource_type,

            "status":        finding.get("status", "NON_COMPLIANT"),

            "details":       finding.get("details", {}),

            "region":        finding.get("region", self.region),

            "processed_at":  now_iso,

            "recorded_at":   finding.get("recorded_at") or now_iso,

            "llm_analysis":       None,

            "auto_remediation":   None,

        }



        # ── Exception Registry Check ─────────────────────────────────────────
        #
        # Before making any AWS API calls, check if there is a formally approved,
        # non-expired exception for this resource + control combination.
        # If so, return immediately with status=EXCEPTED — no remediation,
        # no LLM call, no boto3 queries.

        try:

            from governance.exception_registry import ExceptionRegistry

            _exc_reg = ExceptionRegistry()

            active_exc = _exc_reg.get_active_exception(resource_id, control_id)

            if active_exc:

                exc_reason = _exc_reg.build_exception_reason(active_exc)

                logger.info(

                    f"    ⊛ [EXCEPTED] {control_id} on {resource_id} — "

                    f"{exc_reason}"

                )

                enriched["status"]          = "EXCEPTED"

                enriched["exception"]       = active_exc

                enriched["llm_analysis"]    = None

                enriched["auto_remediation"] = {

                    "status":  "skipped",

                    "message": f"Active exception on record: {exc_reason}",

                }

                enriched["risk"] = {

                    "risk_level": "EXCEPTED",

                    "risk_pct":   0,

                    "raw_score":  0,

                    "breakdown":  {},

                }

                return enriched

        except Exception as _exc_err:

            logger.debug(f"    [ExceptionRegistry] check skipped: {_exc_err}")



        # ── Step A: Collect Context ───────────────────────────────────────────

        if getattr(self, 'skip_scan', False) and finding.get("context"):

            logger.info(f"    → [Mock Mode] Reusing existing context from scan report...")

            context = finding.get("context", {})

            enriched["context"] = context

        else:

            logger.info(f"    → Querying AWS APIs for resource context...")

            try:

                context = self.collector.collect(resource_type, resource_id, control_id)

                enriched["context"] = context

                logger.info(f"      [Context] tags={context.get('tags', {})}")

                logger.info(f"      [Context] empty={context.get('is_empty', False)}, connections={len(context.get('connections', {}).get('downstream', {})) + len(context.get('connections', {}).get('upstream', {}))}")

            except Exception as e:

                logger.warning(f"    ⚠ Context collection failed: {e} — using empty context")

                context = {}

                enriched["context"] = {"error": str(e)}



        # Inject combined-violation metadata from pre-processing step
        context["coexisting_violations"] = finding.get("coexisting_violations", [])

        # Selectively inject scanner details into context.
        # IMPORTANT: Never overwrite keys already populated by ContextCollector
        # (e.g., live attached_instances, activity_evidence, vpc_id, tags).
        # CIS-5.3 scanner puts attached_instances=[] (stub) in details;
        # a blind context.update() would erase the real live list from the collector.
        _SAFE_DETAIL_INJECT = {
            # Security Group controls
            "port", "cidrs", "protocol", "cidr_exposure", "sg_id", "sg_name",
            "service", "offending_cidrs", "exposed_cidrs", "ip_protocol",
            # IAM controls
            "username", "access_key_id", "key_age_days", "last_used_days",
            "last_used_service", "is_dormant",
            # RDS controls
            "db_port", "sg_cidrs", "sg_cidr_exposure", "db_instance_status",
            "sg_ids", "sg_peer_refs",
            # EC2 controls
            "env_tag", "role_tag", "subnet_id",
            # Generic
            "violation", "remediation_note",
            # CIS-5.3 specific: inbound/outbound rule detail for LLM context.
            # Not used by gate/scorer (they re-fetch live), but the admin
            # reading the RCA benefits from seeing exactly which rules were flagged.
            "inbound_rule_count", "outbound_rule_count",
            "inbound_rules", "outbound_rules",
        }
        scanner_details = finding.get("details", {})
        for k in _SAFE_DETAIL_INJECT:
            if k in scanner_details and k not in context:
                context[k] = scanner_details[k]



        # ── Step B: Risk Scoring ──────────────────────────────────────────────

        try:

            risk       = risk_scorer.score(control_id, context)

            risk_level = risk["risk_level"]

            enriched["risk"] = risk

            bd = risk.get('breakdown', {})

            logger.info(f"    → Risk Score: {risk['raw_score']}/{risk['max_score']} ({risk['risk_pct']}%) -> {risk_level}")

            logger.info(f"      [Breakdown] Severity({bd.get('compliance_severity', 0)}) + Env({bd.get('environment_criticality', 0)}) + Data({bd.get('data_sensitivity', 0)}) = {risk.get('raw_score', 0)}/{risk.get('max_score', 50)}")

        except Exception as e:

            logger.warning(f"    ⚠ Risk scoring failed: {e} — defaulting to HIGH")

            risk       = {"risk_level": "HIGH", "raw_score": 0, "risk_pct": 0, "error": str(e)}

            risk_level = "HIGH"

            enriched["risk"] = risk



        # ── Step C: Remediation Safety Gate ──────────────────────────────────

        safety_action, safety_reason = self.remediator.check_safety_gate(control_id, context, resource_id)

        enriched["gate_action"] = safety_action



        # ── Step D: Confidence Override ──────────────────────────────────────────

        # If context is incomplete (missing tags, unresolved APIs), the system

        # cannot make a reliable autonomous decision — force to human review.

        confidence   = risk.get("confidence", {})

        force_review = confidence.get("force_human_review", False)

        if force_review:

            missing = [

                k for k, v in confidence.get("factors", {}).items()

                if not v.get("present", v.get("resolved", v.get("success", True)))

            ]

            if risk_level in LLM_ESCALATION_LEVELS:

                # Bug E fix: HIGH/CRITICAL findings already route to LLM — the confidence

                # override doesn't change their path (BLOCK always wins; PROCEED goes to

                # high_proceed_verify). The old message "Overriding AUTO → human review"

                # was factually wrong — nothing was overridden. Correct the log.

                logger.warning(

                    f"    ⚠ LOW confidence ({confidence.get('score')}%) on {risk_level} finding — "

                    f"missing context: {missing}. Bug A override will intercept gate=PROCEED."

                )

            else:

                logger.warning(

                    f"    ⚠ LOW confidence ({confidence.get('score')}%) — "

                    f"missing context: {missing}. Overriding AUTO → human review."

                )



        # ── Confidence warnings: LLM-only context ──────────────────────────
        # Confidence warnings are passed to the LLM prompt separately via
        # the conf_note variable in _build_llm_prompt. They are NOT appended
        # to safety_reason, which is user-facing in the dashboard UI.
        # Keeping safety_reason clean: gate decision only, no noise.

        # ── Resolution Fork ───────────────────────────────────────────────────
        # Routing is driven purely by Operational Risk Score + Safety Gate.
        #
        #  LOW/MEDIUM  + PROCEED → LLM cross-verify → auto-remediate
        #  LOW/MEDIUM  + BLOCK   → LLM plan → quick_approve (human picks fix)
        #  HIGH/CRITICAL + PROCEED → LLM cross-verify → quick_approve (human signs off)
        #  HIGH/CRITICAL + BLOCK   → LLM full RCA → investigate (deep review)

        if safety_action == "BLOCK":

            if risk_level in LLM_ESCALATION_LEVELS:
                # HIGH/CRITICAL + BLOCK: deep RCA — gate determined the fix is
                # unsafe AND the violation is high impact. Full investigate.
                self._handle_escalation(
                    enriched, finding, context, risk,
                    priority="investigate",
                    safety_reason=safety_reason,
                )
            else:
                # LOW/MEDIUM + BLOCK: gate flagged an operational risk but the
                # violation itself is lower impact. Quick human approval is enough.
                self._handle_escalation(
                    enriched, finding, context, risk,
                    priority="quick_approve",
                    safety_reason=safety_reason,
                )

        elif risk_level in LLM_ESCALATION_LEVELS:
            # HIGH/CRITICAL + PROCEED: gate confirmed the fix is architecturally
            # safe, but a HIGH/CRITICAL finding on a production resource must
            # never be auto-remediated. LLM generates a complete plan; admin
            # reviews and approves before any action is taken.
            self._handle_escalation(
                enriched, finding, context, risk,
                priority="quick_approve",
                safety_reason=safety_reason,
            )

        else:
            # LOW/MEDIUM + PROCEED: gate approved the fix and risk is bounded.
            # LLM independently cross-verifies architectural safety, then
            # auto-remediates. This is the only fully-automated path.
            self._handle_proceed_verification(enriched, finding, context, risk, safety_reason)



        return enriched



    # ═══════════════════════════════════════════════════════════════════════════

    #  PROCEED PATH — LLM ARCHITECTURAL VERIFICATION (LOW / MEDIUM)

    # ═══════════════════════════════════════════════════════════════════════════



    def _handle_proceed_verification(

        self,

        enriched:      dict,

        finding:       dict,

        context:       dict,

        risk:          dict,

        safety_reason: str,

    ):

        """

        Called for LOW/MEDIUM risk findings where the Safety Gate says PROCEED.



        Before any auto-remediation happens, we ask the LLM to independently

        cross-verify that the gate's architectural reasoning is correct given

        the live AWS context. If the LLM disagrees or flags a discrepancy,

        we abort the auto-fix and escalate to human review.

        """

        control_id  = enriched["control_id"]

        resource_id = enriched["resource_id"]

        risk_level  = risk["risk_level"]



        logger.info(

            f"    -> Gate=PROCEED ({risk_level}): invoking LLM architectural "

            f"safety verification before auto-remediating {resource_id}..."

        )



        proceed_ok = True   # assume safe unless LLM flags a discrepancy

        if not self.dry_run:

            analysis = self._invoke_llm(

                finding, context, risk,

                priority="proceed_verify",

                safety_reason=safety_reason,

            )

            enriched["llm_analysis"] = analysis



            # Extract the LLM's architectural safety verdict.
            # Default to True (not False): absence of the key means the
            # model gave no opinion — the deterministic gate has already
            # confirmed PROCEED, so a missing key must not veto it.

            safety_verif = analysis.get("safety_verification", {}) if analysis else {}

            proceed_ok   = safety_verif.get("architecturally_safe", True)

            verif_reason = safety_verif.get("verification_rationale", "")



            if not proceed_ok:

                # LLM flagged a discrepancy — abort auto-fix, escalate to human

                logger.warning(

                    f"    -> LLM OVERRODE gate PROCEED decision for {resource_id}: "

                    f"{verif_reason}"

                )

                enriched["llm_override"] = {
                    "action": "BLOCKED_BY_LLM_VERIFICATION",
                    "reason": verif_reason,
                }
                # Do NOT call _handle_escalation here — that fires a second LLM
                # call (investigate priority), doubling cost and overwriting the
                # verification analysis we already have. Reuse it directly.
                override_reason = (
                    f"LLM verification disagreed with gate PROCEED: {verif_reason}. "
                    f"Original gate justification: {safety_reason}"
                )
                enriched["escalation_priority"] = "investigate"
                enriched["gate_block_reason"]   = override_reason
                self._notify_user(
                    level=risk["risk_level"],
                    icon="🚨",
                    header="MANUAL ADMIN REVIEW REQUIRED — LLM Override",
                    control_id=enriched["control_id"],
                    resource_id=resource_id,
                    risk=risk,
                    context=context,
                    extra=override_reason,
                )
                return



            logger.info(

                f"    -> LLM confirmed gate PROCEED is architecturally safe: "

                f"{verif_reason[:100]}"

            )

        else:

            logger.info("    -> [DRY RUN] Skipping LLM verification.")

            enriched["llm_analysis"] = {"status": "skipped_dry_run"}



        # LLM confirmed (or dry-run) — proceed with auto-remediation

        self._handle_auto_remediation(enriched, finding, context, risk)










    def _handle_auto_remediation(self, enriched: dict, finding: dict, context: dict, risk: dict):

        """Auto-remediate LOW/MEDIUM findings and notify user."""

        risk_level  = risk["risk_level"]

        control_id  = enriched["control_id"]

        resource_id = enriched["resource_id"]



        logger.info(f"    → Routing to AUTO track: {risk_level} risk ({risk['risk_pct']}% score)")

        logger.info(f"    → Triggering auto-remediation...")



        if self.dry_run:

            logger.info(f"    → [DRY RUN] Skipping actual remediation.")

            enriched["auto_remediation"] = {"status": "skipped_dry_run"}

            success, msg = True, "Simulated remediation (dry-run)"

        else:

            # ── Capture pre-remediation state for rollback support ──────────

            pre_state = self.remediator.capture_pre_remediation_state(

                control_id, resource_id

            )

            logger.info(

                f"      [Snapshot] Pre-remediation state captured for {resource_id} — "

                f"restore_call='{pre_state.get('restore_call', 'n/a')}'"

            )

            success, msg = self.remediator.remediate(enriched)

            enriched["auto_remediation"] = {

                "status":                "success" if success else "failed",

                "message":               msg,

                "pre_remediation_state": pre_state,

            }



            # ── VERIFICATION_FAILED: boto3 call failed ──────────────────────

            # If the remediate() call itself returned False, escalate immediately.

            if not success:

                logger.warning(

                    f"    ⚠ AUTO-REMEDIATION FAILED for {resource_id} "

                    f"({control_id}): {msg}. Re-escalating to LLM Investigate."

                )

                enriched["auto_remediation"]["status"] = "VERIFICATION_FAILED"

                self._handle_escalation(

                    enriched, finding, context, risk,

                    priority="investigate",

                    safety_reason=(

                        f"VERIFICATION_FAILED: Auto-remediation boto3 call failed. "

                        f"Message: {msg}. "

                        f"Pre-remediation state captured — rollback available via: "

                        f"{pre_state.get('restore_call', 'manual')}."

                    ),

                )

                return

            # ── Post-Remediation Compliance Re-Verification ─────────────────
            #
            # The remediate() call above succeeded at the boto3 layer (HTTP 200).
            # Now independently re-query the live AWS resource and re-apply the
            # control's compliance logic to confirm the resource is actually fixed.
            # This catches partial writes, eventual-consistency delays, and race
            # conditions that a simple write-then-read-back inside _remediate_*
            # cannot reliably detect.

            logger.info(

                f"      [PostVerify] Re-querying {resource_id} to confirm "

                f"{control_id} compliance post-fix..."

            )

            post_compliant, post_state = self.remediator.verify_post_remediation(

                control_id, resource_id, context=context

            )

            enriched["auto_remediation"]["post_remediation_state"] = post_state

            if not post_compliant:

                verify_err = post_state.get("verify_error", "")

                obs        = post_state.get("observed_state", {})

                logger.warning(

                    f"    ⚠ POST-REMEDIATION RE-VERIFICATION FAILED for {resource_id} "

                    f"({control_id}): resource is still non-compliant after fix. "

                    f"observed_state={obs}. Re-escalating to LLM Investigate."

                )

                enriched["auto_remediation"]["status"] = "VERIFICATION_FAILED"

                self._handle_escalation(

                    enriched, finding, context, risk,

                    priority="investigate",

                    safety_reason=(

                        f"VERIFICATION_FAILED: Auto-remediation boto3 call succeeded but "

                        f"post-remediation compliance re-scan confirmed resource is STILL "

                        f"NON-COMPLIANT. Observed state: {obs}. "

                        + (f"Re-verification error: {verify_err}. " if verify_err else "")

                        + f"Pre-remediation state captured — rollback available via: "

                        f"{pre_state.get('restore_call', 'manual')}."

                    ),

                )

                return

            logger.info(

                f"      [PostVerify] ✓ {resource_id} confirmed COMPLIANT — "

                f"post-remediation re-scan passed."

            )

        status_icon = "✅" if success else "❌"

        self._notify_user(

            level=risk_level,

            icon=status_icon,

            header="SYSTEM ACTION TAKEN — AUTO-REMEDIATED",

            control_id=control_id,

            resource_id=resource_id,

            risk=risk,

            context=context,

            extra=f"Remediation: {msg}",

        )




    # ═══════════════════════════════════════════════════════════════════════════

    #  HIGH / CRITICAL — LLM ESCALATION

    # ═══════════════════════════════════════════════════════════════════════════



    def _handle_escalation(

        self,

        enriched:      dict,

        finding:       dict,

        context:       dict,

        risk:          dict,

        priority:      str = "investigate",

        safety_reason: str = "",

    ):

        """Invoke LLM for RCA + remediation plan and alert admin."""

        risk_level  = risk["risk_level"]

        control_id  = enriched["control_id"]

        resource_id = enriched["resource_id"]



        enriched["escalation_priority"] = priority

        if safety_reason:

            enriched["gate_block_reason"] = safety_reason



        icon = "🚨" if risk_level == "CRITICAL" else "🔴"

        gate_note = (

            f" [Gate BLOCKED: {safety_reason}]"

            if safety_reason and priority == "investigate" else ""

        )

        logger.info(

            f"    → {risk_level} risk ({risk['risk_pct']}%) — "

            f"escalating to LLM for RCA ({priority}){gate_note}..."

        )



        if self.dry_run:

            logger.info(f"    → [DRY RUN] Skipping LLM call.")

            enriched["llm_analysis"] = {"status": "skipped_dry_run"}

        else:

            analysis = self._invoke_llm(finding, context, risk, priority, safety_reason)

            # ── Fallback: if LLM timed out, build synthetic RCA from gate reasoning ──
            # The safety gate already computed a context-aware decision with full
            # justification. Rather than showing "LLM unavailable", we surface the
            # gate's reasoning as the RCA. The admin still gets actionable output.
            if analysis.get("_llm_error"):
                logger.warning(f"      [LLM FALLBACK] LLM unavailable — generating synthetic RCA from safety gate reasoning")
                control_id = finding.get("control_id", "")
                security_brief = self._CONTROL_BRIEFS.get(
                    control_id,
                    f"Violation of {finding.get('control_name', control_id)}."
                )
                gate_decision = enriched.get("gate_action", "BLOCK")  # Use the authoritative gate action already set in enriched

                analysis = {
                    "root_cause": (
                        f"{security_brief} "
                        f"Safety Gate assessed this resource and returned {gate_decision}: "
                        f"{safety_reason or 'No specific gate reasoning available.'}  "
                        f"Note: This analysis was generated from the deterministic Safety Gate — "
                        f"the LLM verifier was unavailable ({analysis.get('_llm_error', 'timeout')})."
                    ),
                    "business_impact": (
                        f"Because this misconfiguration is deployed in the {risk.get('breakdown', {}).get('_env_tag', 'production')} environment, "
                        f"any potential compromise of associated resources would carry high operational impact across live production workloads."
                    ),
                    "recommended_fix": (
                        f"Replace the unrestricted inbound access on port 22 (SSH) with the internal VPC CIDR block to securely eliminate public exposure."
                        if gate_decision == "PROCEED" else
                        f"Address the gate's BLOCK reason before proceeding: {safety_reason}"
                    ),
                    "fix_steps": (
                        [
                            f"Step 1: Identify the Security Group ({finding.get('resource_id', 'sg-id')}) associated with the instance and review its inbound rules.",
                            f"Step 2: Update the Security Group to replace the unrestricted inbound access on port 22 (SSH) with the internal VPC CIDR block.",
                            f"Step 3: Verify that the update has been successfully applied and the instance is no longer exposed to public access.",
                        ]
                        if gate_decision == "PROCEED" else
                        [
                            f"Step 1: Review the Safety Gate assessment: {safety_reason}",
                            f"Step 2: Verify the gate's conclusion against current AWS state",
                            f"Step 3: Apply the remediation action recommended by the gate",
                            f"Step 4: Confirm the CIS control violation is resolved",
                        ]
                    ),
                    "prerequisite_actions": (
                        [f"Gate BLOCKED this action: {safety_reason}. Resolve before proceeding."]
                        if gate_decision == "BLOCK" else
                        ["Schedule a maintenance window to apply the fix, and notify stakeholders of the planned downtime. Obtain approval from relevant teams before proceeding."]
                    ),
                    "operational_impact": (
                        f"Applying the fix may result in a brief downtime of approximately 5-10 minutes, depending on the instance's workload and dependencies."
                        if gate_decision == "PROCEED" else
                        f"Operational risk flagged by gate: {safety_reason}"
                    ),
                    "safe_window": "Recommended UTC time window for applying the fix: 02:00-03:00 (avoid peak hours and minimize impact on live workloads)." if gate_decision == "PROCEED" else "Schedule during maintenance window.",
                    "rollback_steps": [
                        f"Step 1: Revert the Security Group update by replacing the internal VPC CIDR block with the original unrestricted inbound access on port 22 (SSH) if the fix causes issues.",
                    ],
                    "safety_verification": {
                        "architecturally_safe": gate_decision == "PROCEED",
                        "verification_rationale": (
                            f"Based on deterministic Safety Gate analysis (LLM verifier unavailable). "
                            f"Gate decision: {gate_decision}. Reason: {safety_reason}"
                        ),
                    },
                    "_synthetic_rca": True,
                    # gate_reason is always populated so the frontend banner renders for both PROCEED and BLOCK.
                    # gate_block_reason is kept for backward compat (only set when truly BLOCKed).
                    "gate_reason":       safety_reason,
                    "gate_block_reason": safety_reason if gate_decision == "BLOCK" else None,
                }

            enriched["llm_analysis"] = analysis

            if analysis and "root_cause" in analysis:

                logger.info(f"      [RCA] {analysis.get('root_cause', '')[:120]}")

                fix = analysis.get("recommended_fix", "")

                if fix:

                    logger.info(f"      [Fix] {fix[:120]}")

                prereqs = analysis.get("prerequisite_actions", [])

                if prereqs:

                    logger.info(f"      [Pre-reqs] {prereqs}")



        self._notify_user(

            level=risk_level,

            icon=icon,

            header="MANUAL ADMIN REVIEW REQUIRED",

            control_id=control_id,

            resource_id=resource_id,

            risk=risk,

            context=context,

            extra=(

                f"Gate: {safety_reason or 'PROCEED — score-based escalation'}. "

                "LLM Root Cause Analysis generated. Review plan and APPROVE or REJECT."

            ),

        )

        # ── Mark quick_approve findings as PENDING_APPROVAL ─────────────────
        # The dashboard reads this status to show Approve / Deny buttons.
        # investigate findings are fully autonomous (no human approval needed).

        if priority == "quick_approve":

            enriched["status"] = "PENDING_APPROVAL"

            enriched["pending_approval"] = {

                "requested_at": datetime.now(timezone.utc).isoformat(),

                "risk_level":   risk_level,

                "safety_reason": safety_reason,

            }



    # ═══════════════════════════════════════════════════════════════════════════

    #  LLM INVOCATION

    # ═══════════════════════════════════════════════════════════════════════════



    def _invoke_llm(
        self,
        finding:       dict,
        context:       dict,
        risk:          dict,
        priority:      str,
        safety_reason: str = "",
    ) -> dict:
        """
        Build a control-specific, context-rich prompt and call the LLM
        (meta/llama-3.1-70b-instruct) for Root Cause Analysis and remediation planning.
        """
        from ai.llm_client import (
            MODEL_HEAVY, MODEL_LIGHT,
            TIMEOUT_HEAVY, TIMEOUT_LIGHT,
            TOKENS_HEAVY, TOKENS_LIGHT,
        )

        try:
            prompt = self._build_llm_prompt(finding, context, risk, priority, safety_reason)

            # Model selection based on priority
            if priority == "investigate":
                model_id   = MODEL_HEAVY
                timeout    = TIMEOUT_HEAVY
                max_tokens = TOKENS_HEAVY
                tier_label = "70B - deep RCA"
            else:
                model_id   = MODEL_LIGHT
                timeout    = TIMEOUT_LIGHT
                max_tokens = TOKENS_LIGHT
                tier_label = "70B - RCA / verify"

            logger.info(
                f'    -> Invoking LLM [{tier_label}] for '
                f"{finding.get('resource_id', '?')} (priority={priority})..."
            )
            result = self.llm.generate(
                prompt,
                model_id=model_id,
                timeout=timeout,
                max_tokens=max_tokens,
            )

            # Fallback: if primary model timed out, use deterministic synthetic RCA
            if result.get("_llm_error") and model_id == MODEL_HEAVY:
                logger.warning(
                    f"    -> LLM timed out — using deterministic fallback for {priority}..."
                )
                result = self.llm.generate(
                    prompt,
                    model_id=MODEL_LIGHT,
                    timeout=TIMEOUT_LIGHT,
                    max_tokens=TOKENS_LIGHT,
                )
                if not result.get("_llm_error"):
                    result["_model_fallback"] = "LLM timed out; RCA generated via deterministic fallback."
                    tier_label = "FALLBACK (deterministic synthetic RCA)"

            logger.info(f'    -> LLM response received [{tier_label}]')
            return result

        except Exception as e:
            logger.error(f"    LLM invocation failed: {e}")
            return {
                "root_cause":           str(e),
                "recommended_fix":      "LLM unavailable - manual review required",
                "fix_steps":            [],
                "rollback_steps":       [],
                "prerequisite_actions": [],
                "safety_verification":  {
                    "architecturally_safe":   False,
                    "verification_rationale": "LLM unavailable - fail-safe blocking auto-remediation.",
                },
            }


    #  Control-specific security briefs injected into the LLM prompt

    # ─────────────────────────────────────────────────────────────────────────



    _CONTROL_BRIEFS = {

        "CIS-2.1.4": (

            "S3 Public Access Block is DISABLED. This means any bucket policy or ACL granting "

            "public access will take effect. If this bucket receives a public bucket policy, "

            "data becomes readable by anyone on the internet. AWS Block Public Access is the "

            "last line of defence against accidental data exposure via misconfigured policies."

        ),

        "CIS-2.1.1": (

            "S3 bucket objects are NOT encrypted at rest. Any data written to this bucket is "

            "stored in plaintext. A compromised AWS credential or a misconfigured S3 policy "

            "would expose raw data with no encryption barrier. CIS requires SSE-AES256 or SSE-KMS."

        ),

        "CIS-2.1.5": (

            "S3 bucket versioning is DISABLED. Without versioning, a ransomware attack or "

            "accidental delete permanently destroys data. Versioning is the primary recovery "

            "mechanism for S3 objects and is required for compliance with data retention policies."

        ),

        "CIS-5.2": (

            "A Security Group allows UNRESTRICTED INBOUND ACCESS (0.0.0.0/0) on a high-risk "

            "administrative port (SSH/RDP/administrative API). Any IP on the internet can attempt "

            "to connect to this resource. This is the #1 initial access vector for ransomware "

            "and credential brute-force attacks against cloud infrastructure."

        ),

        "Org-5": (

            "An EC2 instance has a PUBLIC IP ADDRESS assigned directly. Without an ALB/WAF in "

            "front, all ports reachable via Security Group rules are directly internet-exposed. "

            "This bypasses network-layer controls and violates the principle of private instance topology."

        ),

        "CIS-1.14": (

            "An IAM ACCESS KEY has not been rotated in over 90 days. Long-lived credentials are "

            "the primary target for credential harvesting. A leaked 90-day-old key provides "

            "sustained access to AWS APIs. CIS requires rotation every 90 days to limit the "

            "exposure window of any exfiltrated credential."

        ),

        "CIS-2.3.2": (

            "An RDS INSTANCE is marked PubliclyAccessible=True. The database port is potentially "

            "reachable from the internet. Even if Security Group rules currently restrict access, "

            "a misconfigured SG rule would immediately expose the database to brute-force attacks. "

            "Databases must reside in private subnets with no public endpoint."

        ),

        "CIS-2.2.1": (

            "An EBS VOLUME at rest is UNENCRYPTED. Any snapshot derived from this volume will "

            "also be unencrypted. A snapshot shared accidentally (or through SSRF/confused deputy) "

            "reveals raw disk data with no encryption barrier. AWS recommends default encryption "

            "for all EBS volumes in production."

        ),

        "CIS-5.3": (

            "The DEFAULT VPC SECURITY GROUP has inbound or outbound rules. "

            "CIS requires the default SG to have ZERO rules in both directions. "

            "Any resource accidentally launched without specifying a dedicated SG inherits "

            "the default SG automatically. If the default SG has permissive rules, those "

            "resources are silently exposed without any intentional policy decision. "

            "The default SG is the 'fallback' that must be a hard wall, not a door."

        ),

        "Org-SG-DB": (

            "A SECURITY GROUP allows direct inbound internet access (0.0.0.0/0) to a "

            "DATABASE PORT (MySQL/PostgreSQL/MongoDB/Redis/Elasticsearch). "

            "Database engines are not designed to be internet-facing. Exposed database ports "

            "are directly targeted by automated credential brute-force bots within minutes of "

            "exposure. A single successful connection grants full read/write access to all data. "

            "This is the most critical network exposure pattern in cloud environments."

        ),

        "Org-RDS-SG-Chain": (

            "An RDS SECURITY GROUP is using raw IP CIDR ranges (IpRanges) to allow database "

            "port access instead of Security Group references (UserIdGroupPairs). "

            "This violates the AWS zero-trust Security Group Chaining pattern. "

            "CIDR-based rules allow ANY host within the IP range to connect to the database, "

            "including future resources that may be malicious or compromised. "

            "Security Group Chaining (referencing the specific EC2 app SG) ensures ONLY "

            "the approved application instances can reach the database, regardless of their IP. "

            "This is especially critical for preventing lateral movement inside the VPC after "

            "an EC2 compromise — a valid VPC IP should not automatically grant DB access."

        ),

        # Bug P2 fix: added missing CIS-2.3.1 control brief.

        # Without this the LLM got the generic fallback ("Review CIS documentation") for the

        # most complex remediation workflow in the pipeline (snapshot-copy-restore).

        "CIS-2.3.1": (

            "An RDS INSTANCE has at-rest encryption DISABLED. All data written to the underlying "

            "EBS storage is stored in plaintext. A compromised credential, misconfigured snapshot "

            "policy, or accidental snapshot share would expose raw database files with no encryption "

            "barrier. CRITICAL: RDS at-rest encryption CANNOT be enabled in-place on a running "

            "instance. The only supported path is: (1) Copy the unencrypted snapshot with KMS "

            "encryption enabled to create an encrypted snapshot, (2) Restore a new RDS instance "

            "from the encrypted snapshot, (3) Update application connection strings to the new "

            "endpoint, (4) Run smoke tests under production load, (5) Decommission the unencrypted "

            "instance after a validation window. This requires a scheduled maintenance window, "

            "application downtime during connection cutover, and DBA/application team coordination."

        ),

    }



    def _build_llm_prompt(

        self,

        finding:       dict,

        context:       dict,

        risk:          dict,

        priority:      str,

        safety_reason: str = "",

    ) -> str:

        """

        Build a control-specific, context-rich RCA prompt.

        Grounded entirely from the live AWS context snapshot — no RAG needed.

        """

        control_id    = finding.get("control_id", "")

        control_name  = finding.get("control_name", "")

        resource_id   = finding.get("resource_id", "")

        resource_type = finding.get("resource_type", "")

        risk_level    = risk.get("risk_level", "")

        risk_pct      = risk.get("risk_pct", 0)

        breakdown     = risk.get("breakdown", {})

        rationale     = risk.get("rationale", "")

        confidence    = risk.get("confidence", {})



        # ── Enrich context summary ─────────────────────────────────────────

        tags         = context.get("tags", {})

        attr         = context.get("attribution", {})

        connections  = context.get("connections", {})

        is_empty     = context.get("is_empty", False)

        conf_band    = confidence.get("band", "HIGH")

        conf_score   = confidence.get("score", 100)



        # Pull topology / network fields (set by scanner/context_collector)

        is_private    = context.get("is_private_subnet", None)

        cidr_exposure = (

            finding.get("details", {}).get("cidr_exposure") or

            context.get("cidr_exposure", "unknown")

        )

        instance_state = context.get("instance_state", "unknown")

        attached_insts = context.get("attached_instances", [])



        # Pre-remediation snapshot — only use what was already captured by
        # _handle_auto_remediation before the fix was applied.
        # Do NOT call capture_pre_remediation_state() here:
        #   - For BLOCK/escalation: no remediation occurs, rollback snapshot is misleading.
        #   - For proceed_verify: snapshot is captured in _handle_auto_remediation
        #     which runs AFTER the LLM verification, so it isn't available yet here.
        pre_state = (finding.get("auto_remediation") or {}).get("pre_remediation_state")



        context_summary = json.dumps({

            "tags":             tags,

            "environment":      breakdown.get("_env_tag", "unknown"),

            "data_class":       breakdown.get("_data_classification", "unknown"),

            "is_private_subnet": is_private,

            "has_public_ip":    context.get("has_public_ip", False),

            "cidr_exposure":    cidr_exposure,

            "instance_state":   instance_state,

            "attached_instances": attached_insts,

            "is_empty_resource": is_empty,

            "connections":      connections,

            "attribution":      attr,

            "confidence_band":  conf_band,

            "confidence_score": conf_score,

            # ── Activity Evidence (log-derived, not configuration-derived) ──

            # Surfaces real observed behaviour: who connected, from where,

            # and whether external/anonymous access was detected.

            # The LLM uses this to ground its RCA in actual observed activity,

            # not just configuration state.

            "activity_evidence": {

                "analyst_summary":          context.get("activity_evidence", {}).get("analyst_summary", "Not available."),

                "external_access_detected": context.get("activity_evidence", {}).get("external_access_detected", False),

                "exploitation_signals":     context.get("activity_evidence", {}).get("exploitation_signals", []),

                "suggested_cidr_replacements": context.get("activity_evidence", {}).get("suggested_cidr_replacements", []),

                "logging_enabled":          context.get("activity_evidence", {}).get("logging_enabled", False),

                "evidence_source":          context.get("activity_evidence", {}).get("source", "unknown"),

                # Detailed per-IP connection data (VPC Flow Logs) — top 10 IPs by connection count

                "observed_source_ips":      context.get("activity_evidence", {}).get("observed_source_ips", [])[:10],

                # Detailed per-caller data (CloudTrail) — who called which APIs from where

                "unique_callers":           context.get("activity_evidence", {}).get("unique_callers", [])[:10],

            },

        }, indent=2, default=str)



        # ── Control-specific security brief ────────────────────────────────

        security_brief = self._CONTROL_BRIEFS.get(

            control_id,

            f"Violation of {control_name}. Review CIS Benchmark documentation for remediation guidance."

        )



        # ── Gate block / priority framing ──────────────────────────────────

        if safety_reason and priority == "investigate":

            mode_header = f"""⚠ REMEDIATION SAFETY GATE — BLOCKED

The Remediation Safety Gate automatically evaluated this resource and BLOCKED autonomous remediation.

Gate block reason: {safety_reason}



YOUR PRIMARY TASK: Explain what the admin must do FIRST before remediation can safely proceed.

List these as prerequisite_actions in your JSON response."""

        elif priority == "quick_approve":

            # quick_approve fires for two cases:
            #   1. LOW/MEDIUM + gate=BLOCK  — gate flagged operational risk; human picks fix.
            #   2. HIGH/CRITICAL + gate=PROCEED — gate approved fix but score demands sign-off.
            # In both cases the LLM generates a complete RCA + remediation plan.
            # The admin reviews and APPROVES or REJECTS before anything is applied.

            # Derive the gate label from safety_reason content.
            # safety_action is defined in _process_finding (caller scope) and is
            # not passed into _build_llm_prompt, so we infer it here.
            gate_label = "PROCEED" if safety_reason and "PROCEED" in safety_reason.upper() else "BLOCK"

            mode_header = f"""HUMAN REVIEW REQUIRED — REMEDIATION PLAN

The automated pipeline has prepared a remediation plan for this finding.
This fix WILL NOT be applied automatically. The administrator must review and approve.

Gate decision : {gate_label}
Risk level    : {risk_level} ({risk.get('risk_pct', '?')}%)

Context / reason this review was triggered:
{safety_reason}


YOUR TASK:
Provide a complete Root Cause Analysis and a step-by-step remediation plan.

The administrator will read your output and click APPROVE or REJECT.

Be specific and actionable:
  1. Explain exactly what the misconfiguration is and why it is a risk.
  2. List every step required to fix it, including any prerequisite actions
     (maintenance window, dependency checks, stakeholder notifications).
  3. State clearly if any step carries operational risk (e.g. brief downtime,
     connection drop, service restart required).
  4. Provide rollback steps in case the fix causes an unintended outage.

If there is ANY ambiguity about safety, list it in prerequisite_actions
so the administrator can make an informed decision before proceeding."""

        elif priority == "proceed_verify":

            mode_header = f"""ARCHITECTURAL SAFETY VERIFICATION REQUEST

The deterministic Remediation Safety Gate returned PROCEED for this resource.

Gate justification: '{safety_reason}'



IMPORTANT — Reading the context fields correctly:
  - cidr_exposure="internet" means the Security Group RULE contains internet source CIDRs
    (0.0.0.0/0 or ::/0). It does NOT mean the instance is currently reachable from the internet.
  - is_private_subnet=true means there is NO Internet Gateway (IGW) route on the subnet.
    An internet-sourced SG rule in a private subnet is REDUNDANT — no inbound traffic can
    physically reach the resource from outside. The gate correctly identifies this as safe.
  - Do NOT set architecturally_safe=false merely because cidr_exposure="internet" and
    is_private_subnet=true appear together. This is the expected pattern for PROCEED decisions
    on private-subnet resources with overly-broad SG rules.



YOUR SOLE TASK: Verify that the gate's justification is architecturally correct.

Check the live AWS context below and confirm:

  1. No active workloads, attached instances, or traffic flows contradict the PROCEED decision.

  2. Applying the automated fix will have ZERO operational impact.

  3. If the intended fix would cause an OUTAGE or break a legitimate active workload, set architecturally_safe=false. DO NOT block just to debate semantics or correct the wording.



This is a verification checkpoint — not a full RCA. Be concise and factual."""



        else:

            mode_header = (

                f"This is a {risk_level} risk finding requiring full Root Cause Analysis "

                "and a detailed remediation plan."

            )



        # ── Confidence context ─────────────────────────────────────────────

        conf_note = ""

        if conf_band in ("LOW", "MEDIUM"):

            missing = [

                k for k, v in confidence.get("factors", {}).items()

                if not v.get("present", v.get("resolved", v.get("success", True)))

            ]

            conf_note = (

                f"\nCONTEXT COMPLETENESS WARNING: Confidence is {conf_band} ({conf_score}/100). "

                f"Missing context: {missing}. Some scoring factors used default values. "

                "Note any assumptions in your analysis."

            )



        # ── Rollback context ───────────────────────────────────────────────

        rollback_note = ""

        if pre_state and not pre_state.get("capture_error"):

            rollback_note = f"""

=== PRE-REMEDIATION STATE SNAPSHOT ===

The system captured this configuration snapshot BEFORE remediation:

{json.dumps(pre_state.get('config', {}), indent=2, default=str)}

Restore call: {pre_state.get('restore_call', 'N/A')}



Include concrete rollback_steps in your response using this snapshot.

"""



        # Dynamically build evidence instructions for the LLM prompt.
        # Process conditional logic in Python and give the LLM ONE clear directive.

        #

        # Field mapping from context_collector._query_vpc_flow_logs():

        #   observed_source_ips  → ALL IPs (internal + external) that connected

        #   external_connections → subset of observed_source_ips where is_external=True

        # The gate must check observed_source_ips for ANY activity, then branch.

        evidence_instruction = ""

        is_dangling = context.get("_dangling_sg", False)

        deps = context.get("dependencies", [])

        attached = context.get("attached_instances", [])

        act_ev = context.get("activity_evidence", {})



        ev_source = act_ev.get("source", "")



        if is_dangling or (not attached and not deps and "SECURITYGROUP" in resource_type.upper()):
            evidence_instruction = (
                'State concisely in root_cause: "Dangling Security Group with no attached instances. '
                'The open 0.0.0.0/0 rule is latent technical debt posing theoretical exposure, '
                'but removing it has zero operational impact since no workloads are attached."'
            )
        elif ev_source == "vpc_flow_logs":
            if not act_ev.get("logging_enabled", False) or not act_ev.get("observed_source_ips", []):
                window_days = act_ev.get("evidence_window_days", 15)
                evidence_instruction = (
                    f'State explicitly in root_cause: "VPC Flow Logs analysis confirmed 0 inbound connection attempts '
                    f'on port 22 over the preceding {window_days} days. Because the attached EC2 instance has an internal '
                    f'private IP and no active external traffic was observed, replacing 0.0.0.0/0 with the internal VPC CIDR '
                    f'block securely eliminates public exposure without disrupting existing administrative access." '
                    f'CRITICAL RULE: Do NOT invent, assume, or hallucinate any IP addresses or external connection counts.'
                )
            else:
                window_days = act_ev.get("evidence_window_days", 15)
                all_ips     = act_ev.get("observed_source_ips", [])
                ext_ips     = [e for e in all_ips if e.get("is_external", False)]
                int_ips     = [e for e in all_ips if not e.get("is_external", False)]

                raw_port = context.get("port") or context.get("db_port") or finding.get("details", {}).get("port")
                port_str = f"port {raw_port}" if raw_port else "monitored network ports"

                if ext_ips:
                    ext_ip_strs = [
                        f"{e.get('ip')} ({e.get('connections', 1)} connections)"
                        if isinstance(e, dict) else str(e)
                        for e in ext_ips
                    ]
                    ips_str = ", ".join(ext_ip_strs)
                    evidence_instruction = (
                        f'State explicitly in root_cause: "In the last {window_days} days, VPC Flow Logs '
                        f'recorded {len(all_ips)} source IP(s) connecting on {port_str}, '
                        f'of which {len(ext_ips)} are EXTERNAL (non-RFC1918): {ips_str}. '
                        f'This confirms active external access against {port_str}."'
                    )
                else:
                    int_ip_strs = [
                        f"{e.get('ip')} ({e.get('connections', 1)} connections)"
                        if isinstance(e, dict) else str(e)
                        for e in int_ips
                    ]
                    ips_str = ", ".join(int_ip_strs) if int_ip_strs else "internal source(s)"
                    evidence_instruction = (
                        f'State explicitly in root_cause: "In the last {window_days} days, VPC Flow Logs '
                        f'recorded {len(all_ips)} accepted inbound connection(s) on {port_str} '
                        f'from internal source IP(s): {ips_str}. '
                        f'All observed traffic is from RFC1918 addresses — no external connections detected."'
                    )

        elif ev_source == "cloudtrail":
             if not act_ev.get("logging_enabled", False):
                 evidence_instruction = 'Note in prerequisite_actions that CloudTrail logging must be enabled for this resource to trace access.'
             elif act_ev.get("exploitation_signals", []):
                 sigs = ", ".join(act_ev.get("exploitation_signals", []))
                 evidence_instruction = f'State explicitly in root_cause: "CloudTrail analysis detected suspicious exploitation signals: {sigs}. This suggests active compromise or probing."'
             else:
                 summary = act_ev.get("analyst_summary", "")
                 callers = act_ev.get("unique_callers", [])
                 caller_details = []
                 for c in callers:
                     u = c.get("username", "unknown")
                     ip = c.get("source_ip", "unknown")
                     caller_details.append(f"principal '{u}' (IP: {ip})")
                 
                 callers_str = ", ".join(caller_details) if caller_details else ""
                 if callers_str:
                     evidence_instruction = f'State explicitly in root_cause: "Recent CloudTrail access history was analyzed ({summary}). Observed callers: {callers_str}."'
                 else:
                     evidence_instruction = f'Note in root_cause: "Recent CloudTrail access history was analyzed. {summary}"'

                

        # Bug P4 fix: add fallback for resource types with no flow log or CloudTrail evidence

        # source (e.g. S3, EBS, IAM). Without this, evidence_instruction stays empty and the

        # prompt renders an empty "ACTIVITY EVIDENCE DIRECTIVE:" section, which is confusing

        # to the LLM and wastes prompt space. The fallback instructs the model to base its

        # analysis on configuration state only — accurate for non-network resource types.

        if not evidence_instruction:

            evidence_instruction = (

                "Analyse the context above and provide your RCA based on the configuration "

                "state and resource metadata provided. No real-time connection or access log "

                "data is available for this resource type — base your analysis on the "

                "configuration facts, resource tags, and the security brief above. "

                "Do not speculate about traffic patterns or access history."

            )

            if is_private:

                evidence_instruction += '\n  - Crucial: The instance is located in a private subnet (no internet route). The public IP is redundant and unreachable. Explicitly state that it is safe to remove the public IP without disconnecting live traffic.'

            else:

                evidence_instruction += '\n  - Crucial: The instance is in a public subnet. Recommend replacing direct SSH access with AWS SSM Session Manager and placing web traffic behind an ALB. Do NOT recommend blindly removing the public IP.'

            

        prompt = f"""You are a Cloud Security Architect performing Root Cause Analysis (RCA)
and remediation planning for an AWS compliance violation.

{mode_header}




=== VIOLATION DETAILS ===

CIS Control ID         : {control_id}

Control Name           : {control_name}

Resource ID            : {resource_id}

Resource Type          : {resource_type}

Operational Risk Score : {risk_pct}% ({risk_level})

Score Breakdown        : Severity={breakdown.get('compliance_severity',0)}, Env={breakdown.get('environment_criticality',0)}, Data={breakdown.get('data_sensitivity',0)}

Score Rationale        : {rationale}



=== SECURITY CONTEXT ===

{security_brief}



=== LIVE AWS CONTEXT ===

{context_summary}

{rollback_note}

=== YOUR TASK ===

Provide a structured Root Cause Analysis and remediation plan grounded in the context above.



IMPORTANT — ACTIVITY EVIDENCE DIRECTIVE:

{evidence_instruction}



{conf_note}
Respond ONLY in valid JSON — no markdown fences, no prose outside the JSON object:

{{
  "root_cause": "2 concise sentences max. State clearly: (1) what exact misconfiguration exists, and (2) its real-world exposure based on live context and observed access logs. Do NOT repeat words or invent IP addresses.",

  "business_impact": "1-2 sentences. Describe the real-world operational blast radius tailored specifically to the resource's environment (dev vs prod) and data sensitivity. For non-production (dev/test) environments, state that blast radius is isolated and low. For production environments, state the operational impact on live business workloads. Never claim a dev environment directly impacts production workloads.",

  "recommended_fix": "One sentence summarising the fix action.",

  "fix_steps": [
    "Step 1: ...",
    "Step 2: ...",
    "Step 3: ..."
  ],

  "prerequisite_actions": [
    "Action required BEFORE remediation — e.g. schedule maintenance window, notify stakeholders, obtain approval. For PROCEED with no dependencies: state 'None required.'"
  ],

  "operational_impact": "Specific downtime or dependency risks of applying the fix. For PROCEED with no attached workloads: state zero impact explicitly.",

  "safe_window": "Recommended UTC time window for applying the fix.",

  "rollback_steps": [
    "Step 1: How to revert the change if it causes an issue."
  ],

  "safety_verification": {{
    "architecturally_safe": true,
    "verification_rationale": "Direct 1-sentence factual verification of architectural safety. State facts directly (e.g. 'Static website hosting is disabled and traffic is 100% internal, so enabling BPA will not cause downtime') without meta-phrases like 'The gate justification is architecturally correct'."
  }},

  "gate_block_reason": {json.dumps(safety_reason or None)}
}}

"""

        return prompt.strip()



    # ═══════════════════════════════════════════════════════════════════════════

    #  NOTIFICATIONS

    # ═══════════════════════════════════════════════════════════════════════════



    def _notify_user(

        self,

        level: str,

        icon: str,

        header: str,

        control_id: str,

        resource_id: str,

        risk: dict,

        context: dict,

        extra: str = "",

    ):

        """Log a structured notification message for the admin/user."""

        attr     = context.get("attribution", {})

        actor    = attr.get("actor", "Unknown Actor")

        attr_ts  = attr.get("timestamp", "Unknown Time")



        msg = f"    → Decision: {icon} [{level}] {header}"

        if extra:

            msg += f"\n      [Note] {extra}\n"

        logger.info(msg)



    # ═══════════════════════════════════════════════════════════════════════════

    #  REPORTING

    # ═══════════════════════════════════════════════════════════════════════════



    def _build_report(self, processed_findings: list, scan_result) -> dict:

        """Build the final structured report."""

        risk_summary = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

        for f in processed_findings:

            level = f.get("risk", {}).get("risk_level", "HIGH")

            risk_summary[level] = risk_summary.get(level, 0) + 1



        return {

            "report_id":       f"RPT-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",

            "generated_at":    datetime.now(timezone.utc).isoformat(),

            "region":          self.region,

            "services_scanned": self.services,

            "scan_id":         getattr(scan_result, "scan_id", ""),

            "total_findings":  len(processed_findings),

            "risk_summary":    risk_summary,

            "findings":        processed_findings,

        }



    def _save_report(self, report: dict):

        """Persist the report to JSON, preserving full audit trail history across scans."""

        try:

            previous_findings = []

            if os.path.exists(REPORT_PATH):

                try:

                    with open(REPORT_PATH, "r", encoding="utf-8") as f:

                        prev_data = json.load(f)

                        previous_findings = prev_data.get("findings", [])

                except Exception as ex:

                    logger.warning(f"Could not read existing report for audit trail: {ex}")



            new_findings = report.get("findings", [])

            

            # Combine new findings with previous audit history

            combined_findings = list(new_findings)

            new_keys = {

                f"{f.get('control_id')}:{f.get('resource_id')}:{f.get('recorded_at', '')[:19]}"

                for f in new_findings

            }



            for prev_f in previous_findings:

                prev_key = f"{prev_f.get('control_id')}:{prev_f.get('resource_id')}:{prev_f.get('recorded_at', '')[:19]}"

                if prev_key not in new_keys:

                    combined_findings.append(prev_f)



            # Sort combined findings by recorded_at / processed_at descending (newest scan findings first)

            combined_findings.sort(

                key=lambda x: x.get("recorded_at") or x.get("processed_at") or report.get("generated_at") or "",

                reverse=True

            )



            report["findings"] = combined_findings

            report["total_findings"] = len(combined_findings)



            # Recalculate risk summary

            risk_summary = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}

            for f in combined_findings:

                level = f.get("risk", {}).get("risk_level", "HIGH")

                risk_summary[level] = risk_summary.get(level, 0) + 1

            report["risk_summary"] = risk_summary



            with open(REPORT_PATH, "w", encoding="utf-8") as f:

                json.dump(report, f, indent=2, default=str)

            logger.info(f"[STEP 3] Audit Trail Report saved ({len(combined_findings)} total findings) → {REPORT_PATH}")

        except Exception as e:

            logger.error(f"Failed to save report: {e}")



    def _print_summary(self, report: dict):

        """Print a human-readable summary to stdout."""

        risk = report["risk_summary"]

        print("\n" + "=" * 65)

        print("  ComplianceGuard — Scan Complete")

        print("=" * 65)

        print(f"  Report ID : {report['report_id']}")

        print(f"  Region    : {report['region']}")

        print(f"  Services  : {', '.join(report['services_scanned'])}")

        print(f"  Findings  : {report['total_findings']}")

        print(f"\n  Risk Breakdown:")

        print(f"    🔴 CRITICAL — {risk.get('CRITICAL', 0)}  (LLM RCA → Priority admin alert)")

        print(f"    🟠 HIGH     — {risk.get('HIGH', 0)}      (LLM RCA → Admin review)")

        print(f"    🟡 MEDIUM   — {risk.get('MEDIUM', 0)}    (Auto-remediated + user notified)")

        print(f"    🟢 LOW      — {risk.get('LOW', 0)}       (Auto-remediated + user notified)")

        print(f"\n  Report saved → {REPORT_PATH}")

        print("=" * 65)





# ═══════════════════════════════════════════════════════════════════════════════

#  CLI ENTRY POINT

# ═══════════════════════════════════════════════════════════════════════════════



if __name__ == "__main__":

    import argparse



    parser = argparse.ArgumentParser(

        description="ComplianceGuard — CIS Benchmark compliance scanner & AI remediation engine"

    )

    parser.add_argument("--region",   default="us-east-1", help="AWS region to scan")

    parser.add_argument("--profile",  default=None,        help="AWS CLI profile name")

    parser.add_argument(

        "--services", nargs="+",

        default=SERVICES_IN_SCOPE,

        choices=["s3", "iam", "ec2", "rds", "ebs"],

        help="Services to scan (default: all)"

    )

    parser.add_argument(

        "--dry-run", action="store_true",

        help="Skip actual AWS API remediation calls and LLM invocations"

    )

    parser.add_argument(

        "--skip-scan", action="store_true",

        help="Skip the scanning phase and process the existing scan_report.json directly (useful for testing injected traffic)"

    )



    args = parser.parse_args()

    orch = Orchestrator(

        region=args.region,

        profile=args.profile,

        services=args.services,

        dry_run=args.dry_run,

    )

    orch.skip_scan = args.skip_scan

    orch.run()

