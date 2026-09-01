"""
ComplianceGuard — Operational Risk Scorer

Score Label: Operational Risk Score

This score measures OPERATIONAL risk, not pure security severity.
The same vulnerability scores differently across environments because
the blast-radius and data exposure risk differ — that is deliberate.

Formula (3-Factor, Fixed Denominator):
    Operational Risk Score = Compliance Severity + Environment Criticality
                           + Data Sensitivity

    Risk % = (raw_score / 50) × 100   [MAX_SCORE = 50]

    The denominator is normalised to the maximum attainable points
    (Severity 15 + Environment 20 + Data 15 = 50), so the full 0–100%
    range is reachable and every risk band is meaningful.

Separation of Concerns — Why Dependencies Are NOT in the Score:
    Dependencies (attached instances, SG coupling, CloudFront, etc.) answer
    the question "how risky is FIXING this?" — not "how dangerous IS this?"
    That question is answered by the Remediation Safety Gate, which uses
    dependency context to make deterministic PROCEED/BLOCK decisions.
    Including dependencies in the score would double-count them (the gate
    already uses them) and caused the previous /65 denominator to leave
    15 points permanently unreachable for non-data resources.

Weight Justification (expert-designed heuristics, not ML-learned):
    Severity     (max 15): Importance of the CIS control — how critical is
                           this class of vulnerability to the security posture?
    Environment  (max 20): Operational blast-radius — prod affects real users;
                           dev is a sandbox. Highest weight because env tag
                           adoption (~95%) is reliable, and remediation safety
                           is the primary concern for an automation tool.
    Data         (max 15): Confidentiality impact — restricted/PII data
                           exposure compounds the severity of the violation.

Risk Bands (inclusive upper edge for deterministic routing):
    0–25%    → LOW      → Auto-remediate + notify
    >25–50%  → MEDIUM   → Auto-remediate + notify
    >50–75%  → HIGH     → LLM RCA → Admin review
    >75–100% → CRITICAL → LLM RCA → Priority alert

No LLM involved in scoring — this is pure deterministic logic.

Confidence Score (companion metric):
    Measures context completeness: if key metadata is missing (env tag,
    data classification tag), the system is scoring from assumptions.
    LOW confidence (<60%) forces human review regardless of risk band.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 DESIGN POLICY (explicit decisions, not emergent side-effects)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. ENVIRONMENT (max 20) > DATA SENSITIVITY (max 15)
   Environment is the blast-radius signal. A prod misconfiguration affects
   real users/data; a dev one affects a sandbox. Tags for `env` have higher
   adoption (~95%) than `data_classification` (~30-40%). Weighting the more
   reliable, higher-impact signal first means all high-severity prod
   violations reach admin review — a deliberately conservative policy for
   an automation tool that must never silently under-protect production.

2. ADDITIVE FORMULA (not multiplicative)
   Each factor contributes independently: "+15 because severity, +20 because
   prod, +15 because restricted" is a one-sentence explanation per factor.
   This mirrors CIS benchmark methodology and enables audit-ready reports.

3. DEPENDENCY CONTEXT → SAFETY GATE (not scorer)
   Dependency existence and type are evaluated by the Remediation Safety Gate
   (remediator.py), which makes the PROCEED/BLOCK decision. Dependencies are
   also passed to the LLM RCA for blast-radius narrative. They are NOT part
   of the risk score formula to avoid double-counting and to maintain a clean
   fixed denominator.

4. EMPTY RESOURCES: data_score = 0, severity downgraded to Low (5)
   Verified emptiness (via list_objects_v2 + list_object_versions) overrides
   data classification to 0. The misconfiguration exists but has zero
   exposure impact. Environment score is retained so a misconfigured empty
   prod bucket still outranks a dev one.

5. SECURITY GROUPS: data_score = 0 (always)
   A Security Group is a network control — it does not own or persist data.
   Data lives on the EC2 instance, EBS volume, or RDS behind it. Setting
   data_score = 0 for ALL SG findings prevents double-counting.

6. EC2 COMPUTE RESOURCES: data_score = 0
   EC2 instances are compute, not storage. Data lives on mounted EBS volumes
   or in S3 buckets, each with its own independent finding and data_score.

7. UNKNOWN DEFAULTS = WORST-CASE (fail-safe)
   Unknown env → Production (20). Unknown data_class → Restricted (15).
   Missing metadata must never silently downgrade risk.
   Exception: untagged S3 defaults to Internal (5), not Restricted.

8. TOPOLOGY IS CONTEXT, NOT A SCORE MODIFIER
   Subnet placement (private_isolated, private_peered) and CIDR exposure
   (restricted, private) are recorded in breakdown["_topology"] for the LLM
   and human reviewers. They do NOT modify any factor score.
   Reason: topology changes at any time (new IGW, new peering, route table edit)
   without triggering a compliance rescan. Scoring based on today's routing
   would silently under-report violations that become exploitable tomorrow.
   The Safety Gate (remediator.py) uses topology for PROCEED/BLOCK decisions,
   which is the right layer for operational context.
"""

import logging

logger = logging.getLogger(__name__)

# ── Max possible raw score ─────────────────────────────────────────────────────
MAX_SCORE = 50  # 15 (severity) + 20 (env) + 15 (data)  [fixed denominator]

# ── Compliance Severity scores per CIS control ────────────────────────────────
# Low = 5 | Medium = 10 | High = 15
CONTROL_SEVERITY: dict[str, int] = {
    # S3
    "CIS-2.1.4": 15,   # Public Access Enabled          — High
    "CIS-2.1.1": 10,   # Encryption Disabled            — Medium
    "CIS-2.1.5": 5,    # Versioning Not Enabled         — Low
    "CIS-2.1.2": 5,    # Access Logging Disabled        — Low

    # Security Groups
    "CIS-5.2":   15,   # SSH/RDP Open to Internet      — High
    "CIS-5.3":   10,   # Default SG Has Rules          — Medium
    "Org-SG-DB": 15,   # Database Port Exposed          — High

    # EC2
    "Org-5":     10,   # Direct Public IP Exposure      — Medium
    "CIS-5.6":   15,   # Public IP Exposure / IMDSv1    — High
    "CIS-5.7":   5,    # Detailed Monitoring Disabled   — Low

    # RDS & General SG Chaining
    "CIS-2.3.2": 15,   # Publicly Accessible            — High
    "CIS-2.3.1": 15,   # Storage Encryption Disabled    — High
    "Org-RDS-SG-Chain": 15, # RDS SG Chaining Violation   — High
    "Org-SG-Chain": 15,     # General SG Chaining Violation (e.g. EC2 SSH fallback) — High
    "CIS-2.3.3": 5,    # Minor Version Auto-Upgrade Off — Low

    # IAM
    "CIS-1.14":  15,   # Access Key Not Rotated >90d    — High
    "CIS-1.16":  15,   # Wildcard Permissions           — High
    "CIS-1.9":   5,    # Password Min Length < 14       — Low
}

# ── Environment criticality scores ────────────────────────────────────────────
# Policy: Environment is the blast-radius signal. Production outweighs data
# classification because: (a) env tags are more reliably present, (b) prod
# blast radius is real regardless of what data is tagged, (c) for a compliance
# automation tool, the question "will auto-fixing this break production?" is the
# primary gating concern.
ENVIRONMENT_SCORES: dict[str, int] = {
    "prod":        20,
    "production":  20,
    "live":        20,
    "staging":     12,
    "homol":       12,
    "dev":         5,
    "development": 5,
    "test":        5,
    "qa":          5,
}
ENVIRONMENT_DEFAULT = 20  # unknown env → assume PRODUCTION (worst-case / safe default)

# ── Data classification scores (3-tier model) ───────────────────────────────
# Public     = 0   → Data intentionally exposed to everyone
# Internal   = 5   → Internal business data, not for public consumption
# Restricted = 15  → PII, financial, healthcare, regulated data (GDPR/HIPAA)
DATA_CLASSIFICATION_SCORES: dict[str, int] = {
    "public":     0,
    "internal":   5,
    "restricted": 15,
    "regulated":  15,   # alias for restricted — PII, Financial, Healthcare
    "confidential": 15, # treat confidential same as restricted (safe default)
}
DATA_CLASSIFICATION_DEFAULT = 15  # unknown → assume RESTRICTED (worst-case / safe default)

# ── Dependency risk (graduated) ─────────────────────────────────────────────────
# Existence of coupling affects score. Type of coupling is handled by the Remediation Safety Gate.
DEP_NONE   = 0
DEP_SAFE   = 5
DEP_UNSAFE = 15

def _calc_dependency_risk(control_id: str, context: dict):
    if control_id == "CIS-2.1.1":
        return 0, ["encryption transparent to all consumers"], False, False
    
    connections = context.get("connections", {})
    deps = context.get("dependencies", [])
    attached = context.get("attached_instances", context.get("attached_to_instance"))
    
    found = []
    has_unsafe = False
    has_safe = False
    
    cf = connections.get("downstream", {}).get("cloudfront", False)
    oac = context.get("cloudfront_oac_enabled", False)
    if cf and not oac:
        has_unsafe = True
        found.append("cloudfront")
    elif cf and oac:
        has_safe = True
        found.append("cloudfront_oac")
        
    if connections.get("downstream", {}).get("website_hosting"):
        has_unsafe = True
        found.append("website_hosting")
    if connections.get("downstream", {}).get("public_assets_access"):
        has_unsafe = True
        found.append("public_assets")
        
    if connections.get("upstream", {}).get("raw_wildcard_policy"):
        has_unsafe = True
        found.append("wildcard_policy")
        
    if connections.get("downstream", {}).get("lambda_triggers"):
        has_safe = True
        found.append("lambda_triggers")
    if connections.get("upstream", {}).get("replication_source"):
        has_safe = True
        found.append("replication")
    if connections.get("upstream", {}).get("cross_account_iam"):
        has_safe = True
        found.append("cross_account_iam")
    if connections.get("upstream", {}).get("internal_aws_service"):
        has_safe = True
        found.append("internal_aws_service")
    if connections.get("upstream", {}).get("vpc_endpoint"):
        has_safe = True
        found.append("vpc_endpoint")
    if connections.get("upstream", {}).get("pre_signed_urls"):
        has_safe = True
        found.append("pre_signed_urls")
        
    if deps:
        has_unsafe = True
        found.append(f"{len(deps)} config_deps")
    if attached:
        has_unsafe = True
        found.append("attached_instance")
        
    if has_unsafe:
        risk = DEP_UNSAFE
    elif has_safe:
        risk = DEP_SAFE
    else:
        risk = DEP_NONE
        
    return risk, found if found else ["none detected"], has_unsafe, has_safe


# ─────────────────────────────────────────────────────────────────────────────
# CONFIDENCE SCORE
# Context completeness metric — companion to the Operational Risk Score.
# ─────────────────────────────────────────────────────────────────────────────

# Controls where data classification is Not Applicable.
# These are NETWORK controls (SGs, IAM) or COMPUTE resources (EC2) — they do
# not own the data themselves. The risk scorer already handles this via
# per-control overrides. The confidence score must reflect the same logic.
#
# NOT in this list: S3, RDS, EBS — these are data stores where the
# data_classification tag is directly meaningful and its absence is a gap.
_DATA_CLASS_NA_CONTROLS = {
    # Security Group controls — network resources, not data stores.
    # Data lives in the EC2/RDS instance ATTACHED to the SG, not on the SG itself.
    "CIS-5.2", "CIS-5.3", "Org-SG-DB",

    # EC2 instance controls — compute resources. Data is in EBS/S3, not the instance.
    "Org-5", "CIS-5.6", "CIS-5.7",

    # IAM controls — identity/access controls, no data ownership.
    "CIS-1.14", "CIS-1.16", "CIS-1.9",

    # NOTE: CIS-2.2.1, CIS-2.2.2 (EBS) intentionally REMOVED from this list.
    # EBS volumes ARE data stores. Missing data_classification tag on an EBS
    # volume is a genuine context gap and should reduce confidence.
}

# Confidence score weights — must sum to 100.
# Rebalanced from the original 40/40/10/10 design to better reflect
# what actually makes a gate decision reliable:
#   - Env tag (30): still highest weight — wrong env = wrong blast-radius
#   - Data class (30): wrong data assumption = confidentiality risk
#   - Context collected (20): upgraded — foundational API reachability
#   - Dependencies resolved (20): upgraded — attachment state is critical
#     for the Safety Gate to make correct PROCEED/BLOCK decisions
_CONF_WEIGHT_ENV       = 30
_CONF_WEIGHT_DATA      = 30
_CONF_WEIGHT_CTX       = 20
_CONF_WEIGHT_DEPS      = 20


def compute_confidence(control_id: str, context: dict, env_raw: str) -> dict:
    """
    Compute context completeness confidence score (0-100%).

    Measures how much reliable information the system had when scoring.
    When confidence is LOW, the system must not make autonomous decisions -
    its key inputs may be wrong defaults rather than real metadata.

    Factors (weights sum to 100):
      env tag present            30 pts  Highest weight: wrong env assumption
                                         invalidates the entire blast-radius score.
      data_class resolved        30 pts  Wrong data assumption = confidentiality risk.
                                         N/A for network/compute resources (full credit).
      context collected          20 pts  Did the AWS context APIs respond without error?
                                         Upgraded from 10 — foundational API reachability.
      dependencies resolved      20 pts  Was attachment/coupling state actually queried?
                                         Upgraded from 10 — critical input for gate decisions.
                                         NOTE: An empty result (no attachments) IS valid;
                                         we only penalise if the query was never attempted.

    Thresholds:
      >= 80  -> HIGH   -- automated decision is reliable
      65-79  -> MEDIUM -- proceed with caution, log warning
      < 65   -> LOW    -- force human review (insufficient context)
    """
    pts   = 0
    facts = {}

    # -- Factor 1: Environment tag (30 pts) -----------------------------------------------
    if env_raw and env_raw not in ("", "unknown"):
        pts += _CONF_WEIGHT_ENV
        facts["env_tag"] = {"present": True, "value": env_raw, "points": _CONF_WEIGHT_ENV}
    else:
        facts["env_tag"] = {
            "present": False, "value": None, "points": 0,
            "impact":  "Defaulted to PRODUCTION (20). Score may be over-estimated.",
        }

    # -- Factor 2: Data classification (30 pts) -------------------------------------------
    if control_id in _DATA_CLASS_NA_CONTROLS:
        # Network/compute resources: data classification is on the attached resource,
        # not the SG/IAM/EC2 itself. Give full credit — absence of tag is expected.
        pts += _CONF_WEIGHT_DATA
        facts["data_classification"] = {
            "present": True,
            "value":   "n/a (network or compute resource — data lives on attached resource)",
            "points":  _CONF_WEIGHT_DATA,
        }
    elif context.get("is_empty"):
        # Verified empty via API — state is known, not assumed.
        pts += _CONF_WEIGHT_DATA
        facts["data_classification"] = {
            "present": True, "value": "empty (api-verified)", "points": _CONF_WEIGHT_DATA,
        }
    else:
        tags   = context.get("tags", {})
        tags_lower = {str(k).lower(): str(v) for k, v in tags.items()}
        dc_raw = tags_lower.get(
            "data_classification",
            tags_lower.get("dataclassification",
            tags_lower.get("data-classification",
            tags_lower.get("classification",
            tags_lower.get("data", ""))))
        ).lower().strip()
        if dc_raw and dc_raw not in ("", "unknown", "empty_resource"):
            pts += _CONF_WEIGHT_DATA
            facts["data_classification"] = {
                "present": True, "value": dc_raw, "points": _CONF_WEIGHT_DATA,
            }
        else:
            facts["data_classification"] = {
                "present": False, "value": None, "points": 0,
                "impact":  "Defaulted to RESTRICTED (15). Score may be over-estimated.",
            }

    # -- Factor 3: Context collected successfully (20 pts) --------------------------------
    ctx_ok = bool(context) and "error" not in context
    if ctx_ok:
        pts += _CONF_WEIGHT_CTX
        facts["context_collected"] = {"success": True, "points": _CONF_WEIGHT_CTX}
    else:
        facts["context_collected"] = {
            "success": False, "points": 0,
            "impact":  "Context collection failed — scoring from assumptions only.",
        }

    # -- Factor 4: Dependencies resolved (20 pts) -----------------------------------------
    # A dependency query is considered resolved if the key was explicitly populated
    # in the context (even if empty — empty list means no attachments, which is valid).
    # We only penalise if the query was never attempted at all.
    #
    # Bug B fix: removed "'connections' in context" from this check.
    # 'connections' is always present — it is initialised in base_context at the top of
    # ContextCollector.collect() for EVERY finding type:
    #   base_context = {"connections": {"downstream": {}, "upstream": {}, ...}}
    # This meant Factor 4 always scored 20/20, overstating confidence by up to 20 points
    # for IAM, S3, and RDS findings where the attachment query never ran.
    # The check now requires actual populated attachment data or non-empty connection dicts.
    deps_resolved = (
        "attached_instances" in context                           # SG/EC2: ENI query ran
        or context.get("dependencies") is not None               # RDS: explicit dep list
        or bool(context.get("connections", {}).get("downstream"))  # S3: real downstream data
        or bool(context.get("connections", {}).get("upstream"))    # S3: real upstream data
    )
    if deps_resolved:
        pts += _CONF_WEIGHT_DEPS
        facts["dependencies"] = {"resolved": True, "points": _CONF_WEIGHT_DEPS}
    else:
        facts["dependencies"] = {
            "resolved": False, "points": 0,
            "impact":   "Dependency/attachment state unknown — coupling may exist.",
        }

    # ── Build human-readable warnings list for the dashboard ─────────────────
    # These replace the abstract confidence score in the UI.
    # Each entry is a plain-English description of exactly what was assumed.
    warnings = []
    if not facts.get("env_tag", {}).get("present", True):
        warnings.append("env tag missing — environment defaulted to PRODUCTION (score may be over-estimated)")
    if not facts.get("data_classification", {}).get("present", True):
        warnings.append("data_classification tag missing — data sensitivity defaulted to RESTRICTED (score may be over-estimated)")
    if not facts.get("context_collected", {}).get("success", True):
        warnings.append("AWS context API failed — scoring from assumptions only, not live resource state")
    if not facts.get("dependencies", {}).get("resolved", True):
        warnings.append("attachment/dependency state unknown — coupling risk not confirmed")

    # ── Band and routing recommendation ──────────────────────────────────────
    if pts >= 80:
        band           = "HIGH"
        recommendation = "Context is complete. Automated decision is reliable."
        force_review   = False
    elif pts >= 65:
        band           = "MEDIUM"
        recommendation = "Partial context. Proceeding with caution — verify flagged assumptions."
        force_review   = False
    else:
        band           = "LOW"
        recommendation = (
            "Insufficient context for autonomous decision. "
            "Key metadata is missing — defaulted values may misrepresent actual risk. "
            "Routing to human review."
        )
        force_review = True

    return {
        "score":              pts,
        "band":               band,
        "recommendation":     recommendation,
        "factors":            facts,
        "warnings":           warnings,
        "force_human_review": force_review,
    }


def score(control_id: str, context: dict) -> dict:
    """
    Calculate the operational risk score for a CIS violation.

    Args:
        control_id:  e.g. "CIS-2.1.4"
        context:     Full context snapshot from ContextCollector

    Returns:
        dict with:
            raw_score       — integer 0–50
            risk_pct        — float 0–100
            risk_level      — "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
            breakdown       — per-factor scores
            rationale       — human-readable explanation
    """
    breakdown: dict[str, int] = {}

    # ── Factor 1: Compliance Severity ────────────────────────────────────────
    severity_score = CONTROL_SEVERITY.get(control_id, 10)  # default: Medium
    breakdown["compliance_severity"] = severity_score

    # ── Factor 2: Environment Criticality ────────────────────────────────────
    tags = context.get("tags", {})
    tags_lower = {str(k).lower(): str(v) for k, v in tags.items()}
    env_raw = tags_lower.get("env", tags_lower.get("environment", "")).lower().strip()

    env_score = ENVIRONMENT_SCORES.get(env_raw, ENVIRONMENT_DEFAULT)
    breakdown["environment_criticality"] = env_score
    breakdown["_env_tag"] = env_raw or "unknown"

    # ── Factor 3: Data Sensitivity ────────────────────────────────────────────
    # If the bucket is verified empty (via list_objects_v2), data exposure risk
    # is zero — same as explicitly public data. No additional discount beyond
    # zeroing the data score (Policy Decision #4).
    is_empty = context.get("is_empty", False)

    if is_empty:
        data_class_raw = "empty_resource"
        data_score = 0
        severity_score = 5  # Downgrade severity to Low since there is no exposure impact
        breakdown["compliance_severity"] = severity_score
        breakdown["_is_empty"] = True
        breakdown["_data_classification"] = "empty_resource"
    else:
        data_class_raw = tags_lower.get(
            "data_classification",
            tags_lower.get("dataclassification",
            tags_lower.get("data-classification",
            tags_lower.get("classification", 
            tags_lower.get("data", ""))))
        ).lower().strip()
        if not data_class_raw and control_id.startswith("CIS-2.1."):
            data_score = 5  # Exception: untagged S3 defaults to Internal (5)
            breakdown["_data_classification"] = "internal (default for untagged S3)"
        else:
            data_score = DATA_CLASSIFICATION_SCORES.get(data_class_raw, DATA_CLASSIFICATION_DEFAULT)
            breakdown["_data_classification"] = data_class_raw or "unknown"
        breakdown["_is_empty"] = False

    breakdown["data_sensitivity"] = data_score

    # ── Contextual Overrides for Non-S3 Resources (Handling Missing Tags) ─────
    if control_id == "CIS-1.14":
        # IAM Keys: Do not store data.
        data_score = 0
        breakdown["data_sensitivity"] = 0
        breakdown["_data_classification"] = "not_applicable (iam_key)"
        if not env_raw:
            env_score = 5  # default to dev for unknown IAM env
            breakdown["environment_criticality"] = env_score
            breakdown["_env_tag"] = "dev (default for IAM)"

    elif control_id in ("CIS-5.2", "Org-SG-DB", "CIS-5.3"):
        # Security Groups NEVER own data — data lives on attached resources (EC2/EBS/RDS).
        # data_score is always 0, regardless of attachment state (Policy #5).
        #
        # Risk of backend data is captured by:
        #   - dep_score: attached instances → DEP_UNSAFE = 15
        #   - The backend resource's own independent finding (with its own data_score)
        # Propagating data_class from backend → SG would double-count and is
        # logistically ambiguous (one SG can protect resources of mixed classifications).
        #
        # env_score is NOT discounted: a dangling prod SG is a real compliance posture
        # risk — it can be attached to a new instance at any time.
        data_score = 0
        breakdown["data_sensitivity"] = 0
        if not context.get("attached_instances"):
            breakdown["_data_classification"] = "dangling_sg (no attached instances — zero data exposure)"
            breakdown["_dangling_sg"] = True
        else:
            breakdown["_data_classification"] = "not_applicable (security_group — data lives on attached resource)"
            
        # Topology context — recorded for LLM/human context only, NOT used to modify score.
        # The compliance violation exists regardless of subnet placement: a rule allowing
        # 0.0.0.0/0 on SSH is a policy failure whether or not today's routing makes it
        # reachable. Topology can change (new IGW, new peering) without triggering a rescan.
        if context.get("cidr_exposure") == "internet":
            breakdown["_cidr_exposure"] = "internet"
            if context.get("has_public_alb_proxy"):
                breakdown["_topology"] = "public_alb_proxy"
            elif context.get("is_private_subnet"):
                if context.get("is_peered_network"):
                    breakdown["_topology"] = "private_peered"
                else:
                    breakdown["_topology"] = "private_isolated"
            else:
                breakdown["_topology"] = "public_subnet"

        elif context.get("cidr_exposure") == "restricted":
            breakdown["_cidr_exposure"] = "restricted"

    elif control_id in ("Org-5", "CIS-5.6", "CIS-5.7"):
        # EC2 is compute, not storage — data lives on EBS volumes or S3 (Policy #6).
        # data_score = 0. The EBS/S3 resources carry their own findings and data_scores.
        # Applying a data_score here would double-count the same underlying data risk.
        data_score = 0
        breakdown["data_sensitivity"] = 0
        breakdown["_data_classification"] = "not_applicable (ec2_compute — data lives on EBS/S3)"

        # Topology context — recorded for LLM/human context only, NOT used to modify score.
        # A public IP on an instance in a private subnet is unreachable today, but the
        # violation is real: topology changes (new IGW, new route table) are not scanned.
        # Score reflects the compliance fact, not the current routing state.
        if control_id == "Org-5":
            if context.get("is_private_subnet", False):
                if context.get("is_peered_network", False):
                    breakdown["_topology"] = "private_peered"
                else:
                    breakdown["_topology"] = "private_isolated"
            else:
                breakdown["_topology"] = "public_subnet"

            # ALB proxy: instance is directly internet-reachable AND behind a load balancer.
            # Both paths exist simultaneously — high risk (attacker can bypass ALB/WAF).
            if context.get("has_public_alb_proxy"):
                breakdown["_alb_bypass_risk"] = True


    elif control_id in ("CIS-2.3.1", "CIS-2.3.2"):
        # RDS: Stores data, so explicitly default to restricted (15).
        if not data_class_raw:
            data_score = 15
            breakdown["data_sensitivity"] = 15
            breakdown["_data_classification"] = "restricted (default for RDS)"
            
        # Topology context — recorded so the LLM RCA has subnet-level context.
        # sg_cidr_exposure is informational only; it does NOT modify the score.
        if context.get("sg_cidr_exposure") == "private":
            breakdown["_rds_sg_exposure"] = "private"

    # ── Dependency Context (for Safety Gate & LLM — NOT part of score) ────────
    # Dependencies answer "how risky is fixing this?" — handled by the Safety
    # Gate. Kept in breakdown so the gate and LLM can reference them.
    dep_score, found_connections, has_unsafe, has_safe = _calc_dependency_risk(control_id, context)
    # Bug C fix: renamed from "dependency_context" (integer without _ prefix) to
    # "_dep_coupling_note" to match the _ convention for all non-score metadata fields.
    # The integer 15 (DEP_UNSAFE) was confusingly adjacent to compliance_severity=15,
    # environment_criticality=20, data_sensitivity=15 — implying it contributed to
    # raw_score. It does not. raw_score = severity + env + data only (no dep term).
    breakdown["_dep_coupling_note"] = dep_score   # 0=none, 5=safe, 15=unsafe — metadata only
    breakdown["_has_unsafe_deps"] = has_unsafe
    breakdown["_has_safe_deps"] = has_safe
    breakdown["_connections_detail"] = found_connections

    # ── Total & Normalise (3-Factor Fixed Denominator) ────────────────────────
    # Score = (Severity + Environment + Data) / 50 × 100
    # Dependencies are excluded from the score — they live in the Safety Gate.
    raw_score = severity_score + env_score + data_score
    raw_score = max(0, min(raw_score, MAX_SCORE))
    risk_pct  = round((raw_score / MAX_SCORE) * 100, 1)

    # ── Risk Band ─────────────────────────────────────────────────────────────
    if risk_pct <= 25:
        risk_level = "LOW"
    elif risk_pct <= 50:
        risk_level = "MEDIUM"
    elif risk_pct <= 75:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    rationale = _build_rationale(control_id, risk_level, breakdown, raw_score, risk_pct)

    # ── Confidence Score ─────────────────────────────────────────────────────
    # Companion metric: measures how complete the context was when scoring.
    # Passed to orchestrator so it can override AUTO routing if confidence is LOW.
    confidence = compute_confidence(control_id, context, env_raw)

    result = {
        "score_label": "Operational Risk Score",
        "control_id":  control_id,
        "raw_score":   raw_score,
        "max_score":   MAX_SCORE,
        "risk_pct":    risk_pct,
        "risk_level":  risk_level,
        "breakdown":   breakdown,
        "rationale":   rationale,
        "confidence":  confidence,
    }

    conf_badge = f"[Confidence: {confidence['band']} {confidence['score']}%]"
    if confidence["force_human_review"]:
        logger.warning(
            f"[RiskScorer] {control_id} → {raw_score}/{MAX_SCORE} ({risk_pct}%) "
            f"= {risk_level} {conf_badge} ⚠ LOW CONFIDENCE — will override to human review"
        )
    else:
        logger.info(
            f"[RiskScorer] {control_id} → {raw_score}/{MAX_SCORE} ({risk_pct}%) "
            f"= {risk_level} {conf_badge} | env={breakdown['_env_tag']}, "
            f"data={breakdown['_data_classification']}"
        )
    return result


def _build_rationale(
    control_id: str,
    risk_level: str,
    breakdown: dict,
    raw_score: int,
    risk_pct: float,
) -> str:
    """Build a concise human-readable explanation of the score."""
    parts = []

    sev = breakdown.get("compliance_severity", 0)
    if sev >= 15:
        parts.append("High-severity CIS control violation")
    elif sev >= 10:
        parts.append("Medium-severity CIS control violation")
    else:
        parts.append("Low-severity CIS control violation")

    env = breakdown.get("_env_tag", "unknown")
    if env.lower() in ("prod", "production", "live") or env == "unknown":
        parts.append(f"running in Production environment ({env})")
    else:
        parts.append(f"running in non-production environment ({env})")

    data = breakdown.get("_data_classification", "unknown")
    dc   = breakdown.get("data_sensitivity", 0)
    if breakdown.get("_is_empty"):
        parts.append(f"Verified empty resource — no data at risk ({data})")
    elif data.startswith("not_applicable") or data.startswith("dangling_sg"):
        parts.append(f"Data exposure not applicable ({data})")
    elif dc >= 15:
        parts.append(f"Restricted data classification — PII/regulated ({data})")
    elif dc >= 5:
        parts.append(f"Internal data classification ({data})")
    else:
        parts.append(f"Public data classification ({data})")

    if breakdown.get("_has_unsafe_deps") or breakdown.get("_has_safe_deps"):
        parts.append(f"resource has dependencies ({', '.join(breakdown.get('_connections_detail', []))})")
    if breakdown.get("_is_empty"):
        parts.append("Note: Resource is verified empty — no data at risk, risk score is at baseline")
        
    topol = breakdown.get("_topology")
    if topol == "public_alb_proxy":
        parts.append("Warning: Private instance is directly accessible via Public ALB proxy")
    elif topol == "private_peered":
        if control_id == "Org-5":
            parts.append("Context: Instance holds a Public IP in a private subnet peered to Transit/VPN gateways — significant internal blast radius; rule scored at full value")
        elif control_id == "CIS-2.3.2":
            parts.append("Context: Database flagged publicly accessible in a private subnet peered to Transit/VPN gateways — internally reachable; scored at full value")
        else:
            parts.append("Context: SG internet-open rule in a peered private subnet — laterally reachable via Transit/VPN gateways; scored at full value")
    elif topol == "private_isolated":
        if control_id == "Org-5":
            parts.append("Context: Instance holds a Public IP in an isolated private subnet (no IGW route today) — topology noted but rule scored at full compliance value")
        elif control_id == "CIS-2.3.2":
            parts.append("Context: Database flagged publicly accessible in an isolated private subnet — topology noted but scored at full compliance value")
        else:
            parts.append("Context: SG internet-open rule in an isolated private subnet (no IGW route today) — topology noted but scored at full compliance value")

    max_score = MAX_SCORE
    return (
        f"Total Contextual Risk Score: {raw_score}/{max_score} ({risk_pct}%) → {risk_level}. "
        + "; ".join(parts) + "."
    )
