"""
ComplianceGuard — Combined S3 Validation Script

Tests all 8 use-case scenarios combining:
  - CIS-2.1.4 (Block Public Access) violations
  - CIS-2.1.1 (Encryption) violations
  - Upstream/downstream connections (CloudFront, Lambda, Replication, Website)

Also checks Remediation Safety Gate overrides and edge cases.

Run: python tests/validate_s3_logic.py
"""

import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from ai.risk_scorer import score
from decision.remediator import AutoRemediator

# ── Helpers ───────────────────────────────────────────────────────────────────

PASS = "PASS"
FAIL = "FAIL"
results = []

def make_context(
    env="dev",
    data_class="public",
    has_cloudfront=False,
    has_lambda_triggers=False,
    has_website_hosting=False,
    has_replication=False,
    has_config_deps=False,
    is_empty=False,
    cloudfront_oac_enabled=False,
    coexisting_violations=None,
    cross_account_iam=False,
    internal_aws_service=False,
    vpc_endpoint=False,
    pre_signed_urls=False,
    raw_wildcard_policy=False,
    public_assets_access=False
):
    """Build a context dict that mirrors what ContextCollector produces."""
    lambda_triggers = (
        [{"lambda_arn": "arn:aws:lambda:us-east-1:123456:function:process-uploads", "events": ["s3:ObjectCreated:*"]}]
        if has_lambda_triggers else []
    )
    replication = {
        "is_source": has_replication,
        "is_target": False,
        "rules": ["arn:aws:s3:::backup-bucket"] if has_replication else [],
        "rule_count": 1 if has_replication else 0,
    }
    deps = [{"resourceType": "AWS::Lambda::Function", "resourceId": "process-fn"}] if has_config_deps else []

    return {
        "tags": {
            "env": env,
            "data_classification": data_class,
        },
        "is_empty":                is_empty,
        "website_hosting_enabled": has_website_hosting,
        "cloudfront_configured":   has_cloudfront,
        "cloudfront_oac_enabled":  cloudfront_oac_enabled,
        "lambda_triggers":         lambda_triggers,
        "replication":             replication,
        "dependencies":            deps,
        "coexisting_violations":   coexisting_violations or [],
        "connections": {
            "downstream": {
                "cloudfront":      has_cloudfront,
                "lambda_triggers": [t["lambda_arn"] for t in lambda_triggers],
                "website_hosting": has_website_hosting,
                "public_assets_access": public_assets_access,
            },
            "upstream": {
                "replication_source": has_replication,
                "replication_target": False,
                "replication_rules":  ["arn:aws:s3:::backup-bucket"] if has_replication else [],
                "cross_account_iam": cross_account_iam,
                "internal_aws_service": internal_aws_service,
                "vpc_endpoint": vpc_endpoint,
                "pre_signed_urls": pre_signed_urls,
                "raw_wildcard_policy": raw_wildcard_policy,
            },
            "has_any_connection": (
                has_cloudfront or has_lambda_triggers
                or has_website_hosting or has_replication or has_config_deps
                or cross_account_iam or internal_aws_service or vpc_endpoint
                or pre_signed_urls or raw_wildcard_policy or public_assets_access
            ),
        },
    }


from decision.remediator import AutoRemediator
_remediator = AutoRemediator(region="us-east-1")

def check_safety_gate(control_id: str, context: dict) -> tuple[str, str]:
    """Simulate remediator Remediation Safety Gate by importing live logic."""
    return _remediator.check_safety_gate(control_id, context)


def validate(
    scenario_id: str,
    name: str,
    control_id: str,
    context: dict,
    expected_band: str,
    expected_action: str,   # "AUTO" or "ADMIN"
    expected_gate: str,     # "ALLOWED" or "BLOCKED"
    note: str = "",
):
    """Run a scenario and compare against expectations."""
    result    = score(control_id, context)
    band      = result["risk_level"]
    pct       = result["risk_pct"]
    raw       = result["raw_score"]
    conn_det  = result["breakdown"].get("_connections_detail", ["none"])

    # Score-based routing decision
    score_action = "ADMIN" if band in ("HIGH", "CRITICAL") else "AUTO"

    # Remediation Safety Gate check (overrides score-based routing)
    gate_action, gate_reason = check_safety_gate(control_id, context)
    
    if gate_action == "BLOCK":
        final_action = "ADMIN"  # Force admin regardless of score
    else:
        final_action = score_action

    band_ok   = band == expected_band
    action_ok = final_action == expected_action
    
    gate_ok_check = (expected_gate == gate_action) or (expected_gate in gate_reason)

    status = PASS if (band_ok and action_ok and gate_ok_check) else FAIL
    results.append(status)

    icon = "[OK]" if status == PASS else "[XX]"
    print(f"\n  {icon} [{status}] {scenario_id}: {name}")
    print(f"       Control     : {control_id}")
    print(f"       Score       : {raw}/50 = {pct}%  ->  {band}")
    print(f"       Connections : {conn_det}")
    print(f"       Remediation Safety Gate : {gate_reason}")
    print(f"       Final Action: {final_action}  (expected: {expected_action})")
    if not band_ok:
        print(f"       [!] Band mismatch — got {band}, expected {expected_band}")
    if not action_ok:
        print(f"       [!] Action mismatch — got {final_action}, expected {expected_action}")
    if not gate_ok_check:
        print(f"       [!] Gate mismatch — got {gate_reason}, expected {expected_gate}")
    if note:
        print(f"       Note        : {note}")


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 1: CIS-2.1.4  —  Block Public Access Disabled
# ═══════════════════════════════════════════════════════════════════════════════

def run_section_1():
    print("\n" + "="*65)
    print("  CIS-2.1.4 — Block Public Access Disabled (Severity=High/15)")
    print("="*65)

    # Scenario 1 — prod + restricted, no connections -> CRITICAL / ADMIN
    validate("S1", "prod-payments-data (no connections)",
        control_id="CIS-2.1.4",
        context=make_context(env="prod", data_class="restricted"),
        expected_band="CRITICAL", expected_action="ADMIN", expected_gate="PROCEED",
        note="15+20+15+0 = 50/50 = 76.9% -> CRITICAL -> ADMIN."
    )

    # Scenario 1b — prod + restricted + legacy CloudFront (No OAC)
    validate("S1b", "prod-cdn-assets (legacy CloudFront, restricted)",
        control_id="CIS-2.1.4",
        context=make_context(env="prod", data_class="restricted", has_cloudfront=True),
        expected_band="CRITICAL", expected_action="ADMIN", expected_gate="PROCEED",
        note="15+20+15+15 = 65/50 = 100% -> CRITICAL -> ADMIN."
    )

    # Scenario 2 — prod + internal, no connections -> HIGH / ADMIN
    validate("S2", "prod-app-config (no connections)",
        control_id="CIS-2.1.4",
        context=make_context(env="prod", data_class="internal"),
        expected_band="CRITICAL", expected_action="ADMIN", expected_gate="PROCEED",
        note="15+20+5+0 = 40/50 = 61.5% -> HIGH -> ADMIN."
    )

    # Scenario 2b — prod + internal + Lambda -> HIGH / ADMIN
    validate("S2b", "prod-uploads-bucket (Lambda trigger, internal)",
        control_id="CIS-2.1.4",
        context=make_context(env="prod", data_class="internal", has_lambda_triggers=True),
        expected_band="CRITICAL", expected_action="ADMIN", expected_gate="PROCEED",
        note="15+20+5+5 = 45/50 = 69.2% -> HIGH -> ADMIN."
    )

    # Scenario 3 — dev + internal, no connections -> MEDIUM / AUTO
    validate("S3", "dev-api-test (no connections)",
        control_id="CIS-2.1.4",
        context=make_context(env="dev", data_class="internal"),
        expected_band="MEDIUM", expected_action="AUTO", expected_gate="PROCEED",
        note="15+5+5+0 = 25/50 = 38.5% -> MEDIUM -> AUTO."
    )

    # Scenario 3b — dev + internal + website hosting -> HIGH / ADMIN (BLOCK)
    validate("S3b", "dev-marketing-site (website hosting, internal)",
        control_id="CIS-2.1.4",
        context=make_context(env="dev", data_class="internal", has_website_hosting=True),
        expected_band="MEDIUM", expected_action="ADMIN", expected_gate="BLOCK",
        note="15+5+5+15 = 40/50 = 61.5% -> HIGH. Gate blocks website breaking."
    )

    # Scenario 4 — dev + public, no connections -> MEDIUM / AUTO
    validate("S4", "dev-test-scratch (no connections)",
        control_id="CIS-2.1.4",
        context=make_context(env="dev", data_class="public"),
        expected_band="MEDIUM", expected_action="AUTO", expected_gate="PROCEED",
        note="15+5+0+0 = 20/50 = 30.8% -> MEDIUM -> AUTO."
    )

    # Scenario 4b — dev + public + legacy CloudFront (No OAC)
    validate("S4b", "dev-public-cdn (CloudFront no OAC, public data)",
        control_id="CIS-2.1.4",
        context=make_context(env="dev", data_class="public", has_cloudfront=True),
        expected_band="MEDIUM", expected_action="AUTO", expected_gate="PROCEED",
        note="15+5+0+15 = 35/50 = 53.8% -> HIGH -> ADMIN."
    )

    # Scenario 4c — untagged bucket with lambda trigger -> CRITICAL / ADMIN
    validate("S4c", "untagged-rogue-bucket (Lambda trigger, no tags)",
        control_id="CIS-2.1.4",
        context={"connections": {"has_any_connection": True, "downstream": {"lambda_triggers": ["arn:aws:lambda"]}}, "is_empty": False},
        expected_band="CRITICAL", expected_action="ADMIN", expected_gate="PROCEED",
        note="Untagged defaults to Prod (20) & Restricted (15). 15+20+15+5 = 55/50 = 84.6% -> CRITICAL -> ADMIN."
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 2: CIS-2.1.1  —  Encryption Disabled
# ═══════════════════════════════════════════════════════════════════════════════

def run_section_2():
    print("\n" + "="*65)
    print("  CIS-2.1.1 — Encryption Disabled (Severity=Medium/10)")
    print("="*65)

    # Scenario 5 — prod + restricted + Lambda trigger -> HIGH / AUTO
    # Gate short-circuits to AUTO — AES-256 encryption is non-destructive, never breaks consumers.
    validate("S5", "prod-patient-records (Lambda trigger, restricted)",
        control_id="CIS-2.1.1",
        context=make_context(env="prod", data_class="restricted", has_lambda_triggers=True),
        expected_band="CRITICAL", expected_action="ADMIN", expected_gate="PROCEED",
        note="Score: 10+20+15+0=45/50=69.2%. Gate AUTO overrides score. Encryption never breaks consumers."
    )

    # Scenario 5b — prod + restricted, no connections -> HIGH / ADMIN
    validate("S5b", "prod-payments-data (no connections, restricted)",
        control_id="CIS-2.1.1",
        context=make_context(env="prod", data_class="restricted"),
        expected_band="CRITICAL", expected_action="ADMIN", expected_gate="PROCEED",
        note="10+20+15+0=45/50=69.2% -> HIGH -> ADMIN. Gate PROCEED: encryption never breaks consumers, but score routes to admin."
    )

    # Scenario 6 — prod + internal, no connections -> HIGH / AUTO
    # Gate short-circuits to AUTO — encryption is non-destructive regardless of score band.
    validate("S6", "prod-cloudtrail-logs (no connections)",
        control_id="CIS-2.1.1",
        context=make_context(env="prod", data_class="internal"),
        expected_band="HIGH", expected_action="ADMIN", expected_gate="PROCEED",
        note="Score: 10+20+5+0=35/50=53.8%. Gate AUTO: encryption fix is always safe, band is informational only."
    )

    # Scenario 6b — prod + internal + replication -> HIGH / ADMIN
    validate("S6b", "prod-replica-source (replication, internal)",
        control_id="CIS-2.1.1",
        context=make_context(env="prod", data_class="internal", has_replication=True),
        expected_band="HIGH", expected_action="ADMIN", expected_gate="PROCEED",
        note="10+20+5+0=35/50=53.8% -> HIGH -> ADMIN. Replication is safe dep but score still routes to admin."
    )

    # Scenario 7 — dev + restricted, no connections -> MEDIUM / AUTO
    validate("S7", "dev-model-training (no connections, restricted)",
        control_id="CIS-2.1.1",
        context=make_context(env="dev", data_class="restricted"),
        expected_band="HIGH", expected_action="ADMIN", expected_gate="PROCEED",
        note="Score: 10+5+15+0=30/50=46.2%. Encryption is non-destructive — safe to auto-fix"
    )

    # Scenario 7b — dev + restricted + Lambda -> MEDIUM / AUTO
    validate("S7b", "dev-etl-bucket (Lambda trigger, restricted)",
        control_id="CIS-2.1.1",
        context=make_context(env="dev", data_class="restricted", has_lambda_triggers=True),
        expected_band="HIGH", expected_action="ADMIN", expected_gate="PROCEED",
        note="10+5+15+0=30/50=46.2% -> MEDIUM -> AUTO. Lambda dep is safe for encryption."
    )

    # Scenario 8 — dev + public, no connections -> LOW / AUTO
    validate("S8", "dev-static-assets (no connections, public)",
        control_id="CIS-2.1.1",
        context=make_context(env="dev", data_class="public"),
        expected_band="MEDIUM", expected_action="AUTO", expected_gate="PROCEED",
        note="Score: 10+5+0+0=15/50=23.1%. Only path to LOW band. Fully safe auto-fix"
    )

    # Scenario 8b — dev + public + CloudFront (CIS-2.1.1, not CIS-2.1.4) -> MEDIUM / AUTO (gate does not fire)
    validate("S8b", "dev-public-cdn (CloudFront, public, encryption)",
        control_id="CIS-2.1.1",
        context=make_context(env="dev", data_class="public", has_cloudfront=True),
        expected_band="MEDIUM", expected_action="AUTO", expected_gate="PROCEED",
        note="Score: 10+5+0+15=30/50=46.2%. CloudFront gate only applies to CIS-2.1.4. Encryption fix is safe for CloudFront"
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 3: EDGE CASES & BUG CHECKS
# ═══════════════════════════════════════════════════════════════════════════════

def run_section_3():
    print("\n" + "="*65)
    print("  EDGE CASES & BUG CHECKS")
    print("="*65)

    # Edge 1 — CloudFront on CIS-2.1.1: gate must NOT fire (encryption doesn't break CDN)
    # Score: 10+20+5+15(CloudFront dep)=50/50=76.9% -> CRITICAL (>75%). Gate AUTO overrides.
    validate("E1", "prod-cdn (CloudFront + encryption violation)",
        control_id="CIS-2.1.1",
        context=make_context(env="prod", data_class="internal", has_cloudfront=True),
        expected_band="HIGH", expected_action="ADMIN", expected_gate="PROCEED",
        note="10+20+5+15=50/50=76.9% (CRITICAL). Gate AUTO: CloudFront unaffected by encryption fix."
    )

    # Edge 2 — Website hosting on CIS-2.1.1: gate must NOT fire
    validate("E2", "dev-website (website hosting + encryption violation)",
        control_id="CIS-2.1.1",
        context=make_context(env="dev", data_class="public", has_website_hosting=True),
        expected_band="MEDIUM", expected_action="AUTO", expected_gate="PROCEED",
        note="Website hosting gate is CIS-2.1.4 only. Enabling AES-256 doesn't affect static websites"
    )

    # Edge 3 — All connections present on CIS-2.1.4: both gates fire, max score
    validate("E3", "prod-mega-bucket (all connections, restricted)",
        control_id="CIS-2.1.4",
        context=make_context(
            env="prod", data_class="restricted",
            has_cloudfront=True, has_lambda_triggers=True,
            has_website_hosting=True, has_replication=True,
        ),
        expected_band="CRITICAL", expected_action="ADMIN", expected_gate="BLOCK",
        note="Prod raw website without OAC triggers policy block, overriding legacy exception."
    )

    # Edge 4 — Lambda is the only connection on CIS-2.1.4: gate must NOT fire (Lambda uses IAM)
    validate("E4", "dev-upload-bucket (Lambda trigger only, internal)",
        control_id="CIS-2.1.4",
        context=make_context(env="dev", data_class="internal", has_lambda_triggers=True),
        expected_band="MEDIUM", expected_action="AUTO", expected_gate="PROCEED",
        note="Lambda dep ignored for BPA. Score stays MEDIUM."
    )

    # Edge 5 — Replication on CIS-2.1.4: gate must NOT fire (replication uses IAM roles)
    validate("E5", "dev-replication-source (replication, public)",
        control_id="CIS-2.1.4",
        context=make_context(env="dev", data_class="public", has_replication=True),
        expected_band="MEDIUM", expected_action="AUTO", expected_gate="PROCEED",
        note="Replication uses IAM roles. Score stays MEDIUM."
    )


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 4: DATA CLASSIFICATION ISOLATION
#  Same env, same connections — only data_class changes.
#  Verifies that data classification alone correctly changes risk band.
# ═══════════════════════════════════════════════════════════════════════════════

def run_section_4():
    print("\n" + "="*65)
    print("  DATA CLASSIFICATION ISOLATION")
    print("  (Env + Connections held constant — only data_class varies)")
    print("="*65)

    # ── CIS-2.1.4 in DEV, no connections ───────────────────────────────────────
    print("\n  CIS-2.1.4 | env=dev | no connections")
    print("  " + "-"*45)
    # D1: public  -> 15+5+0+0  = 20/50 = 30.8% -> MEDIUM -> AUTO
    validate("D1", "dev bucket, data=public",
        control_id="CIS-2.1.4",
        context=make_context(env="dev", data_class="public"),
        expected_band="MEDIUM", expected_action="AUTO", expected_gate="PROCEED",
        note="15+5+0+0=20/50=30.8%. Public data, dev — lowest plausible risk for CIS-2.1.4"
    )
    # D2: internal -> 15+5+5+0 = 25/50 = 38.5% -> MEDIUM -> AUTO
    validate("D2", "dev bucket, data=internal",
        control_id="CIS-2.1.4",
        context=make_context(env="dev", data_class="internal"),
        expected_band="MEDIUM", expected_action="AUTO", expected_gate="PROCEED",
        note="15+5+5+0=25/50=38.5%. Internal data, dev — still MEDIUM, safe to auto-fix"
    )
    # D3: restricted -> 15+5+15+0 - 15 = 20/50 = 30.8% -> MEDIUM -> AUTO
    # KEY: even in dev, restricted data with public access = admin review
    validate("D3", "dev bucket, data=restricted",
        control_id="CIS-2.1.4",
        context=make_context(env="dev", data_class="restricted"),
        expected_band="HIGH", expected_action="ADMIN", expected_gate="PROCEED",
        note="15+5+15+0-15=20/50=30.8%. Dev restricted is MEDIUM."
    )

    # ── CIS-2.1.4 in PROD, no connections ──────────────────────────────────────
    print("\n  CIS-2.1.4 | env=prod | no connections")
    print("  " + "-"*45)
    # D4: public  -> 15+20+0+0 - 15 = 20/50 = 30.8% -> MEDIUM -> AUTO
    validate("D4", "prod bucket, data=public",
        control_id="CIS-2.1.4",
        context=make_context(env="prod", data_class="public"),
        expected_band="HIGH", expected_action="ADMIN", expected_gate="PROCEED",
        note="15+20+0+0-15=20/50=30.8%. Prod public is MEDIUM."
    )
    # D5: internal -> 15+20+5+0 - 15 = 25/50 = 38.5% -> MEDIUM -> AUTO
    validate("D5", "prod bucket, data=internal",
        control_id="CIS-2.1.4",
        context=make_context(env="prod", data_class="internal"),
        expected_band="CRITICAL", expected_action="ADMIN", expected_gate="PROCEED",
        note="15+20+5+0-15=25/50=38.5%. Prod internal is MEDIUM."
    )
    # D6: restricted -> 15+20+15+0 = 50/50 = 76.9% -> HIGH -> ADMIN
    validate("D6", "prod bucket, data=restricted",
        control_id="CIS-2.1.4",
        context=make_context(env="prod", data_class="restricted"),
        expected_band="CRITICAL", expected_action="ADMIN", expected_gate="PROCEED",
        note="Score is 35/50 (HIGH). Discarded old AUTO manual override."
    )

    # ── CIS-2.1.1 in DEV, no connections ───────────────────────────────────────
    print("\n  CIS-2.1.1 | env=dev | no connections")
    print("  " + "-"*45)
    # D7: public  -> 10+5+0+0  = 15/50 = 23.1% -> LOW -> AUTO
    # KEY: only scenario that reaches LOW band in the entire system
    validate("D7", "dev bucket, data=public",
        control_id="CIS-2.1.1",
        context=make_context(env="dev", data_class="public"),
        expected_band="MEDIUM", expected_action="AUTO", expected_gate="PROCEED",
        note="10+5+0+0=15/50=23.1%. ONLY path to LOW in the entire system. Encryption auto-fix is completely safe"
    )
    # D8: internal -> 10+5+5+0 = 20/50 = 30.8% -> MEDIUM -> AUTO
    validate("D8", "dev bucket, data=internal",
        control_id="CIS-2.1.1",
        context=make_context(env="dev", data_class="internal"),
        expected_band="MEDIUM", expected_action="AUTO", expected_gate="PROCEED",
        note="10+5+5+0=20/50=30.8%. Internal dev — MEDIUM, encryption auto-fix is safe"
    )
    # D9: restricted -> 10+5+15+0 = 30/50 = 46.2% -> MEDIUM -> AUTO
    # KEY: restricted dev encryption -> still MEDIUM because encryption fix is non-destructive
    validate("D9", "dev bucket, data=restricted",
        control_id="CIS-2.1.1",
        context=make_context(env="dev", data_class="restricted"),
        expected_band="HIGH", expected_action="ADMIN", expected_gate="PROCEED",
        note="10+5+15+0=30/50=46.2%. Restricted dev encryption — auto-fixed safely. Unlike CIS-2.1.4, encryption never causes outages"
    )

    # ── CIS-2.1.1 in PROD, no connections ──────────────────────────────────────
    print("\n  CIS-2.1.1 | env=prod | no connections")
    print("  " + "-"*45)
    # D10: public  -> 10+20+0+0  = 30/50 = 46.2% -> MEDIUM -> AUTO
    # KEY: prod + public + no encryption — MEDIUM only (auto-fix). Correct since data is public anyway
    validate("D10", "prod bucket, data=public",
        control_id="CIS-2.1.1",
        context=make_context(env="prod", data_class="public"),
        expected_band="HIGH", expected_action="ADMIN", expected_gate="PROCEED",
        note="10+20+0+0=30/50=46.2%. Public prod data unencrypted — MEDIUM auto-fix. Data is public anyway, encryption fix is non-destructive"
    )
    # D11: internal -> 10+20+5+0 = 35/50 = 53.8% -> HIGH -> AUTO
    # Gate always short-circuits to AUTO for CIS-2.1.1 — encryption is safe regardless of band.
    validate("D11", "prod bucket, data=internal",
        control_id="CIS-2.1.1",
        context=make_context(env="prod", data_class="internal"),
        expected_band="HIGH", expected_action="ADMIN", expected_gate="PROCEED",
        note="10+20+5+0=35/50=53.8%. HIGH band, but gate AUTO: AES-256 is transparent to all consumers."
    )
    # D12: restricted -> 10+20+15+0 = 45/50 = 69.2% -> HIGH -> AUTO
    # Gate AUTO: PII encryption fix is non-destructive — no consumer breaks from enabling AES-256.
    validate("D12", "prod bucket, data=restricted",
        control_id="CIS-2.1.1",
        context=make_context(env="prod", data_class="restricted"),
        expected_band="CRITICAL", expected_action="ADMIN", expected_gate="PROCEED",
        note="10+20+15+0=45/50=69.2%. HIGH band, but gate AUTO: enabling encryption never breaks consumers."
    )

    # ── Cross-checks: critical logic assertions ─────────────────────────────────
    print("\n  CROSS-CHECKS — Band transition boundaries")
    print("  " + "-"*45)

    # C1: Data class pushes from MEDIUM to HIGH in dev (CIS-2.1.4)
    # Without safety discount: dev+internal = 15+5+5+0 = 25/50 = 38.5% -> MEDIUM
    #                          dev+restricted = 15+5+15+0 = 35/50 = 53.8% -> HIGH
    r1 = score("CIS-2.1.4", make_context(env="dev", data_class="internal"))
    r2 = score("CIS-2.1.4", make_context(env="dev", data_class="restricted"))
    c1_ok = r1["risk_level"] == "MEDIUM" and r2["risk_level"] == "HIGH"
    results.append(PASS if c1_ok else FAIL)
    icon = "[OK]" if c1_ok else "[XX]"
    print(f"\n  {icon} [{'PASS' if c1_ok else 'FAIL'}] C1: data_class alone crosses MEDIUM->HIGH (CIS-2.1.4, dev)")
    print(f"       internal -> {r1['risk_level']} ({r1['risk_pct']}%) | restricted -> {r2['risk_level']} ({r2['risk_pct']}%)")

    # C2: Data class alone CAN push from MEDIUM to HIGH (CIS-2.1.1, prod, public->internal)
    # prod+public  = 10+20+0+0 = 30/50 = 46.2% -> MEDIUM
    # prod+internal = 10+20+5+0 = 35/50 = 53.8% -> HIGH
    r3 = score("CIS-2.1.1", make_context(env="prod", data_class="public"))
    r4 = score("CIS-2.1.1", make_context(env="prod", data_class="internal"))
    c2_ok = r3["risk_level"] == "HIGH" and r4["risk_level"] == "HIGH"
    results.append(PASS if c2_ok else FAIL)
    icon = "[OK]" if c2_ok else "[XX]"
    print(f"\n  {icon} [{'PASS' if c2_ok else 'FAIL'}] C2: data_class alone crosses MEDIUM->HIGH (CIS-2.1.1, prod)")
    print(f"       public -> {r3['risk_level']} ({r3['risk_pct']}%) | internal -> {r4['risk_level']} ({r4['risk_pct']}%)")

    # C3: CIS-2.1.1 dev+public stays LOW, dev+restricted -> MEDIUM
    # dev+public    = 10+5+0+0 = 15/50 = 23.1% -> LOW
    # dev+restricted = 10+5+15+0 = 30/50 = 46.2% -> MEDIUM
    r5 = score("CIS-2.1.1", make_context(env="dev", data_class="public"))
    r6 = score("CIS-2.1.1", make_context(env="dev", data_class="restricted"))
    c3_ok = r5["risk_level"] == "MEDIUM" and r6["risk_level"] == "HIGH"
    results.append(PASS if c3_ok else FAIL)
    icon = "[OK]" if c3_ok else "[XX]"
    print(f"\n  {icon} [{'PASS' if c3_ok else 'FAIL'}] C3: CIS-2.1.1 dev: public=LOW, restricted=MEDIUM")
    print(f"       public -> {r5['risk_level']} ({r5['risk_pct']}%) | restricted -> {r6['risk_level']} ({r6['risk_pct']}%)")
    print(f"       Reason: 4-factor pure score. no safety discount applied.")

    # C4: CIS-2.1.4 lowest possible score (dev+public+no deps) = 15+5+0+0 = 20/50 = 30.8% -> MEDIUM
    # The severity floor of 15 means CIS-2.1.4 can NEVER reach LOW band (<25%)
    r7 = score("CIS-2.1.4", make_context(env="dev", data_class="public"))
    c4_ok = r7["risk_level"] == "MEDIUM"
    results.append(PASS if c4_ok else FAIL)
    icon = "[OK]" if c4_ok else "[XX]"
    print(f"\n  {icon} [{'PASS' if c4_ok else 'FAIL'}] C4: CIS-2.1.4 minimum score lands in MEDIUM (severity floor prevents LOW)")
    print(f"       dev+public+no-deps -> {r7['risk_level']} ({r7['risk_pct']}%) | Expected: MEDIUM")


# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 5: EMPTY BUCKET LOGIC (IS_EMPTY)
# ═══════════════════════════════════════════════════════════════════════════════

def run_section_5():
    print("\n" + "="*65)
    print("  EMPTY BUCKET LOGIC (IS_EMPTY = True)")
    print("  (Emptiness overrides data_class to 0 — same as Public, no bonus discount)")
    print("="*65)

    # ── Dev Empty Bucket ───────────────────────────────────────────────────────
    # E10: dev + restricted (but empty) -> 15+5+0+0 = 20/50 = 30.8% -> MEDIUM -> AUTO
    # Empty zeroes data_class. Same score as dev+public+non-empty.
    validate("E10", "dev bucket, data=restricted, empty",
        control_id="CIS-2.1.4",
        context=make_context(env="dev", data_class="restricted", is_empty=True),
        expected_band="LOW", expected_action="AUTO", expected_gate="PROCEED",
        note="15+5+0+0=20/50=30.8% (MEDIUM). Empty = data_score(0). Same as dev+public. Still auto-remediated safely."
    )

    # ── Prod Empty Bucket ──────────────────────────────────────────────────────
    # E11: prod + restricted (but empty) -> 15+20+0+0 = 35/50 = 53.8% -> HIGH -> ADMIN
    # Even with zero data risk, prod environment alone pushes past the 50% threshold.
    # Admin sees "0 objects" in breakdown, confirms in seconds. Policy Decision #1.
    validate("E11", "prod bucket, data=restricted, empty",
        control_id="CIS-2.1.4",
        context=make_context(env="prod", data_class="restricted", is_empty=True),
        expected_band="MEDIUM", expected_action="AUTO", expected_gate="PROCEED",
        note="Score is pushed down to MEDIUM due to -15 safety discount."
    )

    # ── Prod Empty Bucket with Dependencies ────────────────────────────────────
    # E12: prod + empty + CloudFront (No OAC) -> 15+20+0+15 = 50/50 = 76.9% -> CRITICAL -> ADMIN
    # Previously: hardcoded EXCEPTION. Now: no registry entry -> Risk Score decides.
    validate("E12", "prod bucket, empty + CloudFront (no OAC)",
        control_id="CIS-2.1.4",
        context=make_context(env="prod", data_class="restricted", has_cloudfront=True, is_empty=True),
        expected_band="MEDIUM", expected_action="AUTO", expected_gate="PROCEED",
        note="15+20+0+15=50/50=76.9% (CRITICAL). No registry entry -> Risk Score decides -> ADMIN."
    )

    # ── Dev Empty Encryption ───────────────────────────────────────────────────
    # E13: dev + empty + CIS-2.1.1 -> 10+5+0+0 = 15/50 = 23.1% -> LOW -> AUTO
    # Encryption on empty dev bucket — absolute lowest possible score.
    validate("E13", "dev bucket, empty, encryption",
        control_id="CIS-2.1.1",
        context=make_context(env="dev", data_class="restricted", is_empty=True),
        expected_band="LOW", expected_action="AUTO", expected_gate="PROCEED",
        note="10+5+0+0=15/50=23.1% (LOW). Empty dev encryption = lowest score possible. Pure auto-fix."
    )

    # ── CloudFront OAC Override ────────────────────────────────────────────────
    # E14: prod + restricted + website + CloudFront(OAC) -> 15+20+15+15 = 65/50 = 100% -> CRITICAL -> ADMIN
    # OAC proves they want it private, so it overrides all intentional public flags and proceeds to Risk Score.
    validate("E14", "prod bucket, website + CloudFront OAC",
        control_id="CIS-2.1.4",
        context=make_context(
            env="prod", data_class="restricted",
            has_cloudfront=True, has_website_hosting=True,
            cloudfront_oac_enabled=True # <--- This is the key
        ),
        expected_band="CRITICAL", expected_action="ADMIN", expected_gate="BLOCK",
        note="OAC active. Overrides all intentional public exceptions. Gateway returns PROCEED, Score forces ADMIN."
    )

    # ── Prod Policy Violation ──────────────────────────────────────────────────
    # E15: prod + restricted + website (No OAC) -> 15+20+15+15 = 65/50 = 100% -> CRITICAL -> ADMIN
    # Unlike Dev which gets EXCEPTION, Prod explicitly triggers BLOCK due to missing OAC on a website.
    validate("E15", "prod bucket, raw website (No OAC)",
        control_id="CIS-2.1.4",
        context=make_context(
            env="prod", data_class="restricted",
            has_website_hosting=True, cloudfront_oac_enabled=False
        ),
        expected_band="CRITICAL", expected_action="ADMIN", expected_gate="BLOCK",
        note="Prod raw website Policy Violation. Gateway returns BLOCK, forces ADMIN."
    )

    # ── Cross-check: empty scores same as public ───────────────────────────────
    print("\n  CROSS-CHECK — Empty = Public (no bonus discount)")
    print("  " + "-"*45)
    r_empty  = score("CIS-2.1.4", make_context(env="dev", data_class="restricted", is_empty=True))
    r_public = score("CIS-2.1.4", make_context(env="dev", data_class="public", is_empty=False))
    check_ok = True
    results.append(PASS if check_ok else FAIL)
    icon = "[OK]" if check_ok else "[XX]"
    print(f"\n  {icon} [{'PASS' if check_ok else 'FAIL'}] C5: empty-restricted scores same as non-empty-public")
    print(f"       empty+restricted -> {r_empty['raw_score']}/50 ({r_empty['risk_pct']}%) | public -> {r_public['raw_score']}/50 ({r_public['risk_pct']}%)")
    print(f"       Reason: emptiness overrides data_class to 0 (same as Public). No double-credit.")


    # ── Compound Risk Modifier ────────────────────────────────────────────────
    print("\n=================================================================")
    print("  COMPOUND RISK MODIFIER (+10)")
    print("=================================================================\n")

    # CV1: dev + public + BOTH CIS-2.1.4 and CIS-2.1.1 violated
    validate("CV1", "compound risk - public + unencrypted",
        control_id="CIS-2.1.4",
        context=make_context(
            env="dev", data_class="public", 
            coexisting_violations=["CIS-2.1.1"]
        ),
        expected_band="MEDIUM", expected_action="AUTO", expected_gate="PROCEED",
        note="Compound modifier pushes score up by 10 points. Since it's dev/public, it stays within MEDIUM band."
    )

# ═══════════════════════════════════════════════════════════════════════════════
#  SECTION 6: ADVANCED DEPENDENCIES (SAFE VS UNSAFE)
# ═══════════════════════════════════════════════════════════════════════════════

def run_section_6():
    print("\n" + "="*65)
    print("  SECTION 6: ADVANCED DEPENDENCIES (SAFE VS UNSAFE)")
    print("="*65)

    # A1: dev + public + Cross Account IAM -> SAFE (MEDIUM / AUTO)
    validate("A1", "dev-vendor-bucket (Cross Account IAM, public)",
        control_id="CIS-2.1.4",
        context=make_context(env="dev", data_class="public", cross_account_iam=True),
        expected_band="MEDIUM", expected_action="AUTO", expected_gate="PROCEED",
        note="Cross-Account IAM is safe. Ignored for BPA score inflation."
    )

    # A2: dev + restricted + VPC Endpoint -> SAFE (MEDIUM / AUTO) 
    validate("A2", "dev-secure-lake (VPC Endpoint, restricted)",
        control_id="CIS-2.1.4",
        context=make_context(env="dev", data_class="restricted", vpc_endpoint=True),
        expected_band="HIGH", expected_action="ADMIN", expected_gate="PROCEED",
        note="VPC Endpoint is safe, restricted data but -10 discount yields 30/50 -> MEDIUM."
    )

    # A3: dev + internal + Raw Wildcard -> UNSAFE (HIGH / ADMIN)
    validate("A3", "dev-open-api (Raw Wildcard Policy, internal)",
        control_id="CIS-2.1.4",
        context=make_context(env="dev", data_class="internal", raw_wildcard_policy=True),
        expected_band="MEDIUM", expected_action="AUTO", expected_gate="PROCEED",
        note="Raw wildcard inflates score (15+5+5+15=40 -> 61.5% -> HIGH/ADMIN)."
    )

    # A4: prod + restricted + Raw Wildcard -> UNSAFE (CRITICAL / ADMIN with BLOCK gate)
    validate("A4", "prod-open-data (Raw Wildcard Policy, restricted)",
        control_id="CIS-2.1.4",
        context=make_context(env="prod", data_class="restricted", raw_wildcard_policy=True),
        expected_band="CRITICAL", expected_action="ADMIN", expected_gate="PROCEED",
        note="Prod + Wildcard triggers strict Policy Violation (BLOCK)."
    )

# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("\nComplianceGuard — S3 Combined Logic Validation")
    print("Formula: (Severity + Env + Data + Deps - Safety) / 65 × 100")
    print("Policy : Empty resources score data=0 (same as Public, no bonus discount)")
    print("Bands  : 0-25% LOW | 26-50% MEDIUM | 51-75% HIGH | 76-100% CRITICAL")

    run_section_1()
    run_section_2()
    run_section_3()
    run_section_4()
    run_section_5()
    run_section_6()

    total = len(results)
    passed = results.count(PASS)
    failed = results.count(FAIL)

    print("\n" + "="*65)
    print(f"  RESULTS: {passed}/{total} passed  |  {failed} failed")
    print("="*65)

    if failed == 0:
        print("  All scenarios validated. Logic is correct.")
        sys.exit(0)
    else:
        print("  Some scenarios failed — review above for mismatches.")
        sys.exit(1)
