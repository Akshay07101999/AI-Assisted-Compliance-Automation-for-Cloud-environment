"""
ComplianceGuard — Non-S3 Validation Script

Tests validation scenarios for CIS-1.14 (IAM Keys), CIS-5.2 (SG), Org-5 (EC2),
and CIS-2.3.x (RDS), specifically focusing on contextual overrides in the
risk scorer and accurate multi-outcome Remediation Safety Gate routing.

Run: python tests/validate_non_s3_logic.py
"""

import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from ai.risk_scorer import score
from decision.remediator import AutoRemediator

_remediator = AutoRemediator(region="us-east-1")

PASS = "PASS"
FAIL = "FAIL"
results = []

def check_safety_gate(control_id: str, context: dict, resource_id: str = "test-res") -> tuple[str, str]:
    """Simulate remediator Remediation Safety Gate."""
    return _remediator.check_safety_gate(control_id, context, resource_id)

def validate(
    scenario_id: str,
    name: str,
    control_id: str,
    context: dict,
    expected_band: str,
    expected_action: str = None,  # For orchestrator routing outcome
    expected_gate: str = None     # Pure Remediation Safety Gate Output
):
    print(f"\n[{scenario_id}] {control_id}: {name}")
    print(f"Context: {context}")

    # Risk Score
    risk = score(control_id, context)
    act_band = risk["risk_level"]
    print(f"Risk Score: {risk['raw_score']}/{risk['max_score']} ({risk['risk_pct']}%) -> {act_band}")

    # Gate Decision
    gate_action, gate_reason = check_safety_gate(control_id, context)
    print(f"Gate says:  {gate_action} ({gate_reason})")

    # Pipeline Routing Simulation
    if gate_action == "EXCEPTION":
        final_action = "EXCEPTION"
    elif gate_action == "BLOCK":
        final_action = "ADMIN"
    else:  # PROCEED
        if act_band in ["LOW", "MEDIUM"]:
            final_action = "AUTO"
        else:
            final_action = "ADMIN"

    print(f"Pipeline -> {final_action}")

    # Asserts
    band_ok = (act_band == expected_band)
    gate_ok = (expected_gate is None or gate_action == expected_gate)
    action_ok = (expected_action is None or final_action == expected_action)

    status = PASS if (band_ok and gate_ok and action_ok) else FAIL
    results.append({
        "id": scenario_id, "name": name, "status": status,
        "detail": f"Band {act_band} (exp {expected_band}), Gate {gate_action} (exp {expected_gate})"
    })

    if not band_ok:
        print(f"  [!] BAND MISMATCH. Expected {expected_band}, got {act_band}. Breakdown: {risk['breakdown']}")
        return False
    if not gate_ok:
        print(f"  [!] GATE MISMATCH. Expected {expected_gate}, got {gate_action}")
        return False
    if not action_ok:
        print(f"  [!] ACTION MISMATCH. Expected {expected_action}, got {final_action}")
        return False

    return True

# ── IAM Scenarios ────────────────────────────────────────────────────────────

validate("IAM1", "Dormant key, implicit dev tags", "CIS-1.14", 
         context={"is_dormant": True, "last_used_days": 45},
         expected_band="MEDIUM", expected_action="AUTO", expected_gate="PROCEED")

validate("IAM2", "Active key, implicit dev tags", "CIS-1.14", 
         context={"is_dormant": False, "last_used_days": 2},
         expected_band="MEDIUM", expected_action="ADMIN", expected_gate="BLOCK")

validate("IAM3", "Dormant key, explicit prod tags", "CIS-1.14", 
         context={"is_dormant": True, "last_used_days": 45, "tags": {"env": "prod"}},
         expected_band="HIGH", expected_action="ADMIN", expected_gate="PROCEED")

# ── Security Group Scenarios ──────────────────────────────────────────────────

validate("SG1", "Internet SSH, prod tags (dangling)", "CIS-5.2",
         context={"port": 22, "cidr_exposure": "internet", "cidrs": ["0.0.0.0/0"], "tags": {"env": "prod"}, "network_interfaces_count": 0},
         expected_band="HIGH", expected_action="ADMIN", expected_gate="PROCEED")

validate("SG2", "Private SSH, prod tags (running instance, public IP)", "CIS-5.2",
         context={"port": 22, "cidr_exposure": "internet", "cidrs": ["0.0.0.0/0"], "tags": {"env": "prod"}, "network_interfaces_count": 1, "attached_instances": ["i-12345"], "instance_state": "running", "has_public_ip": True, "public_ip": "1.2.3.4"},
         expected_band="HIGH", expected_action="ADMIN", expected_gate="BLOCK")

validate("SG3", "Restricted SSH, running instance with live IP", "CIS-5.2",
         context={"port": 22, "cidr_exposure": "internet", "cidrs": ["1.2.3.4/32"], "network_interfaces_count": 1, "attached_instances": ["i-12345"], "instance_state": "running", "has_public_ip": True, "public_ip": "1.2.3.4"},
         expected_band="HIGH", expected_action="ADMIN", expected_gate="BLOCK")

# ── EC2 Scenarios ──────────────────────────────────────────────────────────

validate("EC21", "Prod bastion host", "Org-5",
         context={"is_bastion": True, "env_tag": "prod", "instance_state": "running", "tags": {"env": "prod"}},
         expected_band="HIGH", expected_action="ADMIN", expected_gate="BLOCK")

validate("EC22", "Prod direct internet app (running)", "Org-5",
         context={"is_bastion": False, "env_tag": "prod", "instance_state": "running", "tags": {"env": "prod"}},
         expected_band="HIGH", expected_action="ADMIN", expected_gate="BLOCK")

# ── RDS Scenarios ──────────────────────────────────────────────────────────

validate("RDS1", "Internet exposure (no tags)", "CIS-2.3.2",
         context={"sg_cidr_exposure": "internet", "db_instance_status": "available"},
         expected_band="CRITICAL", expected_action="ADMIN", expected_gate="BLOCK")

validate("RDS2", "Private exposure (no tags overrides env penalty)", "CIS-2.3.2",
         context={"sg_cidr_exposure": "private", "db_instance_status": "available"},
         expected_band="CRITICAL", expected_action="ADMIN", expected_gate="PROCEED")

# ── Summary ──────────────────────────────────────────────────────────────────
print("\n" + "="*60)
print("NON-S3 VALIDATION SUMMARY")
print("="*60)
passed = sum(1 for r in results if r["status"] == PASS)
total = len(results)

for r in results:
    status_fmt = f"[{r['status']}]"
    print(f"{status_fmt:<7} {r['id']:<5} {r['name']:<40} {r['detail']}")

print(f"\nFinal Score: {passed}/{total} Scenarios Passed")
if passed != total:
    print("\n[!] WARNING: Validation check failed for one or more scenarios.")
    sys.exit(1)
else:
    print("\n[+] SUCCESS: All scenarios validated matching strict CIS logic.")
