import sys
import os
import uuid
import logging
from typing import List, Dict, Any
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import boto3
from botocore.exceptions import ClientError, BotoCoreError

# Import CIS control modules from the scanner domain
from scanner.controls import iam_controls
from scanner.controls import s3_controls
from scanner.controls import ec2_controls
from scanner.controls import rds_controls
from scanner.controls import ebs_controls

logger = logging.getLogger(__name__)

class ScanResult:
    """Encapsulates the findings from a full-cycle compliance scan."""
    def __init__(self, findings: List[Dict[str, Any]]):
        self.scan_id = f"SCAN-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.findings = findings

class ComplianceScanner:
    """
    Core orchestration layer for the ComplianceGuard Capstone.
    Iterates through all integrated AWS services to evaluate real-time configuration
    drift against strict CIS Benchmark standards.
    """
    
    def __init__(self, region: str = "us-east-1", execution_role_arn: str = None, profile: str = None):
        self.region = region
        self.execution_role_arn = execution_role_arn
        
        if profile:
            boto3.setup_default_session(profile_name=profile)
            
        # Initialize robust Boto3 session parameters
        session_kwargs = {"region_name": self.region}
        if self.execution_role_arn:
            sts = boto3.client("sts")
            try:
                creds = sts.assume_role(
                    RoleArn=self.execution_role_arn, 
                    RoleSessionName="ComplianceGuardScanner"
                )["Credentials"]
                session_kwargs.update({
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"]
                })
            except (ClientError, BotoCoreError) as e:
                logger.critical(f"Failed to assume execution role {self.execution_role_arn}: {e}")
                
        # Boot up all required AWS clients for the modules
        try:
            self.s3 = boto3.client('s3', **session_kwargs)
            self.ec2 = boto3.client('ec2', **session_kwargs)
            self.rds = boto3.client('rds', **session_kwargs)
            self.iam = boto3.client('iam', **session_kwargs)
        except Exception as e:
            logger.error(f"[ComplianceScanner] Client initialization failure: {e}")

    def run_full_scan(self, services: List[str] = None) -> ScanResult:
        """
        Executes all active CIS framework checks sequentially across the AWS estate.
        Returns a single unified ScanResult object for downstream pipeline processing.
        """
        logger.info(f"Initiating ComplianceGuard Auto-Scan in region {self.region} for services: {services or 'ALL'}...")
        findings = []

        # ── 1. IAM (Identity & Access Management) ──
        if not services or "iam" in services:
            logger.info("Scanning IAM footprint...")
            try:
                # Requires pagination if iterating all users. The control module handles this inherently.
                users_paginator = self.iam.get_paginator('list_users')
                for page in users_paginator.paginate():
                    for user in page.get('Users', []):
                        username = user['UserName']
                        iam_findings = iam_controls.evaluate_all(username, self.iam)
                        findings.extend(iam_findings)
            except (ClientError, Exception) as e:
                logger.error(f"Failed to execute IAM controls scan: {e}")

        # ── 2. EC2 & Security Groups ──
        if not services or "ec2" in services:
            logger.info("Scanning EC2 network footprints...")
            try:
                # 2a. Security Group checks (CIS-5.2)
                sgs_paginator = self.ec2.get_paginator('describe_security_groups')
                for page in sgs_paginator.paginate():
                    for sg in page.get('SecurityGroups', []):
                        # CIS-5.2 + CIS-5.3 + Org-SG-DB (pass sg obj to avoid extra API call)
                        sg_id = sg['GroupId']
                        sg_findings = ec2_controls.evaluate_sg(sg_id, self.ec2, sg_obj=sg)
                        findings.extend(sg_findings)
                        
                # 2b. EC2 Instance checks (Org-5, CIS-5.6, CIS-5.7)
                instances_paginator = self.ec2.get_paginator('describe_instances')
                for page in instances_paginator.paginate():
                    for reservation in page.get('Reservations', []):
                        for instance in reservation.get('Instances', []):
                            inst_id = instance['InstanceId']
                            ec2_findings = ec2_controls.evaluate_all(inst_id, self.ec2)
                            findings.extend(ec2_findings)
            except (ClientError, Exception) as e:
                logger.error(f"Failed to execute EC2 controls scan: {e}")

        # ── 3. RDS (Relational Database Service) ──
        if not services or "rds" in services:
            logger.info("Scanning RDS deployments...")
            try:
                rds_paginator = self.rds.get_paginator('describe_db_instances')
                for page in rds_paginator.paginate():
                    for db in page.get('DBInstances', []):
                        db_id = db['DBInstanceIdentifier']
                        # Pass ec2 client to RDS logic so it can classify attached Security Group CIDRs correctly.
                        db_findings = rds_controls.evaluate_all(db_id, self.rds, self.ec2)
                        findings.extend(db_findings)
            except (ClientError, Exception) as e:
                logger.error(f"Failed to execute RDS controls scan: {e}")

        # ── 4. EBS Volumes ──
        if not services or "ebs" in services:
            logger.info("Scanning EBS Volumes...")
            try:
                ebs_paginator = self.ec2.get_paginator('describe_volumes')
                for page in ebs_paginator.paginate():
                    for vol in page.get('Volumes', []):
                        vol_id = vol['VolumeId']
                        vol_findings = ebs_controls.evaluate_all(vol_id, self.ec2)
                        findings.extend(vol_findings)
            except (ClientError, Exception) as e:
                logger.error(f"Failed to execute EBS controls scan: {e}")

        # ── 5. S3 Buckets ──
        if not services or "s3" in services:
            logger.info("Scanning S3 Buckets...")
            try:
                buckets_response = self.s3.list_buckets()
                for bucket in buckets_response.get('Buckets', []):
                    bucket_name = bucket['Name']
                    # Evaluate CIS-2.1.1 (Encryption) and CIS-2.1.4 (BPA)
                    s3_finding_list = s3_controls.evaluate_all(bucket_name, self.s3)
                    findings.extend(s3_finding_list)
            except (ClientError, Exception) as e:
                logger.error(f"Failed to execute S3 controls scan: {e}")

        # Cleanse finding objects into raw dicts suitable for JSON audit and ContextCollector ingestion
        dict_findings = []
        for f in findings:
            if hasattr(f, "__dict__"):
                dict_findings.append(f.__dict__)
            elif isinstance(f, dict):
                dict_findings.append(f)

        logger.info(f"[Scanner] Complete. Aggregated {len(dict_findings)} active CIS violations.")
        return ScanResult(dict_findings)

if __name__ == "__main__":
    import argparse
    from decision.orchestrator import Orchestrator, SERVICES_IN_SCOPE

    parser = argparse.ArgumentParser(description="ComplianceGuard Scanner")
    parser.add_argument("--region",   default="us-east-1",      help="AWS region")
    parser.add_argument("--profile",  default=None,              help="AWS CLI profile")
    parser.add_argument("--services", nargs="+", default=SERVICES_IN_SCOPE,
                        choices=["s3", "iam", "ec2", "rds", "ebs"],
                        help="Services to scan (default: all)")
    parser.add_argument("--dry-run",  action="store_true",       help="Skip live AWS remediation and LLM calls")
    args = parser.parse_args()

    print(f"Running ComplianceGuard Scan in region {args.region} for services {args.services}...")
    orch = Orchestrator(region=args.region, profile=args.profile, services=args.services, dry_run=args.dry_run)
    orch.run()

