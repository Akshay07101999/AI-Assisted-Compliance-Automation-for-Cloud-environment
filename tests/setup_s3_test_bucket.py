"""
ComplianceGuard - Real AWS S3 Test Setup

Usage:
    python tests/setup_s3_test_bucket.py --create --profile capstone-test
    python tests/setup_s3_test_bucket.py --verify --profile capstone-test
    python tests/setup_s3_test_bucket.py --delete --profile capstone-test
"""

import boto3
import argparse
import logging
import sys

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

BUCKET_NAME = "complianceguard-test-bucket-noncompliant"
session = None


def get_account_id():
    return session.client("sts").get_caller_identity()["Account"]


def create_noncompliant_bucket():
    s3 = session.client("s3")
    region = session.region_name

    logger.info(f"Creating test bucket: {BUCKET_NAME} in region: {region}")

    # Create bucket
    try:
        if region == "us-east-1":
            s3.create_bucket(Bucket=BUCKET_NAME)
        else:
            s3.create_bucket(
                Bucket=BUCKET_NAME,
                CreateBucketConfiguration={"LocationConstraint": region},
            )
        logger.info(f"  Bucket created: {BUCKET_NAME}")
    except Exception as e:
        if "BucketAlreadyOwnedByYou" in str(e):
            logger.info(f"  Bucket already exists, reusing: {BUCKET_NAME}")
        else:
            logger.error(f"  Failed to create bucket: {e}")
            sys.exit(1)

    # Disable Block Public Access -> CIS-2.1.4 violation
    s3.put_public_access_block(
        Bucket=BUCKET_NAME,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls":       False,
            "IgnorePublicAcls":      False,
            "BlockPublicPolicy":     False,
            "RestrictPublicBuckets": False,
        }
    )
    logger.info("  Block Public Access DISABLED (CIS-2.1.4 violation)")

    # Disable Encryption -> CIS-2.1.1 violation
    try:
        s3.delete_bucket_encryption(Bucket=BUCKET_NAME)
        logger.info("  Encryption DISABLED (CIS-2.1.1 violation)")
    except Exception:
        logger.info("  Encryption already disabled (CIS-2.1.1 violation present)")

    # Tag the bucket (drives risk scoring)
    s3.put_bucket_tagging(
        Bucket=BUCKET_NAME,
        Tagging={
            "TagSet": [
                {"Key": "env",                 "Value": "prod"},
                {"Key": "data_classification", "Value": "restricted"},
                {"Key": "project",             "Value": "complianceguard-test"},
            ]
        }
    )
    logger.info("  Tags set: env=prod, data_classification=restricted")

    account = get_account_id()
    print(f"""
  Test bucket ready!
  Account    : {account}
  Bucket     : {BUCKET_NAME}
  Region     : {region}
  Violations : CIS-2.1.4 (Public Access OFF), CIS-2.1.1 (Encryption OFF)
  Tags       : env=prod, data_classification=restricted

  Expected scores:
    CIS-2.1.4  15+20+15+0 = 50/65 = 76.9% -> CRITICAL
    CIS-2.1.1  10+20+15+0 = 45/65 = 69.2% -> HIGH

  Next step - dry run:
    python -m decision.orchestrator --services s3 --dry-run --profile {args.profile or 'default'}
""")


def delete_test_bucket():
    s3 = session.client("s3")
    logger.info(f"Deleting: {BUCKET_NAME}")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=BUCKET_NAME):
            objects = page.get("Contents", [])
            if objects:
                s3.delete_objects(
                    Bucket=BUCKET_NAME,
                    Delete={"Objects": [{"Key": o["Key"]} for o in objects]}
                )
        s3.delete_bucket(Bucket=BUCKET_NAME)
        logger.info(f"  Deleted: {BUCKET_NAME}")
    except Exception as e:
        if "NoSuchBucket" in str(e):
            logger.info("  Bucket does not exist")
        else:
            logger.error(f"  Failed: {e}")


def verify_violations():
    s3 = session.client("s3")
    print(f"\n  Verifying violations on: {BUCKET_NAME}")

    try:
        r   = s3.get_public_access_block(Bucket=BUCKET_NAME)
        cfg = r["PublicAccessBlockConfiguration"]
        bpa_off = not all(cfg.values())
        status = "VIOLATION EXISTS" if bpa_off else "Compliant (re-run --create)"
        print(f"  CIS-2.1.4 Public Access disabled : {status}")
    except Exception as e:
        print(f"  CIS-2.1.4: {e}")

    try:
        s3.get_bucket_encryption(Bucket=BUCKET_NAME)
        print(f"  CIS-2.1.1 Encryption disabled    : Compliant (re-run --create)")
    except Exception as e:
        if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
            print(f"  CIS-2.1.1 Encryption disabled    : VIOLATION EXISTS")

    try:
        r    = s3.get_bucket_tagging(Bucket=BUCKET_NAME)
        tags = {t["Key"]: t["Value"] for t in r["TagSet"]}
        print(f"  Tags                             : {tags}")
    except Exception as e:
        print(f"  Tags: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ComplianceGuard S3 Test Setup")
    group  = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--create", action="store_true")
    group.add_argument("--delete", action="store_true")
    group.add_argument("--verify", action="store_true")
    parser.add_argument("--profile", default=None, help="AWS CLI profile name")
    parser.add_argument("--region",  default="us-east-1", help="AWS region")
    args = parser.parse_args()

    session = (
        boto3.Session(profile_name=args.profile, region_name=args.region)
        if args.profile
        else boto3.Session(region_name=args.region)
    )

    account = get_account_id()
    logger.info(f"Connected -> Account: {account} | Region: {args.region} | Profile: {args.profile or 'default'}")

    if args.create:
        create_noncompliant_bucket()
        verify_violations()
    elif args.delete:
        delete_test_bucket()
    elif args.verify:
        verify_violations()
