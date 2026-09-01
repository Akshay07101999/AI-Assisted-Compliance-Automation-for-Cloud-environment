"""
ComplianceGuard — AWS Context Collector

Retrieves real-time infrastructure context (routing, dependencies, tags)
to enrich the AI risk formula. This metadata acts as the operational truth
layer ensuring that remediation decisions are context-aware.

Services integrated:
  - AWS Resource Groups Tagging API (for unified cross-service tags)
  - AWS IAM (for active user profiling / key evaluation)
  - AWS EC2 (for VPC peering, Route Table association, Subnet public accessibility)
  - AWS RDS (for Multi-AZ and DB attachment graphs)
  - AWS S3 (for Bucket Policies, replication settings, lambda triggers)
"""

import json
import time
import logging
from typing import Dict, Any, List
from datetime import datetime, timezone, timedelta

import boto3
from botocore.exceptions import ClientError, BotoCoreError

logger = logging.getLogger(__name__)

class ContextCollector:
    """
    Introspects the AWS estate pulling 2nd-order metadata for a specific resource.
    The collected context feeds the Operational Risk Scorer and the Remediation Safety Gate.
    """
    
    def __init__(self, region: str = "us-east-1", execution_role_arn: str = None, session: Any = None):
        self.region = region
        self.execution_role_arn = execution_role_arn

        # ── Per-scan caches ──────────────────────────────────────────────────
        # VPC Flow Log cache: avoids a fresh CloudWatch Insights query (2-20s)
        # for every SG finding that shares the same VPC+port combination.
        # Key: (vpc_id, tuple(sorted ports), tuple(sorted target_ips)) → result dict
        self._flow_log_cache: dict = {}

        # CloudTrail cache: lookup_events has ~2-5s RTT per call.
        # Same resource_name+attribute_key pair is never queried twice per scan.
        # Key: (resource_name, attribute_key) → result dict
        self._cloudtrail_cache: dict = {}

        # ALB instance map: pre-loaded once per collector lifetime.
        # _check_alb_attachment used to paginate ALL TGs + call describe_target_health
        # for every EC2 finding. We build a {instance_id: True} map on first call
        # then do O(1) dict lookups for every subsequent EC2 finding.
        # None = not loaded yet; {} = loaded but no instances in any TG.
        self._alb_instance_map: dict | None = None
        
        # Determine the base client factory (boto3 or the provided session)
        aws_factory = session if session else boto3
        
        session_kwargs = {"region_name": self.region}
        if self.execution_role_arn:
            try:
                sts = aws_factory.client("sts")
                creds = sts.assume_role(
                    RoleArn=self.execution_role_arn, 
                    RoleSessionName="ContextCollectorRole"
                )["Credentials"]
                session_kwargs.update({
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"]
                })
            except Exception as e:
                logger.error(f"[ContextCollector] Failed to assume execution role: {e}")

        # Core SDK Clients
        self.rgta       = aws_factory.client('resourcegroupstaggingapi', **session_kwargs)
        self.s3         = aws_factory.client('s3',         **session_kwargs)
        self.ec2        = aws_factory.client('ec2',        **session_kwargs)
        self.rds        = aws_factory.client('rds',        **session_kwargs)
        self.iam        = aws_factory.client('iam',        **session_kwargs)
        self.elbv2      = aws_factory.client('elbv2',      **session_kwargs)
        # Activity evidence clients (log sources)
        self.cloudtrail = aws_factory.client('cloudtrail', **session_kwargs)
        self.logs       = aws_factory.client('logs',       **session_kwargs)
        
        try:
            sts = aws_factory.client('sts', **session_kwargs)
            self.account_id = sts.get_caller_identity().get('Account')
        except Exception:
            self.account_id = None

    def collect(self, resource_type: str, resource_id: str, control_id: str = "") -> Dict[str, Any]:
        """
        Primary entry point. Normalizes the output into the master context shape
        expected by the Risk Scorer and AutoRemediator.
        """
        logger.debug(f"[ContextCollector] Building intelligence graph for {resource_type}/{resource_id}")
        
        # ── 1. The Global Schema ──
        base_context = {
            "tags": {},
            "dependencies": [],
            "connections": {
                "downstream": {},
                "upstream": {},
                "has_any_connection": False
            },
            "is_empty": False,
            "recorded_at": datetime.now(timezone.utc).isoformat()
        }
        
        # ── 2. Unified Tags (RGTA) ──
        # Tags heavily influence the environmental and data classification score.
        domain_arn = self._construct_arn(resource_type, resource_id)
        if domain_arn:
            base_context["tags"] = self._fetch_rgta_tags(domain_arn)

        # ── 3. Type-Specific Enrichment ──
        try:
            if resource_type.upper() == "AWS::EC2::INSTANCE" or resource_type.upper() == "AWS::EC2::SECURITYGROUP":
                logger.debug("Routing to EC2 contextualizer")
                base_context.update(self._collect_ec2_context(resource_id, resource_type, control_id))

            elif resource_type.upper() == "AWS::S3::BUCKET":
                logger.debug("Routing to S3 contextualizer")
                base_context.update(self._collect_s3_context(resource_id))

            elif resource_type.upper() == "AWS::RDS::DBINSTANCE":
                logger.debug("Routing to RDS contextualizer")
                base_context.update(self._collect_rds_context(resource_id))

            elif "IAM" in resource_type.upper():
                logger.debug("Routing to IAM contextualizer")
                # IAM tags require native IAM API since global RGTA can lag or behave inconsistently for global org keys
                base_context["tags"].update(self._fetch_iam_tags(resource_id))
                # Activity evidence: what APIs has this key/user been calling?
                # Extract access key ID if embedded in resource_id (format: username/key/AKID)
                key_id = resource_id.split("/key/")[-1] if "/key/" in resource_id else resource_id
                base_context["activity_evidence"] = self._query_cloudtrail_events(
                    resource_name=key_id,
                    attribute_key="AccessKeyId",
                    days=30,
                    event_names=None,   # capture ALL events made by this key
                )

        except (ClientError, BotoCoreError) as e:
            logger.warning(f"Partial trace failure on {resource_id}. Scoring gracefully degrades. Err: {e}")

        # Post-process dependency boolean
        has_downstream = any(bool(v) for v in base_context["connections"]["downstream"].values())
        has_upstream   = any(bool(v) for v in base_context["connections"]["upstream"].values())
        base_context["connections"]["has_any_connection"] = has_downstream or has_upstream or bool(base_context.get("dependencies"))

        return base_context

    # ═══════════════════════════════════════════════════════════════════════════
    #  RESOURCE ROUTERS
    # ═══════════════════════════════════════════════════════════════════════════

    def _collect_ec2_context(self, resource_id: str, res_type: str, control_id: str = "") -> Dict[str, Any]:
        """EC2 specific enrichments: Bastion state, attached interfaces, flow log activity."""
        ctx = {
            "is_private_subnet": False,
            "is_peered_network": False,
            "has_public_alb_proxy": False,
        }
        res_type_upper = res_type.upper()
        
        if "INSTANCE" in res_type_upper:
            # 1. State and direct internet reachability
            resp = self.ec2.describe_instances(InstanceIds=[resource_id])
            if resp.get('Reservations'):
                inst = resp['Reservations'][0]['Instances'][0]
                ctx['instance_state'] = inst.get('State', {}).get('Name', 'unknown')
                
                # Check for explicit bastion host pattern tags applied by Ops
                tags_dict = {t['Key'].lower(): t['Value'].lower() for t in inst.get('Tags', [])}
                ctx['is_bastion'] = (
                    tags_dict.get('role') == 'bastion' or 
                    tags_dict.get('name', '').find('bastion') != -1 or
                    tags_dict.get('name', '').find('jump') != -1 
                )

                # Overwrite standard tags from the Describe call just in case RGTA failed
                ctx['tags'] = {t['Key']: t['Value'] for t in inst.get('Tags', [])}

                # Extract Public IP and presence boolean
                pub_ip = inst.get('PublicIpAddress')
                has_eip = False
                for ni in inst.get('NetworkInterfaces', []):
                    if ni.get('Association', {}).get('AllocationId'):
                        has_eip = True
                        break
                        
                if pub_ip:
                    ctx['public_ip'] = pub_ip
                    ctx['has_public_ip'] = True
                else:
                    ctx['has_public_ip'] = False
                ctx['has_elastic_ip'] = has_eip

                # Evaluate Topological Routing
                vpc_id = inst.get('VpcId')
                subnet_id = inst.get('SubnetId')
                routing = self._evaluate_subnet_routing(subnet_id, vpc_id)
                ctx["is_private_subnet"] = routing["is_private"]
                ctx["is_peered_network"] = routing["is_peered"]
                ctx["has_public_alb_proxy"] = self._check_alb_attachment(resource_id)

        elif "SECURITYGROUP" in res_type_upper:
            # ── Step 1: Always resolve VPC ID directly from the SG object (guaranteed) ──
            # This is bulletproof even if no ENIs are attached at scan time.
            try:
                sgs = self.ec2.describe_security_groups(GroupIds=[resource_id]).get('SecurityGroups', [])
                if sgs:
                    ctx['vpc_id'] = sgs[0].get('VpcId')
            except Exception as e:
                logger.warning(f"[ContextCollector] Could not resolve VPC ID for SG {resource_id} via describe_security_groups: {e}")

            # Check what this security group is actually attached to
            resp = self.ec2.describe_network_interfaces(Filters=[{'Name': 'group-id', 'Values': [resource_id]}])
            AttachedInstances = []
            has_public_ip = False
            public_ip_val = None

            for eni in resp.get('NetworkInterfaces', []):
                attach = eni.get('Attachment', {})
                if attach.get('InstanceId'):
                    AttachedInstances.append(attach['InstanceId'])
                # Check for public IP on the ENI association
                pub_ip = eni.get('Association', {}).get('PublicIp')
                if pub_ip:
                    has_public_ip = True
                    public_ip_val = pub_ip
                # ENI VpcId can also update/confirm the vpc_id
                if eni.get('VpcId') and not ctx.get('vpc_id'):
                    ctx['vpc_id'] = eni['VpcId']

            if AttachedInstances:
                ctx["dependencies"] = [{"resourceType": "AWS::EC2::Instance", "resourceId": i} for i in AttachedInstances]
                ctx["attached_instances"] = AttachedInstances

                # Bug #5 fix: Resolve instance states across all attached instances.
                # The Safety Gate CIS-5.2 branch at line 126 checks instance_state to
                # detect stopped instances (safe to replace 0.0.0.0/0 — no lockout risk).
                # For AWS::EC2::SECURITYGROUP findings this key was never populated,
                # so the branch was permanently dead (always read "unknown").
                # Worst-case aggregation: if ANY instance is running → running.
                # Only set "stopped" when ALL attached instances are confirmed stopped.
                try:
                    inst_resp = self.ec2.describe_instances(InstanceIds=AttachedInstances)
                    states = set()
                    for resv in inst_resp.get("Reservations", []):
                        for inst in resv.get("Instances", []):
                            states.add(inst.get("State", {}).get("Name", "unknown"))
                    if "running" in states:
                        ctx["instance_state"] = "running"
                    elif states and "running" not in states and "unknown" not in states:
                        ctx["instance_state"] = "stopped"   # all confirmed stopped
                    else:
                        ctx["instance_state"] = "unknown"
                except Exception as _ie:
                    logger.debug(f"[ContextCollector] Could not resolve instance states for SG {resource_id}: {_ie}")
                    ctx["instance_state"] = "unknown"
            ctx["network_interfaces_count"] = len(resp.get('NetworkInterfaces', []))

            ctx["has_public_ip"] = has_public_ip
            if public_ip_val:
                ctx["public_ip"] = public_ip_val

            if resp.get('NetworkInterfaces'):
                all_private = True
                any_peered = False
                for eni in resp.get('NetworkInterfaces'):
                    r = self._evaluate_subnet_routing(eni.get('SubnetId'), eni.get('VpcId'))
                    if not r["is_private"]: all_private = False
                    if r["is_peered"]: any_peered = True
                ctx["is_private_subnet"] = all_private
                ctx["is_peered_network"] = any_peered

            # ── Activity Evidence: VPC Flow Logs ──────────────────────────
            # Determine which port to query based on the control being evaluated
            port_map = {
                "CIS-5.2":          [22, 3389],
                "Org-SG-DB":        [3306, 5432, 27017, 6379, 9200, 1521, 1433],
                # Org-RDS-SG-Chain: RDS SG uses raw CIDRs on DB port.
                # Must filter to DB ports only — without this entry, query_ports=None
                # and the flow log query runs with no port filter, returning ALL VPC
                # traffic and hitting the 25-row cap with irrelevant rows.
                "Org-RDS-SG-Chain": [3306, 5432, 27017, 6379, 9200, 1521, 1433],
                "CIS-5.3":          None,   # all ports
                "Org-5":            None,   # all ports
            }
            query_ports = port_map.get(control_id)
            vpc_id = ctx.get("vpc_id")
            
            # Target IP extraction to isolate Flow Logs to this specific resource
            # Collect ALL private IPs (primary + secondary) across all ENIs
            target_ips = []
            oldest_attach_time = None
            if resp.get('NetworkInterfaces'):
                for eni in resp.get('NetworkInterfaces'):
                    # Track resource creation bounds to prevent querying stale IP history
                    attach_time = eni.get('Attachment', {}).get('AttachTime')
                    if attach_time:
                        if not oldest_attach_time or attach_time < oldest_attach_time:
                            oldest_attach_time = attach_time
                            
                    # Primary IP
                    pip = eni.get('PrivateIpAddress')
                    if pip and pip not in target_ips:
                        target_ips.append(pip)
                    # Secondary IPs (e.g. multi-homed ENIs)
                    for addr in eni.get('PrivateIpAddresses', []):
                        sec = addr.get('PrivateIpAddress')
                        if sec and sec not in target_ips:
                            target_ips.append(sec)
                        
            if not resp.get('NetworkInterfaces'):
                # Bug #15+#2 fix: Skip flow log query for dangling SGs entirely.
                # With no ENIs there are no destination IPs to filter on.
                # Running a broad VPC-wide query here would:
                #   (a) return traffic from OTHER resources in the VPC (wrong data), and
                #   (b) cache that unrelated result under (vpc_id, ports, ()) so ALL
                #       subsequent dangling-SG queries in this VPC inherit corrupted data,
                #       causing the LLM to generate surgical CIDRs for IPs that never
                #       touched these SGs.
                ctx["activity_evidence"] = {
                    "source": "vpc_flow_logs",
                    "logging_enabled": False,
                    "analyst_summary": "Dangling SG (no ENIs attached) — flow log query skipped. No traffic to analyze.",
                    "note": "No attached network interfaces; no destination IPs to filter on.",
                }
            elif vpc_id:
                ctx["activity_evidence"] = self._query_vpc_flow_logs(
                    vpc_id=vpc_id,
                    ports=query_ports,
                    days=15,
                    target_ips=target_ips,
                    start_time=oldest_attach_time,
                )
            else:
                ctx["activity_evidence"] = {
                    "source": "vpc_flow_logs",
                    "logging_enabled": False,
                    "note": "Could not resolve VPC ID — flow log query skipped."
                }

        return ctx

    def _collect_rds_context(self, resource_id: str) -> Dict[str, Any]:
        """RDS specific enrichments: Security Group topologies, Engine types, CloudTrail activity."""
        ctx = {}
        vpc_id = None      # safe defaults to prevent NameError if describe_db_instances fails
        db_port = 3306

        resp = self.rds.describe_db_instances(DBInstanceIdentifier=resource_id)
        if resp.get('DBInstances'):
            db = resp['DBInstances'][0]
            ctx['engine'] = db.get('Engine')
            ctx['db_instance_status'] = db.get('DBInstanceStatus')
            ctx['multi_az'] = db.get('MultiAZ', False)
            ctx['read_replicas'] = db.get('ReadReplicaDBInstanceIdentifiers', [])

            # If RDS has read replicas, we classify that as a critical downstream coupling
            if ctx['read_replicas']:
                ctx.setdefault("connections", {}).setdefault("downstream", {})
                ctx["connections"]["downstream"]["replication_target"] = True

            vpc_id  = db.get("DBSubnetGroup", {}).get("VpcId")
            db_port = db.get("Endpoint", {}).get("Port", 3306)
            db_create_time = db.get("InstanceCreateTime")

        # 1. CloudTrail Evidence (API Activity)
        ct_evidence = self._query_cloudtrail_events(
            resource_name=resource_id,
            attribute_key="ResourceName",
            days=30,
            event_names=["ModifyDBInstance", "CreateDBSnapshot",
                         "DeleteDBInstance", "RebootDBInstance",
                         "RestoreDBInstanceFromDBSnapshot"],
        )
        ctx["activity_evidence"] = ct_evidence

        # 2. VPC Flow Logs Evidence (Data Plane/Network Activity)
        # Resolve the RDS endpoint DNS to its private IP so the query is pinned
        # to just this specific database instance, not all port-3306 traffic in the VPC.
        if vpc_id:
            rds_target_ips = []
            rds_endpoint_host = resp.get('DBInstances', [{}])[0].get('Endpoint', {}).get('Address') if resp.get('DBInstances') else None
            if rds_endpoint_host:
                import socket as _socket
                try:
                    # Bug #11 fix: Use getaddrinfo instead of gethostbyname.
                    # RDS Multi-AZ instances use round-robin DNS — each call to
                    # gethostbyname returns ONE of N IPs (alternating between AZs).
                    # getaddrinfo returns ALL A records in a single call, so flow
                    # log queries filter on every possible destination IP, not just
                    # the one that happened to be returned at scan time.
                    addr_infos = _socket.getaddrinfo(rds_endpoint_host, None, _socket.AF_INET)
                    resolved_ips = list({info[4][0] for info in addr_infos if info[4][0]})
                    if resolved_ips:
                        rds_target_ips = resolved_ips
                        logger.debug(f"[RDS FlowLogs] Resolved {rds_endpoint_host} -> {resolved_ips}")
                except Exception as e:
                    logger.debug(f"[RDS FlowLogs] DNS resolution failed for {rds_endpoint_host}: {e}")

            fl_evidence = self._query_vpc_flow_logs(
                vpc_id=vpc_id,
                ports=[db_port],
                days=30,
                target_ips=rds_target_ips if rds_target_ips else None,
                start_time=db_create_time if 'db_create_time' in locals() else None,
            )
            # Full merge: copy ALL critical flow log fields into activity_evidence.
            # Previous code only copied observed_source_ips + flow_log_summary,
            # silently discarding external_access_detected, exploitation_signals,
            # external_connections, and suggested_cidr_replacements.
            # The LLM prompt builder reads all four — without this merge, the
            # model was blind to whether the DB port was being actively probed
            # from the internet (TCP-level), seeing only CloudTrail API events.
            if fl_evidence.get("logging_enabled"):
                # Preserve CloudTrail analyst_summary under a prefixed key
                ct_summary = ctx["activity_evidence"].get("analyst_summary", "")
                if ct_summary:
                    ctx["activity_evidence"]["cloudtrail_analyst_summary"] = ct_summary
                # Overwrite with flow log values for the fields LLM reads directly
                ctx["activity_evidence"]["observed_source_ips"]       = fl_evidence.get("observed_source_ips", [])
                ctx["activity_evidence"]["external_connections"]      = fl_evidence.get("external_connections", [])
                ctx["activity_evidence"]["external_access_detected"]  = fl_evidence.get("external_access_detected", False)
                ctx["activity_evidence"]["exploitation_signals"]      = (
                    ctx["activity_evidence"].get("exploitation_signals", []) +
                    fl_evidence.get("exploitation_signals", [])
                )
                ctx["activity_evidence"]["suggested_cidr_replacements"] = fl_evidence.get("suggested_cidr_replacements", [])
                ctx["activity_evidence"]["flow_log_analyst_summary"]  = fl_evidence.get("analyst_summary", "")
                # Update source to reflect dual evidence.
                # Without this, ev_source remains "cloudtrail" and the
                # vpc_flow_logs branch in _build_llm_prompt is never taken
                # for RDS findings, despite having real flow log data.
                ctx["activity_evidence"]["source"] = "vpc_flow_logs"
                # Update top-level analyst_summary to combine both sources
                ctx["activity_evidence"]["analyst_summary"] = (
                    f"[Network/FlowLogs] {fl_evidence.get('analyst_summary', 'No flow log data.')} "
                    f"[API/CloudTrail] {ct_summary}"
                ).strip()

        return ctx


    def _collect_s3_context(self, bucket_name: str) -> Dict[str, Any]:
        """S3 Specific enrichments: Bucket policies, triggers, empty bucket verification"""
        ctx = {
            "is_empty": False,
            "cloudfront_oac_enabled": False,
            "website_hosting_enabled": False,
            "connections": {
                "downstream": {},
                "upstream": {}
            }
        }
        
        # 1. Verify if Bucket is empty (zero data exposure risk override)
        # Two-step check: list_objects_v2 catches current objects; list_object_versions
        # catches versioned objects, delete markers, and incomplete multipart uploads
        # that a MaxKeys=1 object listing misses. Both must confirm zero content.
        try:
            objs = self.s3.list_objects_v2(Bucket=bucket_name, MaxKeys=1)
            current_objects_empty = (objs.get('KeyCount', 0) == 0)
        except ClientError:
            current_objects_empty = False  # Cannot confirm — assume not empty

        versions_empty = False
        try:
            vers = self.s3.list_object_versions(Bucket=bucket_name, MaxKeys=1)
            has_versions    = bool(vers.get('Versions', []))
            has_markers     = bool(vers.get('DeleteMarkers', []))
            
            mp_uploads      = self.s3.list_multipart_uploads(Bucket=bucket_name, MaxUploads=1)
            has_multipart   = bool(mp_uploads.get('Uploads', []))
            
            versions_empty  = not (has_versions or has_markers or has_multipart)
        except ClientError as e:
            if 'NoSuchBucket' in str(e):
                versions_empty = True   # Bucket doesn't exist — vacuously empty
            else:
                versions_empty = False  # Cannot confirm — assume not empty

        ctx["is_empty"] = current_objects_empty and versions_empty

        # 2. Check Static Website Hosting
        try:
            web = self.s3.get_bucket_website(Bucket=bucket_name)
            ctx["website_hosting_enabled"] = True
            ctx["connections"]["downstream"]["website_hosting"] = True
        except ClientError as e:
            if 'NoSuchWebsiteConfiguration' not in str(e):
                logger.debug(f"Bucket Website check suppressed: {e}")
                
        # 3. Check for CloudFront Origin Access Control (OAC) via Bucket Policy
        try:
            policy_resp = self.s3.get_bucket_policy(Bucket=bucket_name)
            policy_json = json.loads(policy_resp.get("Policy", "{}"))
            for statement in policy_json.get("Statement", []):
                # OAC dictates Service == cloudfront.amazonaws.com with specific condition keys
                if statement.get("Effect") == "Allow":
                    principal = statement.get("Principal", {})
                    if isinstance(principal, dict) and principal.get("Service") == "cloudfront.amazonaws.com":
                        ctx["cloudfront_oac_enabled"] = True
                        ctx["connections"]["downstream"]["cloudfront"] = True
                        break
        except ClientError:
            pass

        # 3b. Check CORS Configuration
        try:
            cors = self.s3.get_bucket_cors(Bucket=bucket_name)
            if cors.get("CORSRules"):
                ctx["cors_enabled"] = True
                ctx["connections"]["downstream"]["cors_assets"] = True
        except ClientError as e:
            if 'NoSuchCORSConfiguration' not in str(e):
                logger.debug(f"Bucket CORS check suppressed: {e}")

        # 4. Check Lambda Triggers/Event Notifications
        try:
            notifs = self.s3.get_bucket_notification_configuration(Bucket=bucket_name)
            lambdas = notifs.get("LambdaFunctionConfigurations", [])
            if lambdas:
                ctx["connections"]["downstream"]["lambda_triggers"] = [
                    lam.get('LambdaFunctionArn') for lam in lambdas
                ]
        except ClientError:
            pass

        # 5. Replication Topology
        try:
            repl = self.s3.get_bucket_replication(Bucket=bucket_name)
            ctx["connections"]["upstream"]["replication_source"] = True
        except ClientError:
            pass

        # 6. Activity Evidence: CloudTrail — who has been accessing this bucket?
        # Surfaces: external callers, anonymous access, recent API callers
        ctx["activity_evidence"] = self._query_cloudtrail_events(
            resource_name=bucket_name,
            attribute_key="ResourceName",
            days=30,
            event_names=["GetObject", "PutObject", "DeleteObject",
                         "GetBucketPolicy", "PutBucketPolicy",
                         "PutBucketAcl", "DeleteBucketPolicy",
                         "PutBucketPublicAccessBlock", "CreateBucket",
                         "PutBucketEncryption", "PutBucketVersioning"],
        )

        return ctx

    # ═══════════════════════════════════════════════════════════════════════════
    #  HELPER FUNCTIONS
    # ═══════════════════════════════════════════════════════════════════════════

    def _fetch_rgta_tags(self, resource_arn: str) -> Dict[str, str]:
        """Fetch tags from the global Resource Groups Tagging API"""
        try:
            resp = self.rgta.get_resources(ResourceARNList=[resource_arn])
            resources = resp.get('ResourceTagMappingList', [])
            if resources:
                return {t['Key']: t['Value'] for t in resources[0].get('Tags', [])}
        except ClientError as e:
            logger.debug(f"RGTA Tag fetch failed for {resource_arn} - {e}")
        return {}

    def _fetch_iam_tags(self, username: str) -> Dict[str, str]:
        """Extract IAM User name from ARN safely, then describe tags"""
        try:
            clean_name = username.split('/')[-1] if 'arn:' in username else username
            resp = self.iam.list_user_tags(UserName=clean_name)
            return {t['Key']: t['Value'] for t in resp.get('Tags', [])}
        except ClientError:
            return {}

    def _construct_arn(self, r_type: str, r_id: str) -> str:
        """Utility to safely piece together an ARN from base IDs for the Tagging API"""
        account_id = self.account_id
            
        if not account_id: return None
            
        if "EC2::INSTANCE" in r_type.upper():
            return f"arn:aws:ec2:{self.region}:{account_id}:instance/{r_id}"
        elif "EC2::SECURITYGROUP" in r_type.upper():
            return f"arn:aws:ec2:{self.region}:{account_id}:security-group/{r_id}"
        elif "RDS::DBINSTANCE" in r_type.upper():
            return f"arn:aws:rds:{self.region}:{account_id}:db/{r_id}"
        elif "S3::BUCKET" in r_type.upper():
            return f"arn:aws:s3:::{r_id}"
            
        return None

    def _evaluate_subnet_routing(self, subnet_id: str, vpc_id: str) -> Dict[str, bool]:
        """
        Check route tables for IGW (public) and TGW/PCX/VGW (lateral crossing).

        AWS API field mapping (each route entry has SEPARATE fields per target type):
          GatewayId            → igw-xxx (Internet Gateway) or vgw-xxx (Virtual Private Gateway)
          TransitGatewayId     → tgw-xxx  (NOT in GatewayId — separate field)
          VpcPeeringConnectionId → pcx-xxx (NOT in GatewayId — separate field)
          NatGatewayId         → nat-xxx  (outbound only, does NOT make subnet public)
        """
        # Bug #7 fix: Default to is_private=False (fail-secure).
        # Previously defaulted to True, so any finding where subnet_id was
        # missing (Lambda ENI, cross-account interface, describe failure) would
        # appear to be in a private subnet → Safety Gate would PROCEED to
        # disassociate an EIP that may be on a live public-subnet instance.
        result = {"is_private": False, "is_peered": False}
        if not subnet_id or not vpc_id: return result
        try:
            rt_resp = self.ec2.describe_route_tables(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
            main_rt = None
            subnet_rt = None
            for rt in rt_resp.get('RouteTables', []):
                for assoc in rt.get('Associations', []):
                    if assoc.get('Main'):
                        main_rt = rt
                    if assoc.get('SubnetId') == subnet_id:
                        subnet_rt = rt
                        break
            
            active_rt = subnet_rt if subnet_rt else main_rt
            if active_rt:
                has_igw = False
                for route in active_rt.get('Routes', []):
                    # Internet Gateway → makes subnet public (inbound reachable)
                    gw = route.get('GatewayId', '')
                    if gw.startswith('igw-'):
                        has_igw = True

                    # Virtual Private Gateway (VPN) — in GatewayId with vgw- prefix
                    if gw.startswith('vgw-'):
                        result["is_peered"] = True

                    # Transit Gateway — AWS puts this in its OWN field, NOT GatewayId
                    if route.get('TransitGatewayId', ''):
                        result["is_peered"] = True

                    # VPC Peering — AWS puts this in its OWN field, NOT GatewayId
                    if route.get('VpcPeeringConnectionId', ''):
                        result["is_peered"] = True

                result["is_private"] = not has_igw

        except ClientError:
            pass
        return result

    def _check_alb_attachment(self, instance_id: str) -> bool:
        """Check if instance is actively registered in any ELBv2 Target Group.

        Performance fix: builds a full {instance_id: True} map on first call
        (one TG pagination + N describe_target_health calls) and does O(1)
        dict lookups for every subsequent EC2 finding in the same scan.
        Previously called the full paginator per-finding, which is O(findings × TGs).
        """
        if self._alb_instance_map is None:
            # First call in this scan — build the map
            self._alb_instance_map = {}
            try:
                paginator = self.elbv2.get_paginator('describe_target_groups')
                for page in paginator.paginate():
                    for tg in page.get('TargetGroups', []):
                        if tg.get('TargetType') == 'instance':
                            try:
                                health = self.elbv2.describe_target_health(
                                    TargetGroupArn=tg['TargetGroupArn']
                                )
                                for tr in health.get('TargetHealthDescriptions', []):
                                    iid = tr.get('Target', {}).get('Id')
                                    if iid:
                                        self._alb_instance_map[iid] = True
                            except ClientError:
                                pass
            except ClientError:
                pass
            logger.debug(
                f"[ALBCache] Pre-loaded {len(self._alb_instance_map)} instance(s) "
                "registered in ELBv2 Target Groups."
            )
        return self._alb_instance_map.get(instance_id, False)

    # ═══════════════════════════════════════════════════════════════════════════
    #  ACTIVITY EVIDENCE — LOG QUERIES
    # ═══════════════════════════════════════════════════════════════════════════

    def _query_cloudtrail_events(
        self,
        resource_name: str,
        attribute_key: str = "ResourceName",
        days: int = 30,
        event_names: list = None,
    ) -> dict:
        """
        Query CloudTrail for recent API activity on a resource.

        Surfaces:
          - Which principals (users/roles/keys) have been calling APIs on this resource
          - Source IP addresses (detects external/non-RFC1918 callers)
          - Whether external access has been detected
          - Exploitation signals (e.g. anonymous access, external IPs on sensitive operations)

        Available immediately — CloudTrail management events are enabled by default
        in virtually every AWS account and cover the last 90 days.

        Performance: results are cached per (resource_name, attribute_key) for the
        lifetime of this collector instance (one scan). lookup_events has ~2-5s RTT;
        the same resource is never queried twice in a single scan pass.
        """
        # ── Cache check ───────────────────────────────────────────────────────
        cache_key = (resource_name, attribute_key)
        if cache_key in self._cloudtrail_cache:
            logger.debug(f"[CloudTrail] Cache HIT for {resource_name} — skipping lookup_events call")
            return self._cloudtrail_cache[cache_key]
        try:
            start_time = datetime.now(timezone.utc) - timedelta(days=days)
            resp = self.cloudtrail.lookup_events(
                LookupAttributes=[{
                    "AttributeKey": attribute_key,
                    "AttributeValue": resource_name,
                }],
                StartTime=start_time,
                EndTime=datetime.now(timezone.utc),
                MaxResults=50,
            )
            raw_events = resp.get("Events", [])

            # Filter to relevant event names if specified
            if event_names:
                raw_events = [e for e in raw_events if e.get("EventName") in event_names]

            callers = {}           # unique caller fingerprint → details
            external_access = False
            exploitation_signals = []

            _PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                                 "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                                 "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                                 "172.30.", "172.31.", "192.168.", "127.")

            for event in raw_events:
                event_name = event.get("EventName", "unknown")
                username   = event.get("Username", "unknown")
                source_ip  = "unknown"

                try:
                    detail    = json.loads(event.get("CloudTrailEvent", "{}"))
                    source_ip = detail.get("sourceIPAddress", "unknown")
                except (json.JSONDecodeError, Exception):
                    pass

                # Detect external (non-RFC1918, non-AWS-internal) source IPs
                is_external = (
                    source_ip not in ("unknown", "AWS Internal")
                    and not any(source_ip.startswith(p) for p in _PRIVATE_PREFIXES)
                )

                DATA_PLANE_EVENTS = {"GetObject", "PutObject", "DeleteObject", "DeleteObjects"}
                is_anonymous      = username in ("Anonymous", "anonymous", "")

                if is_external:
                    # Flag as external access / exploitation signal if anonymous OR data-plane object operation
                    if is_anonymous or event_name in DATA_PLANE_EVENTS:
                        external_access = True
                        sig = f"external_ip_called_{event_name}: {source_ip}"
                        if sig not in exploitation_signals:
                            exploitation_signals.append(sig)

                # Anonymous access detection (unsigned S3 requests, public API calls)
                if is_anonymous:
                    external_access = True
                    sig = f"anonymous_access_on_{event_name}"
                    if sig not in exploitation_signals:
                        exploitation_signals.append(sig)

                key = f"{username}|{source_ip}"
                if key not in callers:
                    callers[key] = {
                        "username":    username,
                        "source_ip":   source_ip,
                        "is_external": is_external,
                        "events":      [],
                    }
                if event_name not in callers[key]["events"]:
                    callers[key]["events"].append(event_name)

            unique_callers = list(callers.values())[:15]   # cap for prompt size

            has_ext_callers = any(c.get("is_external", False) for c in unique_callers)
            ext_ip_note = "External IP(s) observed for authenticated IAM admin management. " if has_ext_callers else "All callers from internal/AWS IPs. "

            result = {
                "source":                   "cloudtrail",
                "logging_enabled":          True,
                "evidence_window_days":     days,
                "total_events_found":       len(raw_events),
                "unique_callers":           unique_callers,
                "external_access_detected": external_access,
                "exploitation_signals":     exploitation_signals,
                "analyst_summary": (
                    f"{len(raw_events)} event(s) in last {days} days from "
                    f"{len(unique_callers)} unique caller(s). {ext_ip_note}"
                    + ("[!] UNAUTHORIZED EXTERNAL DATA ACCESS DETECTED. " if external_access else "No unauthorized data plane access or exploitation signals detected.")
                ),
            }
            # Cache the result so repeated queries for the same resource in this scan skip the API call
            self._cloudtrail_cache[cache_key] = result
            return result

        except Exception as e:
            logger.debug(f"[ActivityEvidence] CloudTrail query failed for {resource_name}: {e}")
            return {
                "source":          "cloudtrail",
                "logging_enabled": False,
                "error":           str(e),
                "analyst_summary": "CloudTrail query unavailable — cannot determine recent access history.",
            }

    def _store_cloudtrail_result(self, cache_key: tuple, result: dict) -> dict:
        """Store a CloudTrail result in the per-scan cache and return it."""
        self._cloudtrail_cache[cache_key] = result
        return result

    def _query_vpc_flow_logs(
        self,
        vpc_id: str,
        ports: list = None,
        days: int = 30,
        target_ips: list = None,
        start_time: datetime = None,
    ) -> dict:
        """
        Query VPC Flow Logs via CloudWatch Logs Insights to find which source IPs
        have actually been connecting to specified ports in the last N days.

        This provides the EMPIRICAL EVIDENCE needed to replace a broad CIDR rule
        (like 0.0.0.0/0) with a surgical, least-privilege replacement using only
        the IPs that have actually connected — not a guess.

        Requires: VPC Flow Logs enabled and sending to CloudWatch Logs.
        If not enabled, returns a clear advisory so the analyst is aware.
        """
        # ── Cache check: many SG findings share the same VPC+port combination. ──
        # Serving from cache avoids a fresh CloudWatch Insights query (2-20s each)
        # for every single finding in the same VPC.
        cache_key = (
            vpc_id,
            tuple(sorted(ports)) if ports else (),
            tuple(sorted(target_ips)) if target_ips else (),
        )
        if cache_key in self._flow_log_cache:
            logger.debug(f"[FlowLogs] Cache HIT for {vpc_id} ports={ports} — skipping CloudWatch query")
            return self._flow_log_cache[cache_key]

        try:
            # Step 1: Check if flow logs exist for this VPC
            fl_resp = self.ec2.describe_flow_logs(
                Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
            )
            flow_logs = fl_resp.get("FlowLogs", [])

            if not flow_logs:
                return {
                    "source":          "vpc_flow_logs",
                    "logging_enabled": False,
                    "analyst_summary": (
                        f"VPC Flow Logs NOT enabled on {vpc_id}. "
                        "Cannot determine which IPs are actively connecting. "
                        "Recommendation: enable Flow Logs for evidence-based remediation decisions. "
                        "Without this, the system falls back to replacing 0.0.0.0/0 with VPC CIDR (broad)."
                    ),
                }

            # Step 2: Find an ACTIVE flow log sending to CloudWatch Logs
            cw_fl = next(
                (fl for fl in flow_logs
                 if fl.get("FlowLogStatus") == "ACTIVE"
                 and fl.get("LogDestinationType") == "cloud-watch-logs"),
                None,
            )

            if not cw_fl:
                return {
                    "source":          "vpc_flow_logs",
                    "logging_enabled": True,
                    "analyst_summary": (
                        "Flow Logs active but destination is S3, not CloudWatch Logs. "
                        "Programmatic query requires CloudWatch Logs destination. "
                        "Check S3 destination manually for connection history."
                    ),
                }

            log_group = cw_fl.get("LogGroupName", "/aws/vpc/flowlogs")

            if ports:
                port_conditions = " or ".join([f"dstPort = {int(p)}" for p in ports])
                port_filter = f"| filter ({port_conditions})"
            else:
                port_filter = ""   # query all accepted traffic

            if target_ips:
                ip_conditions = " or ".join([f"dstAddr = '{ip}'" for ip in target_ips])
                ip_filter = f"| filter ({ip_conditions})"
            else:
                ip_filter = ""

            query_string = f"""
                fields srcAddr, dstPort, action, bytes
                | filter action = "ACCEPT"
                {port_filter}
                {ip_filter}
                | stats count() as connections, sum(bytes) as total_bytes by srcAddr, dstPort
                | sort connections desc
                | limit 25
            """

            if start_time:
                # ensure timezone awareness
                if start_time.tzinfo is None:
                    start_time = start_time.replace(tzinfo=timezone.utc)
                start_ts = int(start_time.timestamp())
            else:
                start_ts = int((datetime.now(timezone.utc) - timedelta(days=days)).timestamp())

            end_ts   = int(datetime.now(timezone.utc).timestamp())
            
            # safeguard start_ts
            if start_ts > end_ts:
                start_ts = end_ts - 3600

            start_resp = self.logs.start_query(
                logGroupName=log_group,
                startTime=start_ts,
                endTime=end_ts,
                queryString=query_string,
            )
            query_id = start_resp["queryId"]

            # Step 4: Poll with exponential backoff — most queries complete in 2-4s.
            # Rigid 1s sleeps waste time; backoff lets fast queries return immediately.
            result_resp = None
            final_status = "Unknown"
            wait = 0.3   # initial wait in seconds
            elapsed = 0.0
            max_wait = 12.0  # Previously 20s. 12s is still generous; if CW Insights
                             # hasn't completed in 12s it returns a graceful timeout msg.
            while elapsed < max_wait:
                time.sleep(wait)
                elapsed += wait
                result_resp = self.logs.get_query_results(queryId=query_id)
                final_status = result_resp.get("status", "")
                if final_status == "Complete":
                    break
                if final_status in ("Failed", "Cancelled"):
                    return {
                        "source":          "vpc_flow_logs",
                        "logging_enabled": True,
                        "analyst_summary": f"Flow Logs query {final_status} — try again.",
                    }
                wait = min(wait * 2, 4.0)   # double wait each round, cap at 4s

            if final_status != "Complete":
                return {
                    "source":          "vpc_flow_logs",
                    "logging_enabled": True,
                    "analyst_summary": (
                        "Flow Logs query timed out (>20s). CloudWatch Insights may be slow on large log groups. "
                        "Results unavailable for this scan — re-run to retry."
                    ),
                }

            # Step 5: Parse results
            _PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                                 "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                                 "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                                 "172.30.", "172.31.", "192.168.", "127.")

            rows = result_resp.get("results", []) if result_resp else []
            observed_ips = []
            for row in rows:
                r = {f["field"]: f["value"] for f in row}
                src_ip = r.get("srcAddr", "")
                if not src_ip:
                    continue
                is_external = not any(src_ip.startswith(p) for p in _PRIVATE_PREFIXES)
                observed_ips.append({
                    "ip":          src_ip,
                    "dst_port":    r.get("dstPort", "unknown"),
                    "connections": int(r.get("connections", 0)),
                    "total_bytes": int(r.get("total_bytes", 0)),
                    "is_external": is_external,
                })

            external_ips  = [e for e in observed_ips if e["is_external"]]
            internal_ips  = [e for e in observed_ips if not e["is_external"]]
            exploitation_signals = [
                f"external_ip_connected: {e['ip']} (port {e['dst_port']}, {e['connections']} connections)"
                for e in external_ips
            ]

            # Surgical replacement suggestion: use only observed internal IPs
            suggested_replacements = [
                f"{e['ip']}/32"
                for e in internal_ips[:10]   # top 10 internal IPs by connection count
            ]

            result = {
                "source":                    "vpc_flow_logs",
                "logging_enabled":           True,
                "evidence_window_days":      days,
                "observed_source_ips":       observed_ips,
                "external_connections":      external_ips,
                "external_access_detected":  len(external_ips) > 0,
                "exploitation_signals":      exploitation_signals,
                "suggested_cidr_replacements": suggested_replacements,
                "analyst_summary": (
                    f"{len(observed_ips)} unique source IP(s) connected in last {days} days. "
                    + (f"[!] {len(external_ips)} EXTERNAL IP(s) connected — possible active exploitation: "
                       f"{[e['ip'] for e in external_ips]}. " if external_ips else "No external connections detected. ")
                    + (f"Suggested surgical CIDR replacements (internal only): {suggested_replacements}."
                       if suggested_replacements else "No internal connections observed.")
                ),
            }
            # Store in cache so identical VPC+port queries in this scan skip CloudWatch
            self._flow_log_cache[cache_key] = result
            return result

        except Exception as e:
            logger.debug(f"[ActivityEvidence] VPC Flow Logs query failed for {vpc_id}: {e}")
            return {
                "source":          "vpc_flow_logs",
                "logging_enabled": False,
                "error":           str(e),
                "analyst_summary": "VPC Flow Logs query unavailable — cannot determine active connection history.",
            }
