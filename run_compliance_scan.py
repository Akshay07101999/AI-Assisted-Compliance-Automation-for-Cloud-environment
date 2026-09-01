"""
ComplianceGuard -- Compliance Scanner
"""
import sys, os
sys.stdout.reconfigure(encoding='utf-8')
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from scanner.scanner import ComplianceScanner
from datetime import datetime, timezone

# Human-readable control descriptions
CONTROL_DESC = {
    'CIS-2.1.4':        'S3 Block Public Access Disabled',
    'CIS-2.1.1':        'S3 Server-Side Encryption Disabled',
    'CIS-2.1.2':        'S3 Access Logging Disabled',
    'CIS-2.1.5':        'S3 Versioning Not Enabled',
    'CIS-5.2':          'Unrestricted SSH/RDP Inbound Rule',
    'CIS-5.3':          'Default Security Group Has Active Rules',
    'Org-SG-DB':        'Database Port Exposed to Internet',
    'Org-5':            'EC2 Instance Directly Internet-Exposed',
    'CIS-2.3.2':        'RDS Instance Publicly Accessible',
    'CIS-2.3.1':        'RDS Storage Encryption Disabled',
    'Org-RDS-SG-Chain': 'RDS CIDR-Based Access (SG Chaining Required)',
    'CIS-1.14':         'IAM Access Key Not Rotated (>90 Days)',
    'CIS-1.16':         'IAM Policy Grants Wildcard Permissions',
}

# Service domain grouping
GROUPS = [
    ('S3 Storage',            ['AWS::S3::Bucket']),
    ('EC2 / Security Groups', ['AWS::EC2::SecurityGroup']),
    ('EC2 / Instances',       ['AWS::EC2::Instance']),
    ('RDS',                   ['AWS::RDS::DBInstance']),
    ('IAM',                   ['AWS::IAM::User', 'AWS::IAM::AccessKey']),
]

def get_group(rtype):
    for label, types in GROUPS:
        if rtype in types:
            return label
    return 'Other'

def violation_detail(ctrl, details):
    d = details or {}

    if ctrl == 'CIS-2.1.4':
        flags = []
        if not d.get('BlockPublicAcls',       True): flags.append('BlockPublicAcls')
        if not d.get('IgnorePublicAcls',      True): flags.append('IgnorePublicAcls')
        if not d.get('BlockPublicPolicy',     True): flags.append('BlockPublicPolicy')
        if not d.get('RestrictPublicBuckets', True): flags.append('RestrictPublicBuckets')
        if len(flags) == 4:
            return 'All 4 Block Public Access settings are disabled'
        return 'Disabled: ' + ', '.join(flags) if flags else d.get('reason', 'BPA misconfigured')

    elif ctrl == 'CIS-5.2':
        port  = d.get('port', '?')
        label = 'SSH' if port == 22 else ('RDP' if port == 3389 else f'port {port}')
        cidrs = ', '.join(d.get('cidrs', ['0.0.0.0/0']))
        return f'Port {port} ({label}) open to {cidrs}'

    elif ctrl == 'Org-SG-DB':
        port    = d.get('port', d.get('db_port', '?'))
        service = d.get('service', '')
        cidrs   = ', '.join(d.get('cidrs', ['0.0.0.0/0']))
        svc_str = f' ({service})' if service else ''
        return f'Port {port}{svc_str} open to {cidrs} — database endpoint internet-reachable'

    elif ctrl == 'Org-5':
        state  = d.get('instance_state', d.get('state', ''))
        pub_ip = d.get('public_ip', d.get('public_ip_address', ''))
        parts  = []
        if state:  parts.append(f'State: {state}')
        if pub_ip: parts.append(f'Public IP: {pub_ip}')
        return (', '.join(parts) + ' — no load balancer or CloudFront intermediary') if parts else 'Public IP assigned, no intermediary'

    elif ctrl == 'CIS-1.14':
        age     = d.get('key_age_days', '?')
        last    = d.get('last_used_days')
        svc     = d.get('last_used_service', '')
        dormant = d.get('is_dormant', False)
        used    = 'Never used' if last is None else f'Last used {last}d ago'
        svc_str = f' via {svc}' if svc else ''
        status  = '[DORMANT]' if dormant else '[ACTIVE]'
        return f'Key age: {age} days — {used}{svc_str} {status}'

    elif ctrl == 'CIS-2.3.2':
        parts = []
        if d.get('engine'):             parts.append(f'Engine: {d["engine"]}')
        if d.get('db_port'):            parts.append(f'Port: {d["db_port"]}')
        if d.get('db_instance_status'): parts.append(f'Status: {d["db_instance_status"]}')
        return 'PubliclyAccessible=True' + (' — ' + ', '.join(parts) if parts else '')

    return d.get('violation', d.get('reason', 'See finding details'))

# ── Main ───────────────────────────────────────────────────────────────────────

WIDTH = 132

now = datetime.now(timezone.utc)

print()
print('=' * WIDTH)
print(f'  ComplianceGuard — Compliance Scan Results')
print(f'  Region: us-east-1   |   Scan Time: {now.strftime("%Y-%m-%d %H:%M:%S UTC")}')
print('=' * WIDTH)
print()
print('  Scanning: S3  |  EC2 / Security Groups  |  RDS  |  IAM')
print()

scanner  = ComplianceScanner(region='us-east-1')
result   = scanner.run_full_scan(services=['s3', 'ec2', 'rds', 'iam'])
findings = [f for f in result.findings if f.get('status') == 'NON_COMPLIANT']

if not findings:
    print('  No violations detected — environment is fully compliant.')
    print()
else:
    # Group findings by service domain
    grouped = {}
    for f in findings:
        g = get_group(f.get('resource_type', ''))
        grouped.setdefault(g, []).append(f)

    total = len(findings)
    domains = len(grouped)
    print(f'  {total} NON_COMPLIANT finding(s) detected across {domains} service domain(s)')
    print()

    # Column widths
    C_NUM  =  4
    C_SVC  = 24
    C_CTRL = 16
    C_RES  = 34

    hdr = (
        f"  {'#':<{C_NUM}}"
        f"{'Service Domain':<{C_SVC}}"
        f"{'Control ID':<{C_CTRL}}"
        f"{'Resource ID':<{C_RES}}"
        f"Violation"
    )
    sep_heavy = '  ' + '=' * (WIDTH - 2)
    sep_light = '  ' + '-' * (WIDTH - 2)

    print(hdr)
    print(sep_heavy)

    idx          = 1
    group_order  = [g for g, _ in GROUPS] + ['Other']
    last_group   = None

    for grp in group_order:
        if grp not in grouped:
            continue
        grp_findings = grouped[grp]

        # Section separator between groups
        if last_group is not None:
            print(sep_light)

        # Section label (inline, not a separate header line)
        label_line = f"  {'':>{C_NUM}}  {grp.upper()} — {len(grp_findings)} finding(s)"
        print(label_line)
        print(sep_light)

        for f in grp_findings:
            ctrl   = f.get('control_id', '')
            rid    = f.get('resource_id', '')
            rtype  = f.get('resource_type', '')
            detail = violation_detail(ctrl, f.get('details', {}))

            svc_label = get_group(rtype)

            print(
                f"  {idx:<{C_NUM}}"
                f"{svc_label:<{C_SVC}}"
                f"{ctrl:<{C_CTRL}}"
                f"{rid:<{C_RES}}"
                f"{detail}"
            )
            idx += 1

        last_group = grp

    print(sep_heavy)
    print(f'  Total: {total} NON_COMPLIANT finding(s)   |   Scan ID: {result.scan_id}')
    print()
