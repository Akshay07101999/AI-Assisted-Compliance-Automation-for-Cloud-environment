# AI-Assisted Compliance Automation for Cloud Environments

**ComplianceGuard** is a research prototype of an AI-assisted security compliance system that audits, analyses, and applies remediation actions to AWS cloud misconfigurations. It combines deterministic rule-based scanning with an LLM-assisted decision pipeline and a real-time dashboard to deliver context-aware, risk-ranked remediation proposals — with governance and audit logging throughout.

---

## 🚀 Key Features

- **LLM-Assisted Remediation**: Detects misconfigurations across EC2, S3, RDS, IAM, and EBS and generates AI-assisted remediation proposals for administrator review and approval.
- **Deterministic Risk Scoring**: Uses a multi-signal Operational Risk Score to prioritise findings by severity, environment criticality, and data sensitivity.
- **Context-Aware Decisions**: The orchestrator collects live cloud context (VPC topology, traffic patterns, existing exceptions) before generating remediation actions.
- **Real-Time Dashboard**: A Flask-powered web dashboard provides live scan status, finding summaries, risk trends, and one-click remediation triggers at `http://localhost:5050`.
- **Governance & Audit Logging**: Every scan, decision, and remediation action is persisted to a structured audit log with timestamps, justifications, and exception tracking.
- **Exception Registry**: Formally register approved exceptions with expiry dates, preventing repeated alerts on known-accepted risks.
- **CIS Benchmark Aligned**: Controls map directly to CIS AWS Foundations Benchmark v1.5 and AWS Security Hub standards.

---

## 🛠 Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   ComplianceGuard Engine                │
│                                                         │
│  ┌──────────┐   ┌──────────────┐   ┌────────────────┐  │
│  │ Scanner  │──▶│  Orchestrator│──▶│  Remediator    │  │
│  │          │   │              │   │                │  │
│  │ EC2 / S3 │   │  Context +   │   │  AI Patch +    │  │
│  │ RDS / IAM│   │  Risk Scorer │   │  Safe Apply    │  │
│  │ EBS      │   │  + LLM Brain │   │                │  │
│  └──────────┘   └──────────────┘   └────────────────┘  │
│        │                │                   │           │
│        ▼                ▼                   ▼           │
│  ┌──────────────────────────────────────────────────┐   │
│  │          Governance & Audit Layer                │   │
│  │   Audit Logger │ Exception Registry │ Reports    │   │
│  └──────────────────────────────────────────────────┘   │
│                          │                              │
│                          ▼                              │
│              ┌───────────────────────┐                  │
│              │  Real-Time Dashboard  │                  │
│              │  Flask + Vanilla JS   │                  │
│              │  http://localhost:5050│                  │
│              └───────────────────────┘                  │
└─────────────────────────────────────────────────────────┘
```

### Core Modules

| Module | File | Responsibility |
|---|---|---|
| **Scanner** | `scanner/scanner.py` | Audits AWS resources and produces structured findings |
| **EC2 Controls** | `scanner/controls/ec2_controls.py` | Detects open ports, public IPs, unencrypted volumes |
| **S3 Controls** | `scanner/controls/s3_controls.py` | Flags public buckets, missing encryption, no versioning |
| **RDS Controls** | `scanner/controls/rds_controls.py` | Checks public RDS instances, unencrypted storage |
| **IAM Controls** | `scanner/controls/iam_controls.py` | Detects root usage, no MFA, overly permissive policies |
| **EBS Controls** | `scanner/controls/ebs_controls.py` | Identifies unencrypted and unattached volumes |
| **Orchestrator** | `decision/orchestrator.py` | Coordinates the full scan → analyse → remediate pipeline |
| **Remediator** | `decision/remediator.py` | Generates and applies AI-assisted remediation actions |
| **CIDR Classifier** | `decision/cidr_classifier.py` | Classifies IP ranges for security group rule analysis |
| **LLM Client** | `ai/llm_client.py` | Interfaces with the LLM for intelligent patch generation |
| **Risk Scorer** | `ai/risk_scorer.py` | Multi-signal risk prioritisation engine |
| **Context Collector** | `context/context_collector.py` | Gathers live AWS environment context pre-remediation |
| **Audit Logger** | `governance/audit_logger.py` | Immutable, timestamped log of all actions |
| **Exception Registry** | `governance/exception_registry.py` | Manages approved compliance exceptions with expiry |
| **Dashboard Server** | `dashboard/server.py` | Flask API + static file server for the web UI |

---

## 🚦 Getting Started

### Prerequisites

- Python `3.9+`
- AWS account with credentials configured (`~/.aws/credentials` or env vars)
- IAM role/user with appropriate permissions (see [Minimum IAM Permissions](#minimum-iam-permissions) below)
- NVIDIA NIM API key for AI-assisted analysis — free tier available at [build.nvidia.com](https://build.nvidia.com)

### Installation

```bash
git clone https://github.com/Akshay07101999/AI-Assisted-Compliance-Automation-for-Cloud-environment.git
cd AI-Assisted-Compliance-Automation-for-Cloud-environment
pip install -r requirements.txt
```

### Configure AWS Credentials

```bash
aws configure
# Or export directly:
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_DEFAULT_REGION=us-east-1
```

### Configure LLM Key

```bash
export NVIDIA_API_KEY=your_nvidia_api_key
```

> **Getting an NVIDIA NIM key**: Sign up at [build.nvidia.com](https://build.nvidia.com), create an API key under your profile, and export it as shown above. The free tier provides enough credits to run the full demo.

### Run a Compliance Scan

```bash
python run_compliance_scan.py
```

### Launch the Real-Time Dashboard

```bash
python dashboard/server.py
# Open: http://localhost:5050
```

### Run the Full Pipeline (Scan → Analyse → Remediate)

```bash
python run_pipeline.py
```

### CLI Rollback (Restore Pre-Remediation State)

```bash
python run_pipeline.py --rollback sg-0170c84b16ee7dfad
```

---

## 🤖 LLM Prompt Templates (Section 8.7)

ComplianceGuard uses structured prompt engineering to ground LLM decisions in live AWS context and multi-source telemetry.

The complete prompt templates, system instructions, and JSON schemas referenced in **Section 8.7** are available in:

📄 **[`ai/PROMPT_TEMPLATES.md`](ai/PROMPT_TEMPLATES.md)**

- **System Role Prompt**: Sets the cloud security architect persona and response boundaries.
- **RCA & Remediation Planning Template**: Invoked for high-risk findings and Safety Gate hazard blocks (`quick_approve` / `investigate`).
- **Architectural Safety Verification Template**: Invoked in `proceed_verify` mode before automated changes.
- **Strict JSON Output Schema**: Enforces structured machine-parsable responses with root cause, impact, fix steps, and rollback plans.

---

## 🧪 Demo Scenarios

The system runs against real AWS resources. Point it at any AWS account where misconfigured resources exist, or manually create violations (e.g., a Security Group with SSH open to `0.0.0.0/0`, an S3 bucket with Block Public Access disabled, an RDS instance with `PubliclyAccessible=True`).

The pipeline will detect, score, gate, and remediate (or escalate) each finding:

| Scenario type | Expected Safety Gate | Resolution path |
|---|---|---|
| Orphaned / unattached resource, dev environment | PROCEED | Auto-remediate |
| Active production workload with live traffic | BLOCK | LLM investigate → admin review |
| Database port exposed, instances attached | BLOCK | LLM investigate → admin review |
| Confirmed-dormant IAM key (>90 days unused) | PROCEED | Auto-remediate |
| Static website S3 bucket with BPA disabled | BLOCK | LLM investigate → admin review |

> **Cost note**: RDS instances accrue charges if left running. Terminate any test RDS instances after evaluation.

---

## 🔑 Minimum IAM Permissions

Create an IAM policy with the following actions. Read-only mode requires only the first block; auto-remediation additionally requires the write actions.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ComplianceGuardRead",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeAddresses",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeVolumes",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketAcl",
        "s3:GetBucketWebsite",
        "s3:GetBucketPolicy",
        "s3:ListAllMyBuckets",
        "rds:DescribeDBInstances",
        "iam:ListUsers",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:GetUser",
        "iam:ListMFADevices",
        "sts:GetCallerIdentity",
        "logs:StartQuery",
        "logs:GetQueryResults",
        "logs:DescribeLogGroups"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ComplianceGuardRemediate",
      "Comment": "Required only for auto-remediation mode",
      "Effect": "Allow",
      "Action": [
        "ec2:RevokeSecurityGroupIngress",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:DisassociateAddress",
        "s3:PutBucketPublicAccessBlock",
        "rds:ModifyDBInstance",
        "iam:UpdateAccessKey"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## 📊 Dashboard

The ComplianceGuard dashboard provides a live view of your cloud compliance posture:

- **Live Scan Trigger** — kick off a full pipeline scan with one click
- **Finding Summary** — breakdown by service, severity, and control
- **Risk Trends** — track compliance score over time
- **Remediation Log** — view all actions taken with AI justifications
- **Exception Manager** — register and review approved exceptions

```
GET  /              → Dashboard UI
GET  /api/report    → Latest scan_report.json
POST /api/scan      → Trigger full pipeline
GET  /api/status    → Current scan status (idle / running)
```

---

## 🔍 Compliance Controls Coverage

| Service | Controls |
|---|---|
| **EC2** | Open SSH/RDP to 0.0.0.0/0, unrestricted security groups, public IPs on sensitive instances |
| **S3** | Public bucket ACLs, missing bucket encryption, no versioning, no access logging |
| **RDS** | Publicly accessible instances, unencrypted storage, no multi-AZ, default ports exposed |
| **IAM** | Root account usage, users without MFA, inline policies, overly permissive wildcard policies |
| **EBS** | Unencrypted volumes, unattached volumes, unencrypted snapshots |

---

## 🏛 Governance

ComplianceGuard treats governance as a first-class citizen:

- **Immutable Audit Trail**: Every scan finding, remediation decision, and exception grant is logged with actor, timestamp, and justification.
- **Exception Registry**: Formally track accepted risks with mandatory expiry dates. Exceptions are re-evaluated automatically at expiry.
- **Remediation Justifications**: The LLM generates a plain-English rationale for every automated fix — human-readable and audit-ready.

---

## 🔒 Security Design

ComplianceGuard operates on the principle of **Minimum Required Exposure**.

Key principles:
- **Deny by default**: New resources inherit the most restrictive posture.
- **Context before action**: No remediation is applied without first collecting live environment context.
- **Indirect Prompt Injection Defences**: AWS-derived contextual data (tags, descriptions) is treated as untrusted and isolated from trusted prompt instructions. Output is strictly schema-validated with field-level allow-lists.
- **Advisory LLM Output Only**: The LLM is never given direct AWS execution privileges. Generated remediation steps are advisory proposals evaluated against deterministic safety gates and administrative approvals.
- **Human override & Rollback**: All remediations can be reviewed and rolled back on-demand via the web dashboard or CLI.
- **Exception expiry**: No exception is permanent — all must be renewed with a fresh justification.

---

## 📁 Project Structure

```
AI-Assisted-Compliance-Automation-for-Cloud-environment/
├── ai/
│   ├── llm_client.py             # LLM API interface (NVIDIA NIM)
│   ├── risk_scorer.py            # Multi-signal risk prioritisation
│   └── PROMPT_TEMPLATES.md       # Section 8.7 LLM prompt templates & schemas
├── context/
│   └── context_collector.py      # Live AWS environment context gathering
├── decision/
│   ├── orchestrator.py           # End-to-end pipeline coordinator
│   ├── remediator.py             # Remediation action generator & applier
│   └── cidr_classifier.py        # IP/CIDR range security classifier
├── scanner/
│   ├── scanner.py                # Main scanner entrypoint
│   └── controls/
│       ├── ec2_controls.py
│       ├── s3_controls.py
│       ├── rds_controls.py
│       ├── iam_controls.py
│       └── ebs_controls.py
├── dashboard/
│   ├── server.py                 # Flask API server
│   ├── index.html                # Dashboard UI
│   ├── app.js                    # Dashboard logic
│   └── style.css                 # Dashboard styles
├── governance/
│   ├── audit_logger.py           # Immutable action logger
│   └── exception_registry.py     # Compliance exception manager
├── tests/
│   ├── test_pipeline.py          # Unit + integration tests
│   ├── validate_non_s3_logic.py  # Non-S3 logic validation
│   ├── validate_s3_logic.py      # S3 logic validation
│   └── setup_s3_test_bucket.py   # S3 test fixture setup
├── run_compliance_scan.py        # Quick scan entrypoint
├── run_pipeline.py               # Full pipeline entrypoint
├── requirements.txt              # Python dependencies
└── README.md
```

---

## 🧪 Testing

```bash
pytest tests/

python tests/validate_non_s3_logic.py
python tests/validate_s3_logic.py
```

---

## 📄 License

This project is part of a cloud security capstone and is provided for educational and research purposes.

---

*Built with ❤️ using Python, boto3, Flask, and LLM-assisted intelligence.*
