# iamwho

**iamwho** is a static **AWS IAM security analyzer** that helps you understand:

- **Who can assume a role** (ingress / trust policies)
- **What that role can do** (egress / effective permissions)
- **How privileges could expand** (mutation / escalation paths – upcoming)

It is designed for **security analysis**, not IAM usage tutorials.

---

## What it does

| Analysis | Description |
|--------|-------------|
| **INGRESS** | Who can assume this role? (trust policy analysis) |
| **EGRESS** | What can this role do? (attached & inline policies) |
| **PRIVILEGE MUTATION** | Can it escalate further? *(coming soon)* |

---

## Installation

```bash
# Clone the repository
git clone https://github.com/YayoPalacios/iamwho.git
cd iamwho

# Install in editable mode
pip install -e .

# Or run directly
PYTHONPATH=src python -m iamwho.cli analyze <role-arn>
```

**Requirements**
- Python 3.9+
- boto3
- rich

---

## Usage

```bash
# Analyze a role
iamwho analyze arn:aws:iam::123456789012:role/my-role

# Use a specific AWS profile
AWS_PROFILE=prod iamwho analyze arn:aws:iam::123456789012:role/my-role
```

---

## Example Output

### INGRESS Analysis

```
INGRESS Analysis: arn:aws:iam::123456789012:role/my-role
============================================================
Overall Risk: MEDIUM | Findings: 1

[MEDIUM] arn:aws:iam::123456789012:root
  Type: AWSRoot | Assume: AssumeRole
  Trusts entire AWS account (root).
  Remediation: Replace :root with specific role/user ARNs
```

---

### EGRESS Analysis

```
EGRESS Analysis
============================================================
Verdict: CRITICAL | Findings: 9

Categories: Identity & Access, Data Access, Privilege Escalation
Breakdown:
  CRITICAL: 3
  HIGH: 2
  MEDIUM: 4

[CRITICAL] [ALL] iam:CreateUser
  Can create backdoor users
  Source: Inline: DangerousPolicy

[HIGH] [ALL] s3:GetObject
  Can read S3 data (check Resource scope)
  Source: Managed: arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess

[MEDIUM] [SCOPED] lambda:InvokeFunction
  Can invoke Lambdas (scoped to specific resources)
  Resource: arn:aws:lambda:us-west-2:123456789012:function:my-func
```

---

## Risk Levels

| Level | Meaning |
|------|--------|
| 🔴 **CRITICAL** | Privilege escalation, IAM mutation, admin access |
| 🟠 **HIGH** | Broad data access, compute control |
| 🟡 **MEDIUM** | Enumeration, scoped dangerous actions |
| 🟢 **LOW** | Read-only, limited scope |

---

## Roadmap

- INGRESS analysis (trust policies)
- EGRESS analysis (permissions)
- PRIVILEGE MUTATION (escalation paths)
- `--output json` for CI/CD integration
- Permission boundary analysis
- SCP impact detection
- Multi-role blast radius analysis

---

## What iamwho does *not* do

- Runtime detection or CloudTrail analysis
- Full IAM policy simulation
- Network or secrets analysis
- Compliance mapping (CIS, SOC2, etc.)

iamwho focuses on **static IAM graph analysis** to surface high-impact security risk early.
