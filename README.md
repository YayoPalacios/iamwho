# iamwho

**iamwho** is a static **AWS IAM security analyzer** that helps you
understand:

-   **Who can assume a role** (INGRESS -- trust policies)
-   **What that role can do** (EGRESS -- effective permissions)
-   **How privileges could escalate** (MUTATION -- escalation paths)

Built for **security analysis**, not IAM tutorials.

------------------------------------------------------------------------

## Installation

``` bash
git clone https://github.com/YayoPalacios/iamwho.git
cd iamwho
pip install -e .
```

**Requirements** - Python 3.9+ - boto3 - rich - typer

------------------------------------------------------------------------

## Usage

``` bash
# Run all checks
iamwho analyze arn:aws:iam::123456789012:role/my-role

# Run a specific check
iamwho analyze <role-arn> --check egress
iamwho analyze <role-arn> -c ingress

# Verbose mode (shows explanations & remediations)
iamwho analyze <role-arn> --verbose

# JSON output (CI/CD friendly)
iamwho analyze <role-arn> --json

# Use a specific AWS profile
AWS_PROFILE=prod iamwho analyze <role-arn>
```

------------------------------------------------------------------------

## Example Output

    TARGET: arn:aws:iam::123456789012:role/my-role

    [ EGRESS ] What can this role do?
    ------------------------------------------------------------
      Scope: * = all resources | ~ = scoped
      Categories: Compute, Data Access, Identity & Access

      CRITICAL * iam:CreateUser
               Can create new IAM users

      CRITICAL * iam:AttachUserPolicy
               Can attach policies to users

      HIGH     * s3:GetObject
               Can read S3 objects

      HIGH     ~ lambda:InvokeFunction
               Can invoke Lambda functions (scoped to specific resources)

    ============================================================
      RESULT: 2 CRITICAL | 2 HIGH
      Checks: EGRESS
    ============================================================

------------------------------------------------------------------------

## Checks

| Check | Description |
|:------|:------------|
| `ingress` | Who can assume this role? (trust policy analysis) |
| `egress` | What can this role do? (attached & inline policies) |
| `mutation` | Can privileges escalate? (escalation path detection) |

---

## Risk Levels

| Level | Meaning |
|:------|:--------|
| **CRITICAL** | Privilege escalation, IAM mutation, admin access |
| **HIGH** | Broad data access, compute control |
| **MEDIUM** | Enumeration, scoped dangerous actions |
| **LOW** | Read-only, limited scope |

------------------------------------------------------------------------

## Roadmap

-   INGRESS analysis (trust policies)
-   EGRESS analysis (permissions)
-   MUTATION analysis (escalation paths)
-   `--json` output for CI/CD
-   Permission boundary analysis
-   SCP impact detection
-   Multi-role blast radius analysis

------------------------------------------------------------------------

## What iamwho does *not* do

-   Runtime detection or CloudTrail analysis
-   Full IAM policy simulation
-   Network or secrets analysis
-   Compliance mapping (CIS, SOC2, etc.)

**iamwho** focuses on **static IAM graph analysis** to surface
high-impact security risk early.
