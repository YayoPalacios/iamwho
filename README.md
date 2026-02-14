# iamwho
[![PyPI](https://img.shields.io/pypi/v/iamwho)](https://pypi.org/project/iamwho/)

> **iamwho: Static AWS IAM analyzer focused on post-compromise blast radius.**

![iamwho demo](./assets/demo.png)

---

## How iamwho Thinks About Risk

The diagram below illustrates the difference between **access analysis** and **impact analysis**.

- **Access analysis**: Determines whether an action is allowed.
- **Impact analysis**: Identifies what else becomes reachable once an identity is compromised.

![Impact vs Access analysis](assets/diagram.png)

*iamwho* analyzes this graph to expose escalation paths and blast-radius expansions that remain hidden when policies are evaluated in isolation.

---

## Why

While most AWS IAM tools focus on the question: 

> *Is this action allowed?*

This perspective is incomplete. **iamwho** shifts the focus to a crucial failure mode: 

> *If this identity is compromised, what else becomes reachable?*

Recognizing that attackers consider **trust chains**, **permission composition**, and their potential next steps is vital.

| AWS Tool | Primary Focus | Blind Spot |
|:---------|:--------------|:-----------|
| IAM Access Analyzer | External access, unused permissions | Chained trust & role hopping |
| Policy Simulator | Point-in-time authorization | Post-compromise reach |
| Config Rules | Compliance posture | Effective permission composition |

IAM risk rarely resides within a single policy. A role might seem low risk in isolation yet become dangerous when:
- Assumed by another reachable identity
- Grants permissions enabling mutations
- Unlocks additional roles or services

**iamwho** examines these relationships as a graph, making visible the **ingress → egress → mutation** paths that expand the blast radius, even when individual policies appear secure.


---
## What iamwho Does

**iamwho** is a static **AWS IAM security analyzer** that evaluates IAM configurations and trust relationships from an attacker's perspective. It focuses solely on static analysis, without relying on runtime activity, logs, or CloudTrail events.

The tool answers three core questions:
- **INGRESS** — Who can assume this identity?
- **EGRESS** — What does this identity enable?
- **MUTATION** — Can access be escalated or persisted?

**iamwho** is designed for security impact analysis and does not include:
- Runtime detection or IAM activity monitoring.
- Full IAM policy simulation for real-time permission testing.
- Network or secrets analysis outside of IAM configurations.
- Compliance mapping for standards such as CIS, SOC2, etc.

By focusing on these areas, **iamwho** identifies potential vulnerabilities and escalation paths that may not be apparent through isolated policy evaluations, helping to improve your overall security posture.

---

## Installation

```bash
pip install iamwho
```

---

## Quick Start

```bash
pip install iamwho && iamwho analyze arn:aws:iam::123456789012:role/MyRole
```

For development:

```bash
git clone https://github.com/YayoPalacios/iamwho.git
cd iamwho
pip install -e .
```

---

## Requirements

- Python `3.10+`
- AWS credentials configured (env vars or profile)
- IAM read-only permissions for role and policy inspection (e.g. `iam:Get*`, `iam:List*`)

---

## Usage

```bash
# Run all checks
iamwho analyze arn:aws:iam::123456789012:role/MyRole

# Run a specific check
iamwho analyze <role-arn> --check egress
iamwho analyze <role-arn> -c ingress

# Verbose mode (reasoning and remediation hints)
iamwho analyze <role-arn> --verbose
iamwho analyze <role-arn> -v

# JSON output (CI/CD friendly)
iamwho analyze <role-arn> --json

# Fail if findings meet severity threshold (CI/CD gating)
iamwho analyze <role-arn> --fail-on high
iamwho analyze <role-arn> --fail-on critical

# Use a specific AWS profile
AWS_PROFILE=prod iamwho analyze <role-arn>
```


### Example Output

Running with `--verbose` provides reasoning and potential escalation paths:

```text
[HIGH] ! * iam:CreateAccessKey
           -> Can create access keys for users
           Source: inline:inline-danger
           Scope: ALL

[CRIT] ✗ sts:AssumeRole
           -> Can assume other IAM roles
           Source: inline:inline-danger
           Scope: ALL
```

Using `--json` produces structured output suitable for CI/CD and reporting:

```json
{
  "role": "MyRole",
  "findings": [
    {
      "check": "mutation",
      "severity": "CRITICAL",
      "description": "Privilege escalation via sts:AssumeRole",
      "path": ["MyRole", "AdminRole"]
    }
  ]
}
```

---

## CI/CD Integration

**iamwho** can block pull requests that introduce risky IAM roles.

### GitHub Actions

Create `.github/workflows/iam-audit.yml`:

```yaml
- name: Analyze IAM Role
  run: |
    pip install iamwho
    iamwho analyze $ROLE_ARN --fail-on high
```

### Severity Gating

| Flag | Behavior |
|------|----------|
| `--fail-on critical` | Fails only on critical findings |
| `--fail-on high` | Fails on high or critical |
| `--fail-on medium` | Fails on medium and above |
| `--fail-on low` | Fails on any finding |

### Required Secrets

| Secret | Description |
|--------|-------------|
| `AWS_ACCESS_KEY_ID` | IAM user access key |
| `AWS_SECRET_ACCESS_KEY` | IAM user secret key |

> The IAM principal requires read-only IAM permissions to inspect roles and attached policies.

---

## Checks

| Check | Question It Answers |
|:------|:--------------------|
| ingress | Who can become this role? |
| egress | What does this role enable? |
| mutation | Can access escalate or persist? |

---

## Risk Levels

| Level | Meaning |
|:------|:--------|
| **CRITICAL** | Enables privilege escalation or long-lived persistence |
| **HIGH** | Expands blast radius across services or roles |
| **MEDIUM** | Enables discovery, staging, or limited lateral movement |
| **LOW** | Read-only or tightly scoped access with minimal composition risk |

---

## Roadmap

- [x] INGRESS analysis (trust policies)
- [x] EGRESS analysis (permissions)
- [x] MUTATION analysis (escalation paths)
- [x] JSON output for CI/CD
- [x] Exit codes for CI gating (`--fail-on`)
- [x] PyPI package release

### Planned

- User and group principal support
- Permission boundary analysis

---

## Documentation

- [Cheatsheet](docs/cheatsheet.md) — quick reference
- [Methodology](docs/methodology.md) — how iamwho reasons about IAM risk

---

## License

iamwho is licensed under the MIT License.
The MIT License permits users to use, copy, modify, and distribute the software with minimal restrictions. The only requirement is to include the original copyright and permission notice in all copies or substantial portions of the software.
This allows you to freely use iamwho in both open-source and proprietary projects.
