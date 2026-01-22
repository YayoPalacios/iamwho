# iamwho

> **Static IAM analyzer that shows what happens when one identity is compromised.**

<!-- ![demo](./assets/demo.gif) -->

---

## Why

Most AWS IAM tools answer a narrow question:

> *"Is this action allowed?"*

**iamwho** focuses on a different failure mode:

> *"If this identity is compromised, what else becomes reachable?"*

| AWS Tool | Focus | What It Misses |
|:---------|:------|:---------------|
| IAM Access Analyzer | External access, unused permissions | Chained attack paths |
| Policy Simulator | Point-in-time authorization | Post-compromise reach |
| Config Rules | Compliance posture | Permission composition |

**iamwho** exists to reason about **impact**, not just access.

---

## What iamwho does

**iamwho** is a static **AWS IAM security analyzer** built to look at IAM the way an attacker would.

It helps answer three core questions:

- **INGRESS** - Who can assume this role?
- **EGRESS** - What permissions does the role effectively grant?
- **MUTATION** - Can those permissions be used to escalate or persist access?

This tool is intentionally scoped for **security analysis**, not IAM education or policy authoring.

---

## Installation

```bash
pip install git+https://github.com/YayoPalacios/iamwho.git
```

For development:

```bash
git clone https://github.com/YayoPalacios/iamwho.git
cd iamwho
pip install -e .
```

**Requirements**
- Python 3.9+
- boto3
- rich
- typer

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
iamwho analyze <role-arn> -V

# JSON output (CI/CD friendly)
iamwho analyze <role-arn> --json

# Use a specific AWS profile
AWS_PROFILE=prod iamwho analyze <role-arn>
```

---

## Checks

| Check | Question It Answers |
|:------|:--------------------|
| ingress | Who can become this role? |
| egress | What does this role enable? |
| mutation | Can access escalate or persist? |

---

## Risk levels

| Level | Meaning |
|:------|:--------|
| **CRITICAL** | Privilege escalation, IAM mutation, admin-level access |
| **HIGH** | Broad data access, service control |
| **MEDIUM** | Enumeration, scoped high-risk actions |
| **LOW** | Read-only or tightly scoped access |

---

## Example output

![iamwho demo](assets/demo.png)

---

## Roadmap

- [x] INGRESS analysis (trust policies)
- [x] EGRESS analysis (permissions)
- [x] MUTATION analysis (escalation paths)
- [x] --json output for CI/CD
- [ ] Permission boundary analysis
- [ ] SCP impact detection
- [ ] Multi-role blast radius analysis

---

## What iamwho does not do

- Runtime detection or CloudTrail analysis
- Full IAM policy simulation
- Network or secrets analysis
- Compliance mapping (CIS, SOC2, etc.)

**iamwho** focuses on **static IAM graph analysis** - understanding what becomes reachable when an identity is abused.

---
### Documentation 
- [Cheatsheet](docs/cheatsheet.md) — quick reference
- [Methodology](docs/methodology.md) — how iamwho thinks about IAM
---
## License

MIT
