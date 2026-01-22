# iamwho Cheatsheet

> Quick reference for IAM security analysis.

---

## The three questions

| Check | Question |
|:------|:---------|
| **INGRESS** | Who can become this identity? |
| **EGRESS** | What can this identity do? |
| **MUTATION** | Can it escalate or persist? |

---

## Risk levels

| Level | Meaning |
|:------|:--------|
| 🔴 **CRITICAL** | Privilege escalation, admin access |
| 🟠 **HIGH** | Broad data or service control |
| 🟡 **MEDIUM** | Enumeration, scoped risk |
| 🟢 **LOW** | Read-only, constrained |

---

## Trust policy red flags

| Pattern | Risk | Why |
|:--------|:-----|:----|
| `"Principal": "*"` | 🔴 | Internet-assumable |
| OIDC without `sub` | 🔴 | Any token accepted |
| Cross-account root w/o ExternalId | 🟠 | Confused deputy |
| Service trust w/o SourceArn | 🟡 | Weak scoping |

---

## Dangerous permissions

### Direct escalation

```
iam:AttachUserPolicy
iam:AttachRolePolicy
iam:PutUserPolicy
iam:PutRolePolicy
iam:CreateAccessKey
```

### Indirect escalation

```
iam:PassRole + lambda:CreateFunction
iam:PassRole + ec2:RunInstances
```

### Persistence

```
iam:CreateUser
iam:CreateRole
sts:GetFederationToken
```

---

## Conditions that protect

### Cross-account trust

| Scenario | Condition |
|:---------|:----------|
| Vendor | `sts:ExternalId` |
| Org | `aws:PrincipalOrgID` |

### Service principals

| Scenario | Condition |
|:---------|:----------|
| AWS service | `aws:SourceArn` |
| Account scope | `aws:SourceAccount` |

---

## Authorization rules

| Context | Rule |
|:--------|:-----|
| Same-account | Identity **OR** resource |
| Cross-account | Identity **AND** resource |

---

## Quick commands

```bash
iamwho analyze <role-arn>
iamwho analyze <role-arn> -c egress
iamwho analyze <role-arn> -V
iamwho analyze <role-arn> --json
AWS_PROFILE=prod iamwho analyze <role-arn>
```

---

## What iamwho doesn't do

- Runtime detection
- CloudTrail analysis
- Full policy simulation

iamwho = static IAM graph analysis.
