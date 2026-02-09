# iamwho Cheatsheet

> Quick reference for IAM security analysis.

---

## The Three Questions

| Check | Question |
|:------|:---------|
| **INGRESS** | Who can become this identity? |
| **EGRESS** | What can this identity do? |
| **MUTATION** | Can it escalate or persist? |

---

## Risk Levels

| Level | Meaning |
|:------|:--------|
| 🔴 **CRITICAL** | Privilege escalation or long-lived persistence |
| 🟠 **HIGH** | Broad service or data blast radius |
| 🟡 **MEDIUM** | Discovery, staging, or limited lateral movement |
| 🟢 **LOW** | Read-only or tightly scoped access |

---

## Trust Policy Red Flags

| Pattern | Risk | Why |
|:--------|:-----|:----|
| `"Principal": "*"` | 🔴 | Internet-assumable |
| OIDC without `sub` | 🔴 | Any token accepted |
| Cross-account root w/o ExternalId | 🟠 | Confused deputy |
| Service trust w/o SourceArn | 🟡 | Weak scoping |

---

## Dangerous Permissions

### Direct Escalation

```
iam:AttachUserPolicy
iam:AttachRolePolicy
iam:PutUserPolicy
iam:PutRolePolicy
iam:CreateAccessKey
```

### Indirect Escalation

```
iam:PassRole + lambda:CreateFunction
iam:PassRole + ec2:RunInstances
```

### Persistence

Creates long-lived or renewable credentials outside role assumption.

```
iam:CreateUser
iam:CreateRole
sts:GetFederationToken
```

---

## Conditions That Protect

### Cross-Account Trust

| Scenario | Condition |
|:---------|:----------|
| Vendor | `sts:ExternalId` |
| Org | `aws:PrincipalOrgID` |

### Service Principals

| Scenario | Condition |
|:---------|:----------|
| AWS service | `aws:SourceArn` |
| Account scope | `aws:SourceAccount` |

---

## Authorization Rules

| Context | Rule |
|:--------|:-----|
| Same-account | Identity **OR** resource |
| Cross-account | Identity **AND** resource |

---

## Quick Commands

```bash
iamwho analyze <role-arn>
iamwho analyze <role-arn> -c egress
iamwho analyze <role-arn> -V
iamwho analyze <role-arn> --json
AWS_PROFILE=prod iamwho analyze <role-arn>
```

---

## What iamwho Does Not Do

- Runtime detection
- CloudTrail analysis
- Full policy simulation

**iamwho** = static IAM graph analysis focused on reachability.
