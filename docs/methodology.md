# iamwho – IAM Security Analysis Methodology

> How **iamwho** reasons about AWS IAM from an attacker’s perspective.

---

## Mental Model

iamwho models AWS IAM as a directed graph:

```
[ Principal ]
     │
     ├── (ingress)  ──▶ [ Role / Identity ]
     │
     ├── (egress)   ──▶ [ Capabilities ]
     │
     └── (mutation) ──▶ [ Escalation / Persistence ]
```

In this document, *principal* refers to the actor making the request,
and *identity* refers to the role or user being assumed or evaluated.

Every finding answers one of three questions:

| Check | Question |
|:------|:---------|
| **INGRESS** | Who can become this identity, and under what conditions? |
| **EGRESS** | What can this identity actually do? |
| **MUTATION** | Can this identity escalate, persist, or pivot? |

---

## 1. Principals – Who Can Act

### Principal Types

| Type | Example | Risk Notes |
|:-----|:--------|:-----------|
| IAM User | `arn:aws:iam::123:user/alice` | Long-term credentials |
| IAM Role | `arn:aws:iam::123:role/AppRole` | Preferred execution identity |
| Root | `arn:aws:iam::123:root` | Full account trust |
| Assumed Role | `arn:aws:sts::123:assumed-role/Role/session` | Runtime principal |
| Federated User | `arn:aws:sts::123:federated-user/name` | Legacy federation |
| SAML / OIDC | External IdP | Attribute-based trust |
| AWS Service | `ec2.amazonaws.com` | Confused-deputy risk |
| Wildcard | `*` | Internet-reachable |

### Key Notes

- `:root` in trust policies means **any principal in that account**
- `"*"` and `{ "AWS": "*" }` are equivalent
- `federated-user/*` is **not** SAML/OIDC – it uses `GetFederationToken`

---

## 2. Assume Paths – How Identity Changes

| Path | STS Action | Risk |
|:-----|:-----------|:-----|
| AWS → Role | `sts:AssumeRole` | Cross-account abuse |
| SAML → Role | `sts:AssumeRoleWithSAML` | Over-broad IdP trust |
| OIDC → Role | `sts:AssumeRoleWithWebIdentity` | Token misuse |
| Federation Token | `sts:GetFederationToken` | Persistence |

> `GetFederationToken` is not role assumption, but still creates an identity transformation.

---

## 3. Trust Policies – Ingress Control Surface

For each trust policy statement, iamwho evaluates:

1. Principal breadth  
2. Assume path  
3. Condition presence  
4. Condition effectiveness  

### Principal Breadth Scale

| Scope | Example | Risk |
|:------|:--------|:-----|
| Specific ARN | `role/AppRole` | Low |
| Account root | `123456789012:root` | Medium |
| Org-wide | `PrincipalOrgID` | High |
| Wildcard | `*` | **Critical** |

---

## 4. Conditions That Matter

### Service Principals (Confused Deputy)

Expected conditions:
- `aws:SourceAccount`
- `aws:SourceArn`

**Commonly supported services**
- Lambda, EC2, ECS, EKS
- S3, CloudTrail, Config
- SNS, SQS, EventBridge

iamwho treats missing source conditions as **MEDIUM** by default.

### Cross-Account Trust

| Scenario | Expected Condition |
|:---------|:-------------------|
| Vendor access | `sts:ExternalId` |
| Internal org | `aws:PrincipalOrgID` |
| Specific roles | `aws:PrincipalArn` |

### OIDC / Web Identity

Missing subject scoping is **CRITICAL**.

| Provider | Required Conditions |
|:---------|:-------------------|
| GitHub Actions | `aud` + constrained `sub` |
| EKS | Cluster-scoped `sub` |
| Cognito | `sub`, `aud` |

---

## 5. Permissions – Egress Surface

iamwho approximates effective permissions using:

1. Identity policies  
2. Permission boundaries  
3. SCPs (if visible)  
4. Session policies (restrictive only)  

| Context | Rule |
|:--------|:-----|
| Same-account | Identity **OR** resource policy |
| Cross-account | Identity **AND** resource policy |

Results include **confidence levels** rather than claiming full IAM simulation.

---

## 6. Dangerous Capabilities – Mutation Primitives

### Tier 1 – Direct Escalation

```
iam:AttachUserPolicy
iam:AttachRolePolicy
iam:PutUserPolicy
iam:PutRolePolicy
iam:UpdateAssumeRolePolicy
iam:CreateAccessKey
iam:CreatePolicyVersion
iam:SetDefaultPolicyVersion
```

### Tier 2 – Indirect Escalation

```
iam:PassRole + lambda:CreateFunction
iam:PassRole + ec2:RunInstances
iam:PassRole + cloudformation:CreateStack
```

### Tier 3 – Persistence

```
iam:CreateUser
iam:CreateRole
sts:GetFederationToken
```

---

## 7. Guardrails – SCPs & Permission Boundaries

- SCPs and permission boundaries **restrict**, never grant
- Management account is exempt from SCPs
- Service-linked roles ignore SCPs

Compromise of the management account effectively bypasses all organizational guardrails.

---

## 8. Confidence Levels

| Level | Meaning |
|:------|:--------|
| **STATIC** | Directly visible in policy |
| **INFERRED** | Derived from intersections |
| **PARTIAL** | Missing external data |

---

## 9. What iamwho Does Not Do

- Full IAM simulation
- CloudTrail analysis
- Runtime or network inspection

**iamwho** is static IAM graph analysis focused on reachability.
