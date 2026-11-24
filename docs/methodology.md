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

For **GitHub Actions** (the public issuer
`token.actions.githubusercontent.com`), iamwho evaluates the `sub` condition's
operator and values. The severity depends on **who can satisfy the pattern**:

| Severity | Who can assume | Examples |
|:---------|:---------------|:---------|
| **CRITICAL** | Anyone on GitHub | no `sub`; `repo:*`; a wildcard in the org part (`repo:my-org*/*`, `repo:my-or?/*`) |
| **HIGH** | Anyone in the org | a wildcard in the repository name, with the org pinned (`repo:my-org/*`, `repo:my-org/app*`, `repo:my-org/ap?:*`) |
| **MEDIUM** | One repository, any ref or any other context | `repo:my-org/app:*`, `repo:my-org/app:ref:refs/heads/*`, `repo:my-org/app:pull_request`, `StringEquals repo:my-org/app` |
| **LOW** | One repository, a literal `ref:` or `environment:` | `repo:my-org/app:ref:refs/heads/main`, `repo:my-org/app:environment:prod` |

A wildcard in the org part is CRITICAL because anyone can register an
organization that matches. A pinned ref does not lower a CRITICAL or HIGH
pattern: `repo:my-org/*:ref:refs/heads/main` is still HIGH.

Rules:

- `*` and `?` are both wildcards. Only the text before the first wildcard
  counts as pinned.
- `StringEquals` values are literal, so `StringEquals sub = "repo:*"` is not a
  wildcard. `StringLike` values are case-sensitive glob patterns, and values
  are never lowercased. `StringEqualsIgnoreCase` is the exception: it compares
  case-insensitively, so `Repo:My-Org/App` is rated as `repo:my-org/app`.
- Condition key names match case-insensitively.
- A multi-value list takes the severity of its broadest value. A value iamwho
  can't rate (not a string, or outside the `repo:` format) is never assumed
  narrow. The list keeps a HIGH or CRITICAL value's severity, and is otherwise
  reported as not evaluated, never LOW.
- iamwho assumes the worst about the subject template. A repo-only custom
  claim template produces subjects with no context suffix, so a value without
  one is rated by its repository part: bare `repo:my-org/ap?` is HIGH, and
  `StringEquals sub = "repo:my-org/app"` is MEDIUM.
- Only a literal `ref:<name>` or `environment:<name>` context is LOW. Any
  other or unknown context is MEDIUM: `pull_request` admits every
  pull-request workflow run in the repository.
- `aud` never counts as scoping. Every GitHub token minted for AWS carries
  `aud = sts.amazonaws.com`, so an `aud`-only trust is CRITICAL. `aud` only
  produces INFO notes (see below).
- A `sub` condition that only uses negated operators (`StringNotEquals`,
  `StringNotLike`) is CRITICAL, because it admits every subject it doesn't
  name. `Null: false` is CRITICAL too, because it only asserts that the claim
  exists.
- Condition blocks are ANDed, so when several blocks constrain `sub`, the
  narrowest positive (`StringEquals`, `StringLike`) block decides. Negated and
  `Null: false` blocks never narrow it, and neither does a block iamwho can't
  evaluate: `StringLike sub = "repo:*"` beside an `ArnLike` or `Null: true`
  block on `sub` is still CRITICAL. Only when no positive block was evaluated
  and another `sub` block can't be evaluated (including beside a negation) does
  the trust report MEDIUM, not evaluated.

#### Not evaluated

A `sub` condition iamwho can't evaluate is reported **MEDIUM** with
`subject_evaluated: false` and `subject_verdict: "NOT_EVALUATED"`. It is
neither a false CRITICAL nor a reassuring LOW. The cases are:

- `Null: true`. The claim must be absent, so no GitHub token matches.
- a `sub` with no string values (an empty list, a number, an object). No
  token can match it.
- a `sub` under any other operator
- a value outside the `repo:` subject format, such as a custom claim template
  (`StringLike sub = "repository_owner:*"`), unless a wildcard falls before
  `repo:` is complete (`*`, `rep*`), which is CRITICAL

The raw `sub` blocks iamwho couldn't evaluate are attached to the finding as
`unevaluated_sub_condition`. This also happens when an evaluated block still
sets the verdict, for example the non-string entry in
`["repo:my-org/*", {"x": 1}]` (HIGH).

**Exit codes.** MEDIUM not-evaluated findings pass the default gate, which
fails only on CRITICAL and HIGH. Use `--fail-on medium` to fail on them too.

#### What is listed but never credited

- **Other condition keys.** An evaluated `sub` verdict keeps its severity when
  the statement has other condition keys (for example
  `token.actions.githubusercontent.com:repository_owner` or `aws:SourceIp`).
  Every key other than the GitHub `sub` and `aud` is listed under
  `unevaluated_condition_keys`, and is not assumed to narrow access. So is
  `aud` under any operator other than `StringEquals`,
  `StringEqualsIgnoreCase` or `StringLike` (for example `StringNotEquals` or
  `Null`).
- **`Deny` statements.** Trust-policy `Deny` statements are listed raw under
  the ingress result's `deny_statements` and never lower a finding.
- **Several statements.** Each web-identity statement is rated on its own,
  and the worst one sets the role's severity (`highest_risk`). For example, a
  pinned statement next to a `repo:my-org/*` statement is HIGH.

#### `aud` notes

`audience_notes` holds INFO notes on the GitHub `aud` condition. They never
change the `sub` verdict or the exit code:

| `code` | When |
|:-------|:-----|
| `aud_missing` | No `aud` condition. Adding `sts.amazonaws.com` is defense in depth. |
| `aud_unexpected` | An `aud` value other than `sts.amazonaws.com`. It may be a custom audience, or a role nobody can assume. |

Each note is `{"code", "severity": "INFO", "message"}`. Values are compared
with their operator's semantics: `StringLike aud = "sts.*"` matches
`sts.amazonaws.com`, and `StringEqualsIgnoreCase` ignores case. An `aud` under
any other operator produces no note and is listed under
`unevaluated_condition_keys` instead.

#### JSON fields

The JSON finding for a GitHub trust carries `provider: "github"`,
`subject_verdict` (the severity, or `NOT_EVALUATED`), `subject_evaluated`,
`unevaluated_sub_condition`, `unevaluated_condition_keys` and
`audience_notes`. The ingress result's `deny_statements` is filled for every
role.

`provider` is set for `oidc-provider/`, Cognito and `saml-provider/`
principals, and its values are stable:

| `provider` | Principal |
|:-----------|:----------|
| `github` | `oidc-provider/token.actions.githubusercontent.com` |
| `github_enterprise` | `oidc-provider/token.actions.githubusercontent.com/<enterprise>` |
| `eks` | `oidc-provider/oidc.eks.*` |
| `cognito` | `cognito-identity.amazonaws.com` |
| `generic_oidc` | Any other `oidc-provider/` |
| `saml` | `saml-provider/` |

For the other web-identity providers, `subject_verdict` is the severity with
`subject_evaluated: true` when the identifying key is absent, and
`NOT_EVALUATED` with `subject_evaluated: false` when it is present. SAML
findings have `subject_verdict: null` and `subject_evaluated: false`.
`unevaluated_sub_condition` and `unevaluated_condition_keys` are GitHub-only,
and `audience_notes` is set for GitHub and SAML. All of these fields are `null`
for other principals, including the public identity providers
`accounts.google.com`, `graph.facebook.com` and `www.amazon.com`, which iamwho
does not yet classify.

With `-v`, a GitHub trust's conditions are shown as plainly present only when
its subject verdict is LOW. Otherwise the line says that the conditions don't
scope `sub` (CRITICAL), what the `sub` pattern still admits (any repository in
the org for HIGH, more than a pinned ref or environment for MEDIUM), or that
it was not evaluated.

#### Other web-identity providers and SAML

iamwho evaluates `sub` values for the public GitHub issuer only. For every
other web-identity provider it checks that the provider's **identifying key**
is present, which is not value evaluation (ADR-0001). It never gives these
trusts a reassuring severity:

| Severity | When |
|:---------|:-----|
| **CRITICAL** | Cognito without `cognito-identity.amazonaws.com:aud`. Any identity pool, in any AWS account, can mint a token |
| **HIGH** | EKS or generic OIDC without `<issuer>:sub`. Any token from that IdP can assume |
| **MEDIUM**, not evaluated | The identifying key is present. Its values are not evaluated |
| **LOW** | SAML. No assertion attributes are evaluated |

Rules:

- The identifying key must belong to the trusted issuer: `<issuer>:sub`, where
  `<issuer>` is the path after `oidc-provider/` in the principal ARN. Key names
  match case-insensitively. A `sub` key for a different issuer in the same
  statement does not count.
- A key that only appears under negated operators (`StringNotEquals`,
  `StringNotLike`, and their qualified forms) or `Null: false` counts as
  **absent**, the same as for GitHub: it admits every token carrying the claim.
  So EKS or generic OIDC is HIGH, and Cognito is CRITICAL.
- `Null: true`, an unrecognised operator, or a negation beside a positive
  condition on the key: the key is present, so the trust is MEDIUM, not
  evaluated.
- **GitHub Enterprise custom issuers**
  (`token.actions.githubusercontent.com/<enterprise>`) are deliberately treated
  as a generic provider. An enterprise can use its own subject claim template,
  so the public-GitHub `repo:` rules are not applied: `sub` presence is checked,
  and a present `sub` is MEDIUM, not evaluated, however pinned or broad it looks.
- Cognito identity pools (`cognito-identity.amazonaws.com`) are classified as
  federated OIDC, not as an AWS service, so the confused-deputy rule does not
  apply to them. `amr` is not evaluated.
- SAML findings carry `subject_evaluated: false` and `subject_verdict: null`,
  not `NOT_EVALUATED`, which always means MEDIUM. Their `audience_notes` hold
  one INFO note, `saml_aud_missing`, when the statement has no `saml:aud`
  condition, and are empty (`[]`) when it does. The note never changes the risk.

| Provider | Identifying condition | Evaluated |
|:---------|:----------------------|:----------|
| GitHub Actions | Constrained `sub` (`aud` recommended, but never counts as scoping) | `sub` operator and values |
| GitHub Enterprise custom issuer | `sub` | Presence only |
| EKS | Cluster-scoped `sub` (`system:serviceaccount:<namespace>:<name>`) | Presence only |
| Generic OIDC | `sub` | Presence only |
| Cognito | `aud` (the identity pool ID), plus `amr` (usually `ForAnyValue:StringLike` `authenticated`) to separate authenticated from unauthenticated identities | `aud` presence only; `amr` not evaluated |
| SAML | `saml:aud` recommended | Presence of `saml:aud`, as an INFO note |

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
