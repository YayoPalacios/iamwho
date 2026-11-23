# iamwho

Static, single-principal AWS IAM analysis of post-compromise blast radius: if this identity is compromised, what else becomes reachable.

## Language

### Web identity

**Web-identity chain**:
A path that starts at an external OIDC subject, enters a role via web-identity federation, and continues through role-to-role hops to further roles.
_Avoid_: OIDC trust chaining, role chaining

**Web-identity entry**:
A role whose trust policy admits an external OIDC subject; the first hop of a web-identity chain.
_Avoid_: entry point, OIDC role

**Overbroad web-identity trust**:
A role trust that admits more OIDC subjects than intended, such as a subject pattern matching every repository in an organization or on the platform.
_Avoid_: weak OIDC trust, OIDC misconfiguration
