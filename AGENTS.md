# AGENTS.md

Orientation for contributors, human or AI. Read this before changing analysis logic.

## What iamwho is

A static AWS IAM analyzer focused on post-compromise blast radius. It answers
"if this identity is compromised, what else becomes reachable?" — not "is this
action allowed?". It reads IAM configuration via the AWS API and reasons about
it offline. No runtime data, no CloudTrail, no logs.

Three checks:

| Check | Question it answers |
|:---|:---|
| ingress | Who can become this role? |
| egress | What does this role enable? |
| mutation | Can access escalate or persist? |

### Explicitly out of scope

- Runtime detection or IAM activity monitoring
- Full IAM policy simulation / real-time permission testing
- Network or secrets analysis outside IAM configuration
- Compliance mapping (CIS, SOC 2, etc.)

Additional current limits, worth knowing before you file a bug: explicit `Deny`
statements and `NotPrincipal` are not evaluated; permissions boundaries, SCPs,
and session policies are not fetched; only the `aws` partition is supported.
Findings are therefore *potential* reach, not proven authorization. Don't
describe output as effective permissions.

## Where things live

```
src/iamwho/
  cli.py                       Typer app, ARN validation, rendering, exit codes
  models.py                    Dataclasses + enums (used by ingress only)
  checks/_client.py            Shared IAM client: pagination, retries, caching
  checks/ingress.py            Trust policy analysis   -> IngressResult
  checks/egress.py             Identity policy analysis -> dict
  checks/privilege_mutation.py Escalation paths (pure; consumes egress output)
```

Two data conventions coexist: ingress returns dataclasses, egress and mutation
return plain dicts. This is historical. Match the module you're editing; don't
convert one to the other as a drive-by.

Key entry points: every check module exposes `run` as an alias for its
`analyze_*` function. `analyze_privilege_mutation` accepts an already-computed
egress result and delegates to `_check_mutation(permissions)`, which is pure —
it takes a finding list, not an ARN. Keep that split; it is what makes the
checks testable.

**All AWS access goes through `checks/_client.py`.** Never call
`boto3.client("iam")` from a check. The client module owns pagination, adaptive
retries, and per-ARN caching; bypassing it reintroduces silent truncation and
duplicate reads.

## Adding a new check

1. Create `src/iamwho/checks/<name>.py` with `analyze_<name>(arn)` plus a
   `run = analyze_<name>` alias, and export it from `checks/__init__.py`.
2. Read AWS state through `_client`, and let `IamFetchError` carry the
   user-facing message.
3. Return `{"status": "success"|"error"|"not_applicable", ...}`. On error,
   populate **both** `message` and `error` — the CLI keys off specific fields,
   and a mismatch makes the check silently report zero findings. Verify an error
   path renders as an error and exits non-zero, not as "no findings".
4. Add a normalizer in `cli.py` and wire it into `analyze`, the section
   rendering, `print_summary`, and the error collection in `analyze`.
5. Emit only severities in `SEVERITY_ORDER`
   (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`/`INFO`/`PASS`) and confirm
   `calculate_exit_code` handles every one you emit.
6. Add fixtures and tests covering the success path, the empty path, and at
   least one AWS-error path.

Extending an existing check is usually a table edit, not new code: escalation
primitives live in `ESCALATION_PATHS` and `ESCALATION_COMBOS`
(`privilege_mutation.py`); action severity lives in `CRITICAL_ACTIONS` /
`HIGH_RISK_ACTIONS` / `MEDIUM_RISK_ACTIONS` (`egress.py`). If you add an action
to one, check whether the other needs it too — the checks are independently
maintained and can disagree.

## Running things

```bash
pip install -e ".[dev]"

pytest                       # test suite
ruff check .                 # lint  (must pass)
ruff format .                # format (must be clean)

iamwho analyze arn:aws:iam::123456789012:role/MyRole --check egress -v
iamwho analyze <arn> --json  # machine-readable
```

Tests must never touch AWS. Install a fake through
`iamwho.checks._client.set_client()` — the `iam` fixture in `tests/conftest.py`
does this for you and gives you a `FakeIamClient` that counts API calls and
paginates. Do not monkeypatch private fetch functions.

## Hop-depth cap

> Applies once bounded chain analysis lands; until then, all checks reason
> about a single role.

Chain analysis walks role-to-role edges (`iam:PassRole`, `sts:AssumeRole`) to a
**maximum of 2–3 hops**, set by `MAX_CHAIN_DEPTH`.

The cap is deliberate. iamwho is a single-principal analyzer meant to run in a
PR gate with read-only credentials, in seconds. Full account graphing is a
different tool with a different cost model — use PMapper for that. Unbounded
walking would also multiply API calls past throttling limits and require read
access to every role in the account, which the tool does not assume.

**The cap must be visible, never silent.** Any truncated walk sets
`truncated: true`, reports `max_depth`, and lists unexplored edges in both JSON
and verbose output. A finding that stops early must say so. Do not raise the cap
to fix a missed path — that is a signal the path needs different modeling, not
more depth.

Cycles are guarded by a visited set; a role reachable by two paths is reported
once, at its shortest depth.

## Commits and PRs

- Imperative mood, lowercase, no trailing period: `add passrole target
  resolution`, `fix fail-open on egress access denied`.
- One logical change per commit. Keep formatting churn out of behavior commits.
- Before pushing: `ruff check .`, `ruff format .`, `pytest` — all clean.
- Any change to detection logic needs a test proving the new verdict, and an
  update to `docs/methodology.md` if it changes a documented severity. Docs and
  code have drifted before; treat a severity change as a two-file change.
- Version bumps: `pyproject.toml` only — everything else derives from package
  metadata. Tag the release.
- Never commit `dist/`, `.idea/`, or `.DS_Store`.
