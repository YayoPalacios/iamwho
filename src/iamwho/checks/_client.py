# src/iamwho/checks/_client.py
"""Shared IAM client and cached, paginated reads.

All AWS access made by the checks goes through this module. It exists so that:

- one boto3 client (and one credential resolution) is shared by every check,
  configured with adaptive retries so throttling is handled by botocore rather
  than surfacing as a bare ``ClientError``;
- list operations are paginated, so roles with more policies than fit in a
  single page are not silently truncated;
- repeated reads of the same role are served from an LRU cache, which is what
  keeps a bounded chain walk from re-fetching the same role at every hop;
- tests have a single seam: call :func:`set_client` with a fake and every check
  reads from it, with no need to monkeypatch private fetch functions.

Failures are raised as :class:`IamFetchError`, whose ``message`` is the
user-facing string the checks render. Exceptions are deliberately not cached by
``lru_cache``, so a transient failure is retried on the next call.
"""

import copy
from functools import lru_cache
from typing import Any, NoReturn

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

# Bounded so that a chain walk which fans out cannot grow memory without limit.
_CACHE_SIZE = 256

# Adaptive mode adds client-side rate limiting on top of retries, which matters
# once a single run reads many roles instead of one.
_RETRY_CONFIG = Config(retries={"max_attempts": 10, "mode": "adaptive"})

# IAM returns the first; some sibling APIs return the second.
_ACCESS_DENIED_CODES = frozenset({"AccessDenied", "AccessDeniedException"})

_client: Any = None


class IamFetchError(Exception):
    """A read against the IAM API failed.

    ``message`` is the user-facing string; ``code`` is the AWS error code when
    one was available.
    """

    def __init__(self, message: str, code: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.code = code


# =============================================================================
# CLIENT LIFECYCLE
# =============================================================================


def get_client() -> Any:
    """Return the process-wide IAM client, creating it on first use."""
    global _client
    if _client is None:
        _client = boto3.Session().client("iam", config=_RETRY_CONFIG)
    return _client


def set_client(client: Any) -> None:
    """Install a client and drop cached reads.

    Tests inject fixtures here. Passing ``None`` restores the real client on the
    next call to :func:`get_client`.
    """
    global _client
    _client = client
    clear_cache()


def clear_cache() -> None:
    """Drop every cached read."""
    _trust_policy_cached.cache_clear()
    _role_policies_cached.cache_clear()
    _managed_policy_document_cached.cache_clear()


# =============================================================================
# HELPERS
# =============================================================================


def extract_role_name(role_arn: str) -> str | None:
    """Extract the role name from a role ARN, or None if it is not one."""
    if ":role/" not in role_arn:
        return None
    try:
        role_path = role_arn.split(":role/")[1]
    except IndexError:
        return None
    return role_path.split("/")[-1] or None


def _raise_for_client_error(
    e: ClientError,
    resource_name: str,
    action: str,
    entity_kind: str = "Role",
) -> NoReturn:
    """Translate a botocore ClientError into an IamFetchError.

    ``entity_kind`` names what ``resource_name`` refers to ("Role" or
    "Policy") for the NoSuchEntity message; callers fetching a role can rely
    on the default.
    """
    code = e.response.get("Error", {}).get("Code", "Unknown")
    if code == "NoSuchEntity":
        raise IamFetchError(
            f"{entity_kind} not found: {resource_name}", code=code
        ) from e
    if code in _ACCESS_DENIED_CODES:
        raise IamFetchError(
            f"Access denied {action}: {resource_name}", code=code
        ) from e
    raise IamFetchError(f"AWS error: {code}", code=code) from e


def _require_role_name(role_arn: str) -> str:
    role_name = extract_role_name(role_arn)
    if role_name is None:
        raise IamFetchError(f"Invalid role ARN format: {role_arn}")
    return role_name


# =============================================================================
# CACHED READS
# =============================================================================


@lru_cache(maxsize=_CACHE_SIZE)
def _trust_policy_cached(role_arn: str) -> dict[str, Any]:
    role_name = _require_role_name(role_arn)
    client = get_client()
    try:
        response = client.get_role(RoleName=role_name)
    except ClientError as e:
        _raise_for_client_error(e, role_name, "fetching role")
    return response["Role"]["AssumeRolePolicyDocument"]


@lru_cache(maxsize=_CACHE_SIZE)
def _managed_policy_document_cached(policy_arn: str) -> dict[str, Any]:
    client = get_client()
    try:
        policy_info = client.get_policy(PolicyArn=policy_arn)
        version_id = policy_info["Policy"]["DefaultVersionId"]
        version = client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
    except ClientError as e:
        _raise_for_client_error(e, policy_arn, "fetching policy", entity_kind="Policy")
    return version["PolicyVersion"]["Document"]


@lru_cache(maxsize=_CACHE_SIZE)
def _role_policies_cached(role_arn: str) -> list[dict[str, Any]]:
    role_name = _require_role_name(role_arn)
    client = get_client()
    policies: list[dict[str, Any]] = []

    try:
        inline_pages = client.get_paginator("list_role_policies").paginate(
            RoleName=role_name
        )
        for page in inline_pages:
            for policy_name in page.get("PolicyNames", []):
                document = client.get_role_policy(
                    RoleName=role_name, PolicyName=policy_name
                )["PolicyDocument"]
                policies.append(
                    {
                        "name": policy_name,
                        "type": "inline",
                        "arn": None,
                        "document": document,
                    }
                )

        attached_pages = client.get_paginator("list_attached_role_policies").paginate(
            RoleName=role_name
        )
        for page in attached_pages:
            for attached in page.get("AttachedPolicies", []):
                policy_arn = attached["PolicyArn"]
                policies.append(
                    {
                        "name": attached["PolicyName"],
                        "type": "managed",
                        "arn": policy_arn,
                        # Cached separately: managed policies are commonly shared
                        # across many roles.
                        "document": _managed_policy_document_cached(policy_arn),
                    }
                )
    except ClientError as e:
        _raise_for_client_error(e, role_name, "fetching policies for")

    return policies


# =============================================================================
# PUBLIC READS
# =============================================================================


def get_trust_policy(role_arn: str) -> dict[str, Any]:
    """Return a role's trust policy document. Cached per role ARN."""
    return copy.deepcopy(_trust_policy_cached(role_arn))


def get_role_policies(role_arn: str) -> list[dict[str, Any]]:
    """Return a role's inline and attached policies. Cached per role ARN.

    Each entry has ``name``, ``type`` (``inline`` or ``managed``), ``arn`` and
    ``document``.
    """
    return copy.deepcopy(_role_policies_cached(role_arn))
