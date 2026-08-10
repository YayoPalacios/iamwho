"""Shared test fixtures.

Tests never touch AWS. A :class:`FakeIamClient` is installed through
``checks._client.set_client``, which is the single seam every check reads
through.
"""

from typing import Any

import pytest
from botocore.exceptions import ClientError

from iamwho.checks import _client

ACCOUNT = "123456789012"


def role_arn(name: str) -> str:
    return f"arn:aws:iam::{ACCOUNT}:role/{name}"


def policy_arn(name: str) -> str:
    return f"arn:aws:iam::{ACCOUNT}:policy/{name}"


def allow(actions: Any, resources: Any = "*", **extra: Any) -> dict[str, Any]:
    """Build an Allow statement."""
    return {"Effect": "Allow", "Action": actions, "Resource": resources, **extra}


class _FakePaginator:
    def __init__(self, client: "FakeIamClient", operation: str) -> None:
        self._client = client
        self._operation = operation

    def paginate(self, **kwargs: Any):
        return self._client._paginate(self._operation, **kwargs)


class FakeIamClient:
    """Minimal stand-in for boto3's IAM client.

    Records every operation in ``calls`` so tests can assert on how many reads a
    run performs, and splits list results into pages of ``page_size`` so
    pagination is genuinely exercised.
    """

    def __init__(self, page_size: int = 100) -> None:
        self.page_size = page_size
        self.calls: list[str] = []
        self.trust_policies: dict[str, dict[str, Any]] = {}
        self.inline_policies: dict[str, dict[str, dict[str, Any]]] = {}
        self.attached_policies: dict[str, list[str]] = {}
        self.managed_policies: dict[str, dict[str, Any]] = {}
        self.errors: dict[str, str] = {}
        self.exceptions: dict[str, Exception] = {}

    # -- fixture construction ------------------------------------------------

    def add_role(
        self,
        name: str,
        trust_policy: dict[str, Any] | None = None,
        inline: dict[str, dict[str, Any]] | None = None,
        attached: list[str] | None = None,
    ) -> str:
        self.trust_policies[name] = trust_policy or {
            "Version": "2012-10-17",
            "Statement": [],
        }
        self.inline_policies[name] = inline or {}
        self.attached_policies[name] = attached or []
        return role_arn(name)

    def add_managed_policy(self, name: str, document: dict[str, Any]) -> str:
        arn = policy_arn(name)
        self.managed_policies[arn] = document
        return arn

    def fail(self, operation: str, code: str) -> None:
        """Make ``operation`` raise a ClientError with ``code``."""
        self.errors[operation] = code

    def raise_exception(self, operation: str, exc: Exception) -> None:
        """Make ``operation`` raise an arbitrary, non-ClientError exception.

        For simulating failures the checks don't translate to IamFetchError,
        e.g. botocore.exceptions.NoCredentialsError.
        """
        self.exceptions[operation] = exc

    def count(self, operation: str) -> int:
        return self.calls.count(operation)

    # -- boto3 surface -------------------------------------------------------

    def _record(self, operation: str) -> None:
        self.calls.append(operation)
        exc = self.exceptions.get(operation)
        if exc:
            raise exc
        code = self.errors.get(operation)
        if code:
            raise ClientError(
                {"Error": {"Code": code, "Message": f"simulated {code}"}}, operation
            )

    def _pages(self, items: list[Any], key: str) -> list[dict[str, Any]]:
        if not items:
            return [{key: []}]
        return [
            {key: items[i : i + self.page_size]}
            for i in range(0, len(items), self.page_size)
        ]

    def _paginate(self, operation: str, **kwargs: Any):
        self._record(operation)
        role_name = kwargs["RoleName"]
        if operation == "list_role_policies":
            names = sorted(self.inline_policies.get(role_name, {}))
            return iter(self._pages(names, "PolicyNames"))
        if operation == "list_attached_role_policies":
            attached = [
                {"PolicyName": arn.split("/")[-1], "PolicyArn": arn}
                for arn in self.attached_policies.get(role_name, [])
            ]
            return iter(self._pages(attached, "AttachedPolicies"))
        raise AssertionError(f"unexpected paginated operation: {operation}")

    def get_paginator(self, operation: str) -> _FakePaginator:
        return _FakePaginator(self, operation)

    def get_role(self, RoleName: str) -> dict[str, Any]:
        self._record("get_role")
        if RoleName not in self.trust_policies:
            raise ClientError(
                {"Error": {"Code": "NoSuchEntity", "Message": "no such role"}},
                "get_role",
            )
        return {
            "Role": {"AssumeRolePolicyDocument": self.trust_policies[RoleName]},
        }

    def get_role_policy(self, RoleName: str, PolicyName: str) -> dict[str, Any]:
        self._record("get_role_policy")
        return {"PolicyDocument": self.inline_policies[RoleName][PolicyName]}

    def get_policy(self, PolicyArn: str) -> dict[str, Any]:
        self._record("get_policy")
        return {"Policy": {"DefaultVersionId": "v1"}}

    def get_policy_version(self, PolicyArn: str, VersionId: str) -> dict[str, Any]:
        self._record("get_policy_version")
        return {"PolicyVersion": {"Document": self.managed_policies[PolicyArn]}}


@pytest.fixture
def iam() -> Any:
    """Install a FakeIamClient for the duration of a test."""
    client = FakeIamClient()
    _client.set_client(client)
    yield client
    _client.set_client(None)
