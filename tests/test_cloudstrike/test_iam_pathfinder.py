"""Tests for IamPathfinder — IAM privilege escalation path analysis."""

from __future__ import annotations

import pytest

from krumpa.core import ScanContext, Severity, Target
from krumpa.cloudstrike.iam_pathfinder import IamPathfinder


class _MockIam:
    """Minimal IAM client mock."""

    def __init__(self, user_perms: dict | None = None, role_perms: dict | None = None):
        self._user_perms = user_perms or {}
        self._role_perms = role_perms or {}

    def list_user_policies(self, UserName: str):
        return {"PolicyNames": list(self._user_perms.get(UserName, {}).keys())}

    def get_user_policy(self, UserName: str, PolicyName: str):
        doc = self._user_perms.get(UserName, {}).get(PolicyName, {})
        return {"PolicyDocument": doc}

    def list_attached_user_policies(self, UserName: str):
        return {"AttachedPolicies": []}

    def list_role_policies(self, RoleName: str):
        return {"PolicyNames": list(self._role_perms.get(RoleName, {}).keys())}

    def get_role_policy(self, RoleName: str, PolicyName: str):
        doc = self._role_perms.get(RoleName, {}).get(PolicyName, {})
        return {"PolicyDocument": doc}

    def list_attached_role_policies(self, RoleName: str):
        return {"AttachedPolicies": []}


class _MockSession:
    def __init__(self, iam: _MockIam):
        self._iam = iam

    def client(self, service: str, **kw):
        if service == "iam":
            return self._iam
        raise ValueError(f"Unexpected service: {service}")


def _policy_doc(*actions: str) -> dict:
    return {"Statement": [{"Effect": "Allow", "Action": list(actions), "Resource": "*"}]}


@pytest.mark.asyncio
class TestIamPathfinder:

    async def test_detects_wildcard_admin(self):
        iam = _MockIam(
            role_perms={"admin-role": {"AdminPolicy": _policy_doc("*")}}
        )
        session = _MockSession(iam)
        target = Target(url="aws://us-east-1")
        ctx = ScanContext()
        ctx.metadata["aws_inventory"] = {"iam_users": [], "iam_roles": ["admin-role"]}

        pathfinder = IamPathfinder(session=session)
        findings = await pathfinder.analyze(target, ctx)

        assert len(findings) >= 1
        assert any("wildcard" in f.title.lower() or f.severity == Severity.CRITICAL for f in findings)

    async def test_detects_passrole_plus_lambda(self):
        iam = _MockIam(
            role_perms={"deployer": {"DeployPolicy": _policy_doc("iam:PassRole", "lambda:CreateFunction")}}
        )
        session = _MockSession(iam)
        target = Target(url="aws://us-east-1")
        ctx = ScanContext()
        ctx.metadata["aws_inventory"] = {"iam_users": [], "iam_roles": ["deployer"]}

        pathfinder = IamPathfinder(session=session)
        findings = await pathfinder.analyze(target, ctx)

        assert any("PassRole" in f.evidence for f in findings)
        assert all(f.severity == Severity.CRITICAL for f in findings)

    async def test_no_findings_for_safe_role(self):
        iam = _MockIam(
            role_perms={"readonly": {"ReadPolicy": _policy_doc("s3:GetObject", "s3:ListBucket")}}
        )
        session = _MockSession(iam)
        target = Target(url="aws://us-east-1")
        ctx = ScanContext()
        ctx.metadata["aws_inventory"] = {"iam_users": [], "iam_roles": ["readonly"]}

        pathfinder = IamPathfinder(session=session)
        findings = await pathfinder.analyze(target, ctx)
        assert findings == []

    async def test_detects_direct_privesc_attach_user_policy(self):
        iam = _MockIam(
            user_perms={"dev": {"DevPolicy": _policy_doc("iam:AttachUserPolicy")}}
        )
        session = _MockSession(iam)
        target = Target(url="aws://us-east-1")
        ctx = ScanContext()
        ctx.metadata["aws_inventory"] = {"iam_users": ["dev"], "iam_roles": []}

        pathfinder = IamPathfinder(session=session)
        findings = await pathfinder.analyze(target, ctx)

        assert len(findings) >= 1
        assert any("iam:AttachUserPolicy" in f.evidence for f in findings)

    async def test_empty_inventory_returns_no_findings(self):
        iam = _MockIam()
        session = _MockSession(iam)
        target = Target(url="aws://us-east-1")
        ctx = ScanContext()
        ctx.metadata["aws_inventory"] = {"iam_users": [], "iam_roles": []}

        pathfinder = IamPathfinder(session=session)
        findings = await pathfinder.analyze(target, ctx)
        assert findings == []
