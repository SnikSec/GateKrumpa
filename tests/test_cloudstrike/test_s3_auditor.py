"""Tests for S3Auditor — S3 bucket security analysis."""

from __future__ import annotations

import json
import pytest

from krumpa.core import ScanContext, Severity, Target
from krumpa.cloudstrike.s3_auditor import S3Auditor


class _S3Exceptions:
    """Minimal exceptions namespace."""
    class NoSuchPublicAccessBlockConfiguration(Exception):
        pass
    class NoSuchBucketPolicy(Exception):
        pass
    class NoSuchCORSConfiguration(Exception):
        pass
    class ServerSideEncryptionConfigurationNotFoundError(Exception):
        pass
    class ReplicationConfigurationNotFoundError(Exception):
        pass


class _MockS3:
    """Configurable S3 mock for unit tests."""

    exceptions = _S3Exceptions

    def __init__(
        self,
        public_access_block: dict | None = None,
        acl_grants: list | None = None,
        policy: str | None = None,
        cors_rules: list | None = None,
        encrypted: bool = True,
        versioning_status: str = "Enabled",
        replication_rules: list | None = None,
    ):
        self._pab = public_access_block
        self._acl = acl_grants or []
        self._policy = policy
        self._cors = cors_rules
        self._encrypted = encrypted
        self._versioning = versioning_status
        self._replication = replication_rules

    def get_public_access_block(self, Bucket: str):
        if self._pab is None:
            raise _S3Exceptions.NoSuchPublicAccessBlockConfiguration()
        return {"PublicAccessBlockConfiguration": self._pab}

    def get_bucket_acl(self, Bucket: str):
        return {"Grants": [{"Grantee": g, "Permission": "READ"} for g in self._acl]}

    def get_bucket_policy(self, Bucket: str):
        if self._policy is None:
            raise _S3Exceptions.NoSuchBucketPolicy()
        return {"Policy": self._policy}

    def get_bucket_cors(self, Bucket: str):
        if self._cors is None:
            raise _S3Exceptions.NoSuchCORSConfiguration()
        return {"CORSRules": self._cors}

    def get_bucket_encryption(self, Bucket: str):
        if not self._encrypted:
            raise _S3Exceptions.ServerSideEncryptionConfigurationNotFoundError()
        return {"ServerSideEncryptionConfiguration": {}}

    def get_bucket_versioning(self, Bucket: str):
        return {"Status": self._versioning}

    def get_bucket_replication(self, Bucket: str):
        if self._replication is None:
            raise _S3Exceptions.ReplicationConfigurationNotFoundError()
        return {"ReplicationConfiguration": {"Rules": self._replication}}


class _MockSession:
    def __init__(self, s3: _MockS3):
        self._s3 = s3

    def client(self, service: str, **kw):
        if service == "s3":
            return self._s3
        if service == "sts":
            class _STS:
                def get_caller_identity(self): return {"Account": "123456789012"}
            return _STS()
        raise ValueError(service)


@pytest.mark.asyncio
class TestS3Auditor:

    async def test_flags_missing_public_access_block(self):
        session = _MockSession(_MockS3(public_access_block=None))
        ctx = ScanContext()
        ctx.metadata["aws_inventory"] = {"s3_buckets": ["my-bucket"]}
        target = Target(url="aws://us-east-1")

        auditor = S3Auditor(session=session)
        findings = await auditor.analyze(target, ctx)

        assert any("public access block" in f.title.lower() for f in findings)

    async def test_flags_incomplete_public_access_block(self):
        pab = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        }
        session = _MockSession(_MockS3(public_access_block=pab))
        ctx = ScanContext()
        ctx.metadata["aws_inventory"] = {"s3_buckets": ["my-bucket"]}
        target = Target(url="aws://us-east-1")

        auditor = S3Auditor(session=session)
        findings = await auditor.analyze(target, ctx)

        assert any("public access block" in f.title.lower() for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    async def test_flags_public_acl(self):
        all_users = {"URI": "http://acs.amazonaws.com/groups/global/AllUsers", "Type": "Group"}
        session = _MockSession(_MockS3(
            public_access_block={"BlockPublicAcls": False, "IgnorePublicAcls": False,
                                  "BlockPublicPolicy": False, "RestrictPublicBuckets": False},
            acl_grants=[all_users],
        ))
        ctx = ScanContext()
        ctx.metadata["aws_inventory"] = {"s3_buckets": ["public-bucket"]}
        target = Target(url="aws://us-east-1")

        auditor = S3Auditor(session=session)
        findings = await auditor.analyze(target, ctx)

        assert any("acl" in f.title.lower() or "public" in f.title.lower() for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    async def test_flags_public_bucket_policy(self):
        policy = json.dumps({
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}]
        })
        session = _MockSession(_MockS3(
            public_access_block={"BlockPublicAcls": True, "IgnorePublicAcls": True,
                                  "BlockPublicPolicy": False, "RestrictPublicBuckets": False},
            policy=policy,
        ))
        ctx = ScanContext()
        ctx.metadata["aws_inventory"] = {"s3_buckets": ["data-bucket"]}
        target = Target(url="aws://us-east-1")

        auditor = S3Auditor(session=session)
        findings = await auditor.analyze(target, ctx)

        assert any("policy" in f.title.lower() for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    async def test_flags_cors_wildcard(self):
        session = _MockSession(_MockS3(
            public_access_block={"BlockPublicAcls": True, "IgnorePublicAcls": True,
                                  "BlockPublicPolicy": True, "RestrictPublicBuckets": True},
            cors_rules=[{"AllowedOrigins": ["*"], "AllowedMethods": ["GET"]}],
        ))
        ctx = ScanContext()
        ctx.metadata["aws_inventory"] = {"s3_buckets": ["assets-bucket"]}
        target = Target(url="aws://us-east-1")

        auditor = S3Auditor(session=session)
        findings = await auditor.analyze(target, ctx)

        assert any("cors" in f.title.lower() for f in findings)

    async def test_flags_unencrypted_bucket(self):
        session = _MockSession(_MockS3(
            public_access_block={"BlockPublicAcls": True, "IgnorePublicAcls": True,
                                  "BlockPublicPolicy": True, "RestrictPublicBuckets": True},
            encrypted=False,
        ))
        ctx = ScanContext()
        ctx.metadata["aws_inventory"] = {"s3_buckets": ["logs-bucket"]}
        target = Target(url="aws://us-east-1")

        auditor = S3Auditor(session=session)
        findings = await auditor.analyze(target, ctx)

        assert any("encrypt" in f.title.lower() for f in findings)

    async def test_no_findings_for_secure_bucket(self):
        pab = {"BlockPublicAcls": True, "IgnorePublicAcls": True,
               "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
        session = _MockSession(_MockS3(public_access_block=pab, encrypted=True, versioning_status="Enabled"))
        ctx = ScanContext()
        ctx.metadata["aws_inventory"] = {"s3_buckets": ["secure-bucket"]}
        target = Target(url="aws://us-east-1")

        auditor = S3Auditor(session=session)
        findings = await auditor.analyze(target, ctx)

        # Should have no CRITICAL or HIGH findings
        assert not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)

    async def test_flags_sensitive_bucket_name(self):
        pab = {"BlockPublicAcls": True, "IgnorePublicAcls": True,
               "BlockPublicPolicy": True, "RestrictPublicBuckets": True}
        session = _MockSession(_MockS3(public_access_block=pab))
        ctx = ScanContext()
        ctx.metadata["aws_inventory"] = {"s3_buckets": ["prod-model-training-data"]}
        target = Target(url="aws://us-east-1")

        auditor = S3Auditor(session=session)
        findings = await auditor.analyze(target, ctx)

        assert any("sensitive name" in f.title.lower() for f in findings)
        assert any(f.severity == Severity.INFO for f in findings)

    async def test_empty_bucket_list_returns_no_findings(self):
        session = _MockSession(_MockS3())
        ctx = ScanContext()
        ctx.metadata["aws_inventory"] = {"s3_buckets": []}
        target = Target(url="aws://us-east-1")

        auditor = S3Auditor(session=session)
        findings = await auditor.analyze(target, ctx)
        assert findings == []
