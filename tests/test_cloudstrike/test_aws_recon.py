"""Tests for AwsRecon — AWS asset enumeration."""

from __future__ import annotations

import pytest

from krumpa.core import ScanContext, Severity, Target
from krumpa.cloudstrike.aws_recon import AwsRecon


class _MockEc2:
    def describe_instances(self, **kw):
        return {
            "Reservations": [{
                "Instances": [{
                    "InstanceId": "i-abc123",
                    "InstanceType": "t3.medium",
                    "State": {"Name": "running"},
                    "PublicIpAddress": "1.2.3.4",
                    "IamInstanceProfile": {"Arn": "arn:aws:iam::123:instance-profile/MyProfile"},
                    "MetadataOptions": {"HttpTokens": "optional"},  # IMDSv1 enabled
                }]
            }]
        }


class _MockS3:
    def list_buckets(self, **kw):
        return {"Buckets": [{"Name": "my-bucket"}, {"Name": "backup-bucket"}]}


class _MockIam:
    def list_users(self, **kw): return {"Users": [{"UserName": "alice"}, {"UserName": "bob"}]}
    def list_roles(self, **kw): return {"Roles": [{"RoleName": "app-role"}]}


class _MockLambda:
    def get_paginator(self, op):
        class _Pager:
            def paginate(self):
                return iter([{"Functions": [
                    {"FunctionName": "my-fn", "Runtime": "python3.11",
                     "Role": "arn:aws:iam::123:role/LambdaRole",
                     "Environment": {"Variables": {"DATABASE_URL": "postgres://..."}}},
                ]}])
        return _Pager()


class _MockEcr:
    def describe_repositories(self, **kw): return {"repositories": [{"repositoryName": "my-repo"}]}


class _MockEks:
    def list_clusters(self, **kw): return {"clusters": []}


class _MockSageMaker:
    def list_endpoints(self, **kw): return {"Endpoints": []}
    def list_notebook_instances(self, **kw): return {"NotebookInstances": []}


class _MockBedrock:
    def list_foundation_models(self, **kw):
        return {"modelSummaries": [{"modelId": "anthropic.claude-v2"}]}


class _MockSession:
    def client(self, service: str, **kw):
        return {
            "ec2": _MockEc2(),
            "s3": _MockS3(),
            "iam": _MockIam(),
            "lambda": _MockLambda(),
            "ecr": _MockEcr(),
            "eks": _MockEks(),
            "sagemaker": _MockSageMaker(),
            "bedrock": _MockBedrock(),
        }[service]


@pytest.mark.asyncio
class TestAwsRecon:

    async def test_enumerates_s3_buckets(self):
        ctx = ScanContext()
        target = Target(url="aws://us-east-1")

        recon = AwsRecon(session=_MockSession())
        findings = await recon.analyze(target, ctx)

        assert "s3_buckets" in ctx.metadata.get("aws_inventory", {})
        assert ctx.metadata["aws_inventory"]["s3_buckets"] == ["my-bucket", "backup-bucket"]
        assert any("s3 buckets" in f.title.lower() for f in findings)

    async def test_enumerates_iam(self):
        ctx = ScanContext()
        target = Target(url="aws://us-east-1")

        recon = AwsRecon(session=_MockSession())
        await recon.analyze(target, ctx)

        inv = ctx.metadata["aws_inventory"]
        assert "alice" in inv["iam_users"]
        assert "app-role" in inv["iam_roles"]

    async def test_flags_imdsv1_instances(self):
        ctx = ScanContext()
        target = Target(url="aws://us-east-1")

        recon = AwsRecon(session=_MockSession())
        findings = await recon.analyze(target, ctx)

        imds_findings = [f for f in findings if "imds" in " ".join(f.tags)]
        assert len(imds_findings) >= 1
        assert imds_findings[0].severity == Severity.HIGH

    async def test_flags_lambda_sensitive_env(self):
        ctx = ScanContext()
        target = Target(url="aws://us-east-1")

        recon = AwsRecon(session=_MockSession())
        findings = await recon.analyze(target, ctx)

        lambda_findings = [f for f in findings if "lambda" in " ".join(f.tags) and "credential" in " ".join(f.tags)]
        assert len(lambda_findings) >= 1
        assert lambda_findings[0].severity == Severity.HIGH

    async def test_inventory_stored_in_context(self):
        ctx = ScanContext()
        target = Target(url="aws://us-east-1")

        recon = AwsRecon(session=_MockSession())
        await recon.analyze(target, ctx)

        inv = ctx.metadata.get("aws_inventory", {})
        assert "s3_buckets" in inv
        assert "iam_users" in inv
        assert "iam_roles" in inv
        assert "lambda_functions" in inv
        assert "bedrock_models" in inv
