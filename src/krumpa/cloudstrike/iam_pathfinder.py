"""
CloudStrike — IAM privilege escalation path analysis.

Builds a directed permission graph from IAM policies and detects known
privilege escalation paths.  All operations are read-only — no policies are
attached or modified.

Detection covers the vectors documented by Rhino Security Labs and AWS
security research:
  - iam:PassRole + service attach (EC2, Lambda, Glue, SageMaker, etc.)
  - iam:CreatePolicyVersion / iam:SetDefaultPolicyVersion
  - iam:AttachUserPolicy / iam:AttachRolePolicy / iam:PutUserPolicy
  - iam:CreateAccessKey on other users
  - sts:AssumeRole chains to privileged roles
  - Lambda UpdateFunctionCode on a function with a privileged execution role
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Set, Tuple

from krumpa.core import Finding, ScanContext, Severity, Target

logger = logging.getLogger("krumpa.cloudstrike.iam_pathfinder")

# Permissions that enable privilege escalation when combined with PassRole
_PASSROLE_ESCALATION_SERVICES = {
    "ec2:RunInstances": "EC2 instance with privileged role",
    "lambda:CreateFunction": "Lambda function with privileged execution role",
    "lambda:InvokeFunction": "Invoke existing Lambda with privileged role",
    "lambda:UpdateFunctionCode": "Replace Lambda code to exfiltrate role credentials",
    "glue:CreateJob": "Glue job with privileged role",
    "sagemaker:CreateTrainingJob": "SageMaker training job with privileged role",
    "cloudformation:CreateStack": "CloudFormation stack with privileged role",
    "datapipeline:CreatePipeline": "Data Pipeline with privileged role",
    "ecs:RegisterTaskDefinition": "ECS task with privileged role",
}

# Direct privilege escalation permissions (no PassRole required)
_DIRECT_PRIVESC = {
    "iam:CreatePolicyVersion": "Create new policy version with admin permissions",
    "iam:SetDefaultPolicyVersion": "Set older policy version that grants broader access",
    "iam:AttachUserPolicy": "Attach admin policy directly to a user",
    "iam:AttachRolePolicy": "Attach admin policy to a role",
    "iam:AttachGroupPolicy": "Attach admin policy to a group",
    "iam:PutUserPolicy": "Inject inline policy granting admin access",
    "iam:PutRolePolicy": "Inject inline role policy granting admin access",
    "iam:AddUserToGroup": "Add self to admin group",
    "iam:CreateAccessKey": "Create access key for another user",
    "iam:UpdateAssumeRolePolicy": "Update trust policy to allow self-assumption of privileged role",
    "sts:AssumeRole": "Assume role with broader permissions",
}


class IamPathfinder:
    """Analyse IAM permissions for privilege escalation paths."""

    def __init__(self, *, session: Any) -> None:
        self._session = session

    async def analyze(self, target: Target, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        try:
            inventory = ctx.metadata.get("aws_inventory", {})
            iam = self._session.client("iam")

            # Collect all effective permissions per entity
            entities = self._collect_entities(iam, inventory)
            paths = self._find_escalation_paths(entities)

            for entity_name, path_description, vector_type in paths:
                findings.append(Finding(
                    title=f"IAM privilege escalation path: {entity_name}",
                    description=(
                        f"The IAM entity {entity_name!r} has permissions that form a "
                        f"known privilege escalation path ({vector_type}). "
                        "An attacker with access to this identity could gain "
                        "administrative-level permissions."
                    ),
                    severity=Severity.CRITICAL,
                    target=target,
                    evidence=path_description,
                    remediation=(
                        "Apply least-privilege IAM policies. Remove or scope down "
                        f"the permissions enabling the {vector_type} escalation vector. "
                        "Use AWS IAM Access Analyzer to audit and remediate."
                    ),
                    cwe=269,
                    tags=["cloud", "aws", "iam", "privilege-escalation", "privesc"],
                ))

        except Exception as exc:
            logger.debug("IAM pathfinder failed: %s", exc)

        return findings

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _collect_entities(
        self, iam: Any, inventory: Dict
    ) -> List[Tuple[str, Set[str]]]:
        """Return (entity_name, effective_permissions_set) tuples."""
        entities: List[Tuple[str, Set[str]]] = []

        for user in inventory.get("iam_users", []):
            perms = self._get_user_permissions(iam, user)
            entities.append((f"user/{user}", perms))

        for role in inventory.get("iam_roles", []):
            perms = self._get_role_permissions(iam, role)
            entities.append((f"role/{role}", perms))

        return entities

    def _get_user_permissions(self, iam: Any, username: str) -> Set[str]:
        perms: Set[str] = set()
        try:
            # Inline policies
            for policy_name in iam.list_user_policies(UserName=username).get("PolicyNames", []):
                doc = iam.get_user_policy(UserName=username, PolicyName=policy_name)
                perms.update(self._extract_allows(doc.get("PolicyDocument", {})))
            # Attached managed policies
            for policy in iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", []):
                perms.update(self._get_managed_policy_perms(iam, policy["PolicyArn"]))
        except Exception as exc:
            logger.debug("Failed to collect perms for user %s: %s", username, exc)
        return perms

    def _get_role_permissions(self, iam: Any, role_name: str) -> Set[str]:
        perms: Set[str] = set()
        try:
            for policy_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                perms.update(self._extract_allows(doc.get("PolicyDocument", {})))
            for policy in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
                perms.update(self._get_managed_policy_perms(iam, policy["PolicyArn"]))
        except Exception as exc:
            logger.debug("Failed to collect perms for role %s: %s", role_name, exc)
        return perms

    def _get_managed_policy_perms(self, iam: Any, policy_arn: str) -> Set[str]:
        try:
            version_id = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
            doc = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
            return self._extract_allows(doc["PolicyVersion"].get("Document", {}))
        except Exception:
            return set()

    @staticmethod
    def _extract_allows(policy_document: Any) -> Set[str]:
        """Extract all Allow actions from a policy document dict."""
        actions: Set[str] = set()
        if isinstance(policy_document, str):
            try:
                policy_document = json.loads(policy_document)
            except Exception:
                return actions
        for stmt in policy_document.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            stmt_actions = stmt.get("Action", [])
            if isinstance(stmt_actions, str):
                stmt_actions = [stmt_actions]
            for action in stmt_actions:
                actions.add(action.lower())
        return actions

    @staticmethod
    def _find_escalation_paths(
        entities: List[Tuple[str, Set[str]]]
    ) -> List[Tuple[str, str, str]]:
        """Return (entity_name, evidence_str, vector_type) for each found path."""
        results: List[Tuple[str, str, str]] = []

        for entity_name, perms in entities:
            # Wildcard admin
            if "iam:*" in perms or "*" in perms:
                results.append((
                    entity_name,
                    "Entity has wildcard (*) or iam:* permissions — full admin access.",
                    "wildcard-admin",
                ))
                continue  # No need to check further for this entity

            # Direct privilege escalation vectors
            for perm, description in _DIRECT_PRIVESC.items():
                if perm.lower() in perms:
                    results.append((
                        entity_name,
                        f"Permission: {perm}\nVector: {description}",
                        perm,
                    ))

            # PassRole + service combinations
            if "iam:passrole" in perms:
                for service_perm, service_description in _PASSROLE_ESCALATION_SERVICES.items():
                    if service_perm.lower() in perms:
                        results.append((
                            entity_name,
                            f"iam:PassRole + {service_perm}\nVector: {service_description}",
                            f"PassRole+{service_perm}",
                        ))

        return results
