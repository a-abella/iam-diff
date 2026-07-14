"""
AWS IAM policy fetcher.

Retrieves all policies (inline + attached) for a given IAM role name or
policy ARN, then parses each Statement into a list of canonical
AccessStatement objects.
"""

from __future__ import annotations

import json
import logging
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

import boto3

logger = logging.getLogger(__name__)


@dataclass
class AccessStatement:
    """A single parsed IAM statement, expanded to lists of strings."""

    effect: str  # "Allow" | "Deny"
    principals: list[str]  # ["*"] | ["arn:aws:iam::123:role/Foo"]
    actions: list[str]  # ["s3:GetObject", "s3:PutObject"]
    resources: list[str]  # ["arn:aws:s3:::my-bucket/*"]
    conditions: dict[str, Any] = field(default_factory=dict)
    not_action: bool = False  # True when statement used NotAction
    not_resource: bool = False  # True when statement used NotResource

    @property
    def is_deny(self) -> bool:
        return self.effect.lower() == "deny"


def _to_list(value: Any) -> list[str]:
    """Coerce a string or list to a list of strings."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


def _parse_principals(stmt: dict[str, Any]) -> list[str]:
    """Extract principals from a statement dict."""
    raw = stmt.get("Principal", stmt.get("NotPrincipal", "*"))
    if raw == "*" or raw is None:
        return ["*"]
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [str(p) for p in raw]
    # Principal can be {"Service": [...], "AWS": [...]}
    principals: list[str] = []
    for kind, values in raw.items():
        for v in _to_list(values):
            principals.append(f"{kind}:{v}" if kind != "AWS" else v)
    return principals or ["*"]


def parse_policy_document(doc: dict[str, Any]) -> list[AccessStatement]:
    """Parse a policy document dict into a list of AccessStatements."""
    statements: list[AccessStatement] = []
    for stmt in doc.get("Statement", []):
        effect = stmt.get("Effect", "Allow")
        principals = _parse_principals(stmt)
        conditions = stmt.get("Condition", {})

        not_action = "NotAction" in stmt
        not_resource = "NotResource" in stmt

        actions = _to_list(stmt.get("NotAction" if not_action else "Action", []))
        resources = _to_list(stmt.get("NotResource" if not_resource else "Resource", []))

        statements.append(
            AccessStatement(
                effect=effect,
                principals=principals,
                actions=actions,
                resources=resources,
                conditions=conditions,
                not_action=not_action,
                not_resource=not_resource,
            )
        )
    return statements


def _decode_policy(encoded: str) -> dict[str, Any]:
    decoded = urllib.parse.unquote(encoded)
    return json.loads(decoded)  # type: ignore[no-any-return]


def fetch_statements_for_role(
    role_name: str,
    *,
    profile: str | None = None,
    region: str | None = None,
) -> list[AccessStatement]:
    """
    Fetch all IAM statements that apply to *role_name*.

    Collects:
    - Every inline policy on the role
    - Every managed policy attached to the role
    - The role's trust policy (principal = the role's callers)
    """
    session = boto3.Session(profile_name=profile, region_name=region)
    iam = session.client("iam")

    all_statements: list[AccessStatement] = []

    # --- Inline policies ---
    paginator = iam.get_paginator("list_role_policies")
    for page in paginator.paginate(RoleName=role_name):
        for policy_name in page["PolicyNames"]:
            resp = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            doc = _decode_policy(resp["PolicyDocument"]) if isinstance(resp["PolicyDocument"], str) else resp["PolicyDocument"]
            logger.debug("Inline policy %s on role %s", policy_name, role_name)
            all_statements.extend(parse_policy_document(doc))

    # --- Attached managed policies ---
    paginator = iam.get_paginator("list_attached_role_policies")
    for page in paginator.paginate(RoleName=role_name):
        for policy in page["AttachedPolicies"]:
            arn = policy["PolicyArn"]
            version_id = iam.get_policy(PolicyArn=arn)["Policy"]["DefaultVersionId"]
            resp = iam.get_policy_version(PolicyArn=arn, VersionId=version_id)
            doc = resp["PolicyVersion"]["Document"]
            if isinstance(doc, str):
                doc = _decode_policy(doc)
            logger.debug("Attached policy %s on role %s", arn, role_name)
            all_statements.extend(parse_policy_document(doc))

    return all_statements


def fetch_statements_for_policy(
    policy_arn: str,
    *,
    profile: str | None = None,
    region: str | None = None,
) -> list[AccessStatement]:
    """Fetch statements for a standalone managed policy ARN."""
    session = boto3.Session(profile_name=profile, region_name=region)
    iam = session.client("iam")

    version_id = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
    resp = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
    doc = resp["PolicyVersion"]["Document"]
    if isinstance(doc, str):
        doc = _decode_policy(doc)
    return parse_policy_document(doc)


def fetch_statements(
    target: str,
    *,
    profile: str | None = None,
    region: str | None = None,
) -> list[AccessStatement]:
    """
    Auto-detect whether *target* is a role name or a policy ARN and fetch
    the appropriate statements.
    """
    if target.startswith("arn:aws") and ":policy/" in target:
        return fetch_statements_for_policy(target, profile=profile, region=region)
    # Assume role name (or role ARN – extract name)
    if target.startswith("arn:aws"):
        target = target.rsplit("/", 1)[-1]
    return fetch_statements_for_role(target, profile=profile, region=region)
