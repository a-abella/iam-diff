"""Tests for the policy normalizer."""

from __future__ import annotations

from role_diff.fetcher import parse_policy_document
from role_diff.normalizer import normalize, to_sorted_dict

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------

SIMPLE_ALLOW_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": "arn:aws:s3:::my-bucket/*",
        }
    ],
}

DENY_OVERRIDE_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
            "Resource": "arn:aws:s3:::my-bucket/*",
        },
        {
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:DeleteObject",
            "Resource": "arn:aws:s3:::my-bucket/*",
        },
    ],
}

MULTI_PRINCIPAL_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "arn:aws:iam::123456789012:role/RoleA",
                    "arn:aws:iam::123456789012:role/RoleB",
                ]
            },
            "Action": "lambda:InvokeFunction",
            "Resource": "arn:aws:lambda:us-east-1:123456789012:function:MyFunc",
        }
    ],
}

NOT_ACTION_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "NotAction": ["iam:*", "sts:AssumeRole"],
            "Resource": "*",
        }
    ],
}


# ---------------------------------------------------------------------------
# parse_policy_document
# ---------------------------------------------------------------------------


class TestParsePolicyDocument:
    def test_simple_allow(self) -> None:
        stmts = parse_policy_document(SIMPLE_ALLOW_DOC)
        assert len(stmts) == 1
        s = stmts[0]
        assert s.effect == "Allow"
        assert s.principals == ["*"]
        assert sorted(s.actions) == ["s3:GetObject", "s3:PutObject"]
        assert s.resources == ["arn:aws:s3:::my-bucket/*"]
        assert not s.not_action

    def test_deny_statement(self) -> None:
        stmts = parse_policy_document(DENY_OVERRIDE_DOC)
        effects = [s.effect for s in stmts]
        assert "Deny" in effects

    def test_multi_principal(self) -> None:
        stmts = parse_policy_document(MULTI_PRINCIPAL_DOC)
        assert len(stmts) == 1
        assert "arn:aws:iam::123456789012:role/RoleA" in stmts[0].principals
        assert "arn:aws:iam::123456789012:role/RoleB" in stmts[0].principals

    def test_not_action(self) -> None:
        stmts = parse_policy_document(NOT_ACTION_DOC)
        assert len(stmts) == 1
        assert stmts[0].not_action is True
        assert "iam:*" in stmts[0].actions

    def test_empty_document(self) -> None:
        stmts = parse_policy_document({})
        assert stmts == []

    def test_string_action_coerced_to_list(self) -> None:
        doc = {
            "Statement": [
                {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}
            ]
        }
        stmts = parse_policy_document(doc)
        assert stmts[0].actions == ["s3:GetObject"]


# ---------------------------------------------------------------------------
# normalize
# ---------------------------------------------------------------------------


class TestNormalize:
    def test_simple_allow(self) -> None:
        stmts = parse_policy_document(SIMPLE_ALLOW_DOC)
        amap = normalize(stmts)
        ra = amap["*"]["arn:aws:s3:::my-bucket/*"]
        assert "s3:GetObject" in ra.allow
        assert "s3:PutObject" in ra.allow
        assert ra.deny == set()

    def test_deny_overrides_allow(self) -> None:
        stmts = parse_policy_document(DENY_OVERRIDE_DOC)
        amap = normalize(stmts)
        ra = amap["*"]["arn:aws:s3:::my-bucket/*"]
        # DeleteObject should appear in deny
        assert "s3:DeleteObject" in ra.deny
        # net_allow should NOT contain DeleteObject
        assert "s3:DeleteObject" not in ra.net_allow
        # But GetObject and PutObject should be in net_allow
        assert "s3:GetObject" in ra.net_allow
        assert "s3:PutObject" in ra.net_allow

    def test_multi_statement_union(self) -> None:
        doc = {
            "Statement": [
                {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"},
                {"Effect": "Allow", "Principal": "*", "Action": "s3:PutObject", "Resource": "*"},
            ]
        }
        stmts = parse_policy_document(doc)
        amap = normalize(stmts)
        ra = amap["*"]["*"]
        assert "s3:GetObject" in ra.allow
        assert "s3:PutObject" in ra.allow

    def test_not_action_recorded(self) -> None:
        stmts = parse_policy_document(NOT_ACTION_DOC)
        amap = normalize(stmts)
        ra = amap["*"]["*"]
        assert "iam:*" in ra.not_action_allow

    def test_empty_statements(self) -> None:
        amap = normalize([])
        assert amap == {}


# ---------------------------------------------------------------------------
# to_sorted_dict
# ---------------------------------------------------------------------------


class TestToSortedDict:
    def test_sorted_output(self) -> None:
        stmts = parse_policy_document(SIMPLE_ALLOW_DOC)
        amap = normalize(stmts)
        d = to_sorted_dict(amap)
        principal = "*"
        resource = "arn:aws:s3:::my-bucket/*"
        assert principal in d
        assert resource in d[principal]
        entry = d[principal][resource]
        assert entry["allow"] == sorted(entry["allow"])
        assert entry["deny"] == []

    def test_all_keys_present(self) -> None:
        stmts = parse_policy_document(SIMPLE_ALLOW_DOC)
        amap = normalize(stmts)
        d = to_sorted_dict(amap)
        for p in d:
            for r in d[p]:
                for key in ("allow", "deny", "not_action_allow", "not_action_deny", "not_resource_actions"):
                    assert key in d[p][r], f"Missing key {key}"
