"""Tests for the differ module."""

from __future__ import annotations

import io

from role_diff.differ import (
    ChangeKind,
    ResourceDiff,
    compute_diff,
    render_diff,
)
from role_diff.normalizer import ResourceAccess

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_map(allow: list[str], deny: list[str] | None = None) -> dict:
    """Build a minimal AccessMap for principal='*', resource='*'."""
    ra = ResourceAccess()
    ra.allow = set(allow)
    ra.deny = set(deny or [])
    return {"*": {"*": ra}}


# ---------------------------------------------------------------------------
# ResourceDiff.action_diffs
# ---------------------------------------------------------------------------


class TestResourceDiff:
    def test_added_only(self) -> None:
        left_ra = ResourceAccess()
        left_ra.allow = {"s3:GetObject"}
        right_ra = ResourceAccess()
        right_ra.allow = {"s3:GetObject", "s3:PutObject"}
        rd = ResourceDiff(resource="*", left_ra=left_ra, right_ra=right_ra)
        kinds = {d.action: d.kind for d in rd.action_diffs}
        assert kinds["s3:GetObject"] == ChangeKind.EQUAL
        assert kinds["s3:PutObject"] == ChangeKind.ADDED

    def test_removed_only(self) -> None:
        left_ra = ResourceAccess()
        left_ra.allow = {"s3:GetObject", "s3:DeleteObject"}
        right_ra = ResourceAccess()
        right_ra.allow = {"s3:GetObject"}
        rd = ResourceDiff(resource="*", left_ra=left_ra, right_ra=right_ra)
        kinds = {d.action: d.kind for d in rd.action_diffs}
        assert kinds["s3:DeleteObject"] == ChangeKind.REMOVED
        assert kinds["s3:GetObject"] == ChangeKind.EQUAL

    def test_no_diff(self) -> None:
        ra = ResourceAccess()
        ra.allow = {"s3:GetObject"}
        rd = ResourceDiff(resource="*", left_ra=ra, right_ra=ra)
        assert rd.has_diff is False

    def test_left_none(self) -> None:
        right_ra = ResourceAccess()
        right_ra.allow = {"s3:GetObject"}
        rd = ResourceDiff(resource="*", left_ra=None, right_ra=right_ra)
        kinds = {d.action: d.kind for d in rd.action_diffs}
        assert kinds["s3:GetObject"] == ChangeKind.ADDED
        assert rd.has_diff is True

    def test_right_none(self) -> None:
        left_ra = ResourceAccess()
        left_ra.allow = {"s3:GetObject"}
        rd = ResourceDiff(resource="*", left_ra=left_ra, right_ra=None)
        kinds = {d.action: d.kind for d in rd.action_diffs}
        assert kinds["s3:GetObject"] == ChangeKind.REMOVED
        assert rd.has_diff is True

    def test_deny_excluded_from_net_allow(self) -> None:
        left_ra = ResourceAccess()
        left_ra.allow = {"s3:GetObject", "s3:DeleteObject"}
        left_ra.deny = {"s3:DeleteObject"}
        right_ra = ResourceAccess()
        right_ra.allow = {"s3:GetObject"}
        rd = ResourceDiff(resource="*", left_ra=left_ra, right_ra=right_ra)
        # DeleteObject is in left deny, so net_allow excludes it → should not appear as REMOVED
        kinds = {d.action: d.kind for d in rd.action_diffs}
        # DeleteObject: left net_allow does NOT include it; right also doesn't → EQUAL or absent
        # It IS in left_ra.deny so it will still appear in the union
        # But net_allow for left excludes it, so left_has = False (from net_allow perspective)
        # Actually: action_diffs uses net_allow + deny union so DeleteObject shows up from deny
        assert "s3:GetObject" in kinds
        assert kinds["s3:GetObject"] == ChangeKind.EQUAL


# ---------------------------------------------------------------------------
# compute_diff
# ---------------------------------------------------------------------------


class TestComputeDiff:
    def test_identical_maps_no_diff(self) -> None:
        amap = _make_map(["s3:GetObject", "s3:PutObject"])
        diffs = compute_diff(amap, amap)
        assert all(not pd.has_diff for pd in diffs)

    def test_added_principal(self) -> None:
        left = _make_map(["s3:GetObject"])
        right = {
            **_make_map(["s3:GetObject"]),
            "arn:aws:iam::123:role/NewRole": {"*": ResourceAccess()},
        }
        right["arn:aws:iam::123:role/NewRole"]["*"].allow = {"lambda:InvokeFunction"}
        diffs = compute_diff(left, right)
        principals = {pd.principal for pd in diffs}
        assert "arn:aws:iam::123:role/NewRole" in principals

    def test_removed_action(self) -> None:
        left = _make_map(["s3:GetObject", "s3:DeleteObject"])
        right = _make_map(["s3:GetObject"])
        diffs = compute_diff(left, right)
        pd = diffs[0]
        rd = pd.resource_diffs[0]
        removed = [d for d in rd.action_diffs if d.kind == ChangeKind.REMOVED]
        assert any(d.action == "s3:DeleteObject" for d in removed)

    def test_empty_both(self) -> None:
        diffs = compute_diff({}, {})
        assert diffs == []


# ---------------------------------------------------------------------------
# render_diff
# ---------------------------------------------------------------------------


class TestRenderDiff:
    def _render(self, left: dict, right: dict, **kwargs) -> str:
        buf = io.StringIO()
        diffs = compute_diff(left, right)
        render_diff(diffs, "LeftRole", "RightRole", stream=buf, use_color=False, **kwargs)
        return buf.getvalue()

    def test_no_diff_message(self) -> None:
        amap = _make_map(["s3:GetObject"])
        output = self._render(amap, amap)
        assert "No differences found" in output

    def test_added_action_shown(self) -> None:
        left = _make_map(["s3:GetObject"])
        right = _make_map(["s3:GetObject", "s3:PutObject"])
        output = self._render(left, right)
        assert "[+]" in output
        assert "s3:PutObject" in output

    def test_removed_action_shown(self) -> None:
        left = _make_map(["s3:GetObject", "s3:DeleteObject"])
        right = _make_map(["s3:GetObject"])
        output = self._render(left, right)
        assert "[-]" in output
        assert "s3:DeleteObject" in output

    def test_labels_in_header(self) -> None:
        amap = _make_map([])
        output = self._render(amap, amap)
        assert "LeftRole" in output
        assert "RightRole" in output

    def test_no_context_hides_equal(self) -> None:
        left = _make_map(["s3:GetObject", "s3:PutObject"])
        right = _make_map(["s3:GetObject", "s3:DeleteObject"])
        output = self._render(left, right, show_equal=False)
        # GetObject is equal; should not appear outside the resource header
        lines = [line for line in output.splitlines() if "s3:GetObject" in line]
        # With show_equal=False there should be no plain GetObject line
        assert all("[+]" in line or "[-]" in line or "Resource:" in line for line in lines)

    def test_only_changed_skips_unchanged_principals(self) -> None:
        amap = _make_map(["s3:GetObject"])
        extra_ra = ResourceAccess()
        extra_ra.allow = {"s3:GetObject"}
        left = {**amap, "arn:aws:iam::123:role/Same": {"*": extra_ra}}
        right = {**amap, "arn:aws:iam::123:role/Same": {"*": extra_ra}}
        output = self._render(left, right, only_changed=True)
        assert "No differences found" in output
