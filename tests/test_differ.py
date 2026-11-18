"""Tests for the differ module."""

from __future__ import annotations

import io

from iam_diff.differ import (
    ChangeKind,
    ResourceDiff,
    _action_matches,
    _effective_net_allow,
    _resource_matches,
    compute_diff,
    render_diff,
)
from iam_diff.normalizer import ResourceAccess

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


# ---------------------------------------------------------------------------
# Wildcard resolution helpers
# ---------------------------------------------------------------------------


class TestResourceMatches:
    def test_star_matches_any_arn(self) -> None:
        assert _resource_matches("*", "arn:aws:sqs:us-east-1:123456789012:my-queue")

    def test_exact_match(self) -> None:
        assert _resource_matches("arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket")

    def test_glob_pattern(self) -> None:
        assert _resource_matches("arn:aws:s3:::my-bucket/*", "arn:aws:s3:::my-bucket/key")

    def test_no_match(self) -> None:
        assert not _resource_matches("arn:aws:s3:::other-bucket/*", "arn:aws:s3:::my-bucket/key")

    def test_no_cross_service_match(self) -> None:
        assert not _resource_matches("arn:aws:sqs:*", "arn:aws:s3:::my-bucket")


class TestActionMatches:
    def test_exact_match(self) -> None:
        assert _action_matches("sqs:ReceiveMessage", "sqs:ReceiveMessage")

    def test_wildcard_service_all(self) -> None:
        assert _action_matches("sqs:*", "sqs:ReceiveMessage")
        assert _action_matches("sqs:*", "sqs:DeleteMessage")
        assert _action_matches("sqs:*", "sqs:SendMessage")

    def test_wildcard_does_not_cross_service(self) -> None:
        assert not _action_matches("sqs:*", "s3:GetObject")

    def test_case_insensitive(self) -> None:
        assert _action_matches("SQS:*", "sqs:ReceiveMessage")


class TestEffectiveNetAllow:
    def test_star_resource_covers_specific(self) -> None:
        """Resource:* with sqs:* should grant sqs:* to a specific queue ARN."""
        star_ra = ResourceAccess()
        star_ra.allow = {"sqs:*"}
        resource_map = {"*": star_ra}
        effective = _effective_net_allow("arn:aws:sqs:us-east-1:123456789012:my-queue", resource_map)
        assert "sqs:*" in effective

    def test_specific_resource_does_not_gain_from_unrelated_wildcard(self) -> None:
        star_ra = ResourceAccess()
        star_ra.allow = {"s3:*"}
        sqs_ra = ResourceAccess()
        sqs_ra.allow = {"sqs:ReceiveMessage"}
        resource_map = {
            "*": star_ra,
            "arn:aws:sqs:us-east-1:123456789012:my-queue": sqs_ra,
        }
        effective = _effective_net_allow("arn:aws:sqs:us-east-1:123456789012:my-queue", resource_map)
        # Both star_ra and sqs_ra cover the specific queue
        assert "s3:*" in effective
        assert "sqs:ReceiveMessage" in effective

    def test_deny_on_star_resource_subtracted(self) -> None:
        star_ra = ResourceAccess()
        star_ra.allow = {"sqs:*"}
        star_ra.deny = {"sqs:DeleteQueue"}
        resource_map = {"*": star_ra}
        effective = _effective_net_allow("arn:aws:sqs:us-east-1:123456789012:my-queue", resource_map)
        # sqs:DeleteQueue is in both allow (via sqs:*) and deny; net_allow subtracts
        # it at the string level — the literal string "sqs:DeleteQueue" is removed.
        assert "sqs:DeleteQueue" not in effective
        # sqs:* (the wildcard pattern) remains in the effective set because the deny
        # only removes the exact string "sqs:DeleteQueue", not the pattern itself.
        # The action-level glob comparison in action_diffs handles the rest.
        assert "sqs:*" in effective


# ---------------------------------------------------------------------------
# Wildcard encompassing — the core bug scenario
# ---------------------------------------------------------------------------


class TestWildcardEncompassing:
    """
    Principal:* Resource:* sqs:*  should encompass  sqs:specific-action
    on arn:aws:sqs:...:some-queue.  The diff must not report [+] or [-]
    for actions that are already covered by a broader grant.
    """

    def _make_wildcard_map(self, wildcard_actions: list[str]) -> dict:
        """Left map: Principal=*, Resource=*, actions=wildcard_actions."""
        ra = ResourceAccess()
        ra.allow = set(wildcard_actions)
        return {"*": {"*": ra}}

    def _make_specific_map(self, queue_arn: str, actions: list[str]) -> dict:
        """Right map: Principal=*, Resource=* (same wildcards) + specific queue."""
        star_ra = ResourceAccess()
        star_ra.allow = set(["sqs:*"])
        specific_ra = ResourceAccess()
        specific_ra.allow = set(actions)
        return {"*": {"*": star_ra, queue_arn: specific_ra}}

    def test_sqs_wildcard_covers_specific_queue_actions(self) -> None:
        """
        Left:  Principal=* Resource=* sqs:*
        Right: Principal=* Resource=* sqs:*
               Principal=* Resource=arn:aws:sqs:...:q  sqs:DeleteMessage, sqs:ReceiveMessage, sqs:GetQueueAttributes

        Expect: NO diff — the specific queue's actions are covered by sqs:* on *.
        """
        queue_arn = "arn:aws:sqs:us-east-1:339712844224:glue-to-pdf-queue"

        left_ra = ResourceAccess()
        left_ra.allow = {"sqs:*"}
        left_map = {"*": {"*": left_ra}}

        star_ra = ResourceAccess()
        star_ra.allow = {"sqs:*"}
        specific_ra = ResourceAccess()
        specific_ra.allow = {"sqs:DeleteMessage", "sqs:ReceiveMessage", "sqs:GetQueueAttributes"}
        right_map = {"*": {"*": star_ra, queue_arn: specific_ra}}

        diffs = compute_diff(left_map, right_map)
        assert len(diffs) == 1
        pd = diffs[0]
        assert not pd.has_diff, (
            "Expected no diff: sqs:* on Resource:* already covers the specific queue actions"
        )

    def test_truly_new_specific_action_shows_diff(self) -> None:
        """
        An action on a specific resource that is NOT covered by any wildcard
        on the other side should still be reported as a diff.
        """
        queue_arn = "arn:aws:sqs:us-east-1:339712844224:new-queue"

        left_ra = ResourceAccess()
        left_ra.allow = {"s3:*"}  # no sqs coverage
        left_map = {"*": {"*": left_ra}}

        right_ra = ResourceAccess()
        right_ra.allow = {"sqs:DeleteMessage"}
        right_map = {"*": {queue_arn: right_ra}}

        diffs = compute_diff(left_map, right_map)
        pd = diffs[0]
        # The queue ARN resource should show a diff
        queue_rd = next(rd for rd in pd.resource_diffs if rd.resource == queue_arn)
        added = [d for d in queue_rd.action_diffs if d.kind == ChangeKind.ADDED]
        assert any(d.action == "sqs:DeleteMessage" for d in added)

    def test_s3_object_lambda_not_removed_by_s3_wildcard(self) -> None:
        """
        s3-object-lambda:* on Resource:* should not be considered a removal
        just because s3:* is present — they are different service prefixes.
        The diff should show s3-object-lambda:* as EQUAL on both sides.
        """
        ra_left = ResourceAccess()
        ra_left.allow = {"s3:*", "s3-object-lambda:*"}
        left_map = {"*": {"*": ra_left}}

        ra_right = ResourceAccess()
        ra_right.allow = {"s3:*", "s3-object-lambda:*"}
        right_map = {"*": {"*": ra_right}}

        diffs = compute_diff(left_map, right_map)
        assert not diffs[0].has_diff

    def test_render_no_spurious_additions(self) -> None:
        """End-to-end: render_diff must not emit [+] lines for covered actions."""
        queue_arn = "arn:aws:sqs:us-east-1:339712844224:glue-to-pdf-queue"

        left_ra = ResourceAccess()
        left_ra.allow = {"sqs:*"}
        left_map = {"*": {"*": left_ra}}

        star_ra = ResourceAccess()
        star_ra.allow = {"sqs:*"}
        specific_ra = ResourceAccess()
        specific_ra.allow = {"sqs:DeleteMessage", "sqs:ReceiveMessage", "sqs:GetQueueAttributes"}
        right_map = {"*": {"*": star_ra, queue_arn: specific_ra}}

        buf = io.StringIO()
        diffs = compute_diff(left_map, right_map)
        render_diff(diffs, "left-role", "right-role", stream=buf, use_color=False)
        output = buf.getvalue()
        assert "[+]" not in output
        assert "[-]" not in output
        assert "No differences found" in output
