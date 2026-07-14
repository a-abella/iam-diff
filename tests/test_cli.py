"""Tests for the CLI entry point (no real AWS calls)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from iam_diff.cli import main

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_STMTS_A = [
    MagicMock(
        effect="Allow",
        principals=["*"],
        actions=["s3:GetObject"],
        resources=["arn:aws:s3:::bucket-a/*"],
        conditions={},
        not_action=False,
        not_resource=False,
        is_deny=False,
    )
]

SAMPLE_STMTS_B = [
    MagicMock(
        effect="Allow",
        principals=["*"],
        actions=["s3:GetObject", "s3:PutObject"],
        resources=["arn:aws:s3:::bucket-a/*"],
        conditions={},
        not_action=False,
        not_resource=False,
        is_deny=False,
    )
]


def _mock_fetch(side_effects: list):
    """Return a patch context for fetch_statements with given side-effects."""
    return patch("iam_diff.cli.fetch_statements", side_effect=side_effects)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCLI:
    def test_no_diff_exit_0(self, capsys) -> None:
        stmts = SAMPLE_STMTS_A
        with _mock_fetch([stmts, stmts]):
            rc = main(["--no-color", "RoleA", "RoleA"])
        assert rc == 0

    def test_diff_exit_1(self, capsys) -> None:
        with _mock_fetch([SAMPLE_STMTS_A, SAMPLE_STMTS_B]):
            rc = main(["--no-color", "RoleA", "RoleB"])
        assert rc == 1

    def test_fetch_error_exit_1(self, capsys) -> None:
        with patch("iam_diff.cli.fetch_statements", side_effect=Exception("boom")):
            rc = main(["--no-color", "RoleA", "RoleB"])
        assert rc == 1
        captured = capsys.readouterr()
        assert "boom" in captured.err

    def test_no_context_flag(self, capsys) -> None:
        with _mock_fetch([SAMPLE_STMTS_A, SAMPLE_STMTS_B]):
            main(["--no-color", "--no-context", "RoleA", "RoleB"])
        out = capsys.readouterr().out
        # Equal actions should not appear as plain lines
        lines_with_get = [line for line in out.splitlines() if "s3:GetObject" in line]
        assert all("[+]" in line or "[-]" in line or "Resource:" in line for line in lines_with_get)

    def test_only_changed_flag(self, capsys) -> None:
        stmts = SAMPLE_STMTS_A
        with _mock_fetch([stmts, stmts]):
            main(["--no-color", "--only-changed", "RoleA", "RoleA"])
        out = capsys.readouterr().out
        assert "No differences found" in out

    def test_profile_and_region_passed(self) -> None:
        with patch("iam_diff.cli.fetch_statements") as mock_fetch:
            mock_fetch.return_value = SAMPLE_STMTS_A
            main(["--no-color", "--profile", "myprofile", "--region", "eu-west-1", "RoleA", "RoleB"])
        calls = mock_fetch.call_args_list
        for call in calls:
            assert call.kwargs.get("profile") == "myprofile"
            assert call.kwargs.get("region") == "eu-west-1"
