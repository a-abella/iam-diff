"""
CLI entry point for iam-diff.

Usage examples:

    # Compare two roles in the default account / profile
    iam-diff MyRoleA MyRoleB

    # With explicit AWS profile and region
    iam-diff --profile staging --region us-east-1 MyRoleA MyRoleB

    # Compare a role against a managed policy ARN
    iam-diff MyRole arn:aws:iam::123456789012:policy/MyPolicy

    # Hide unchanged action lines (show only +/-)
    iam-diff --no-context MyRoleA MyRoleB

    # Suppress ANSI color
    iam-diff --no-color MyRoleA MyRoleB | tee diff.txt
"""

from __future__ import annotations

import argparse
import logging
import sys

from iam_diff import __version__
from iam_diff.differ import compute_diff, render_diff
from iam_diff.fetcher import fetch_statements
from iam_diff.normalizer import normalize


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iam-diff",
        description=(
            "Diff the functional IAM access of two AWS roles or policies.\n\n"
            "LEFT and RIGHT may be:\n"
            "  - An IAM role name               (e.g. MyRole)\n"
            "  - An IAM role ARN                (e.g. arn:aws:iam::123:role/MyRole)\n"
            "  - An AWS-managed policy ARN      (e.g. arn:aws:iam::aws:policy/ReadOnlyAccess)\n"
            "  - A customer-managed policy ARN  (e.g. arn:aws:iam::123:policy/MyPolicy)\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("left", metavar="LEFT", help="Role name, role ARN, or policy ARN (left side)")
    parser.add_argument("right", metavar="RIGHT", help="Role name, role ARN, or policy ARN (right side)")

    aws = parser.add_argument_group("AWS options")
    aws.add_argument("--profile", metavar="PROFILE", help="AWS CLI profile to use (both sides)")
    aws.add_argument("--region", metavar="REGION", help="AWS region (both sides)")

    display = parser.add_argument_group("display options")
    display.add_argument(
        "--no-context",
        action="store_true",
        default=False,
        help="Hide unchanged (context) action lines; show only additions and removals",
    )
    display.add_argument(
        "--only-changed",
        action="store_true",
        default=False,
        help="Skip principals/resources with no difference",
    )
    display.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable ANSI color output",
    )

    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        print(f"Fetching LEFT:  {args.left} ...", file=sys.stderr)
        left_stmts = fetch_statements(args.left, profile=args.profile, region=args.region)

        print(f"Fetching RIGHT: {args.right} ...", file=sys.stderr)
        right_stmts = fetch_statements(args.right, profile=args.profile, region=args.region)
    except Exception as exc:  # noqa: BLE001
        print(f"Error fetching IAM data: {exc}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

    left_map = normalize(left_stmts)
    right_map = normalize(right_stmts)

    diffs = compute_diff(left_map, right_map)

    use_color = False if args.no_color else None  # None = auto-detect

    render_diff(
        diffs,
        left_label=args.left,
        right_label=args.right,
        show_equal=not args.no_context,
        use_color=use_color,
        only_changed=args.only_changed,
    )

    # Exit 1 if there are any differences (useful in CI)
    has_diff = any(pd.has_diff for pd in diffs)
    return 1 if has_diff else 0


if __name__ == "__main__":
    sys.exit(main())
