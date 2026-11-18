"""
Side-by-side colorized diff of two AccessMaps.

Output format (per principal / resource pair):

    Principal: *
      Resource: arn:aws:s3:::my-bucket/*
        [+] s3:GetObject        (only in right / added)
        [-] s3:DeleteObject     (only in left  / removed)
            s3:PutObject        (present in both)

Color scheme (ANSI):
    green  (+) present only in right
    red    (-) present only in left
    white      present in both (context lines, toggleable)
"""

from __future__ import annotations

import fnmatch
import sys
from dataclasses import dataclass
from enum import Enum
from typing import TextIO

from iam_diff.normalizer import AccessMap, ResourceAccess

# ---------------------------------------------------------------------------
# ANSI helpers
# ---------------------------------------------------------------------------

RESET = "\033[0m"
GREEN = "\033[32m"
RED = "\033[31m"
CYAN = "\033[36m"
BOLD = "\033[1m"
DIM = "\033[2m"


def _color(text: str, code: str, *, use_color: bool = True) -> str:
    if not use_color:
        return text
    return f"{code}{text}{RESET}"


# ---------------------------------------------------------------------------
# Wildcard / glob resolution helpers
# ---------------------------------------------------------------------------


def _resource_matches(pattern: str, resource: str) -> bool:
    """
    Return True if *pattern* covers *resource*.

    IAM resource patterns use ``*`` (any sequence) and ``?`` (single char).
    A plain ``*`` covers every resource ARN.
    """
    if pattern == resource:
        return True
    return fnmatch.fnmatch(resource, pattern)


def _action_matches(pattern: str, action: str) -> bool:
    """
    Return True if *pattern* covers *action*.

    e.g. ``sqs:*`` covers ``sqs:ReceiveMessage``.
    """
    if pattern == action:
        return True
    return fnmatch.fnmatch(action.lower(), pattern.lower())


def _effective_net_allow(resource: str, resource_map: dict[str, ResourceAccess]) -> frozenset[str]:
    """
    Compute the effective net-allowed actions for *resource* given all
    entries in *resource_map* (one principal's resource → ResourceAccess dict).

    A broader entry (e.g. ``Resource: *`` with ``sqs:*``) covers a specific
    resource, so its actions must be folded in before we diff.

    Algorithm:
    1. Collect all Allow actions from every resource entry whose pattern
       matches *resource* (including the exact entry itself).
    2. Keep wildcard action patterns as-is; rely on action-level glob
       matching during the diff comparison.
    3. Subtract all Deny actions from every resource entry that matches
       *resource*.
    """
    combined_allow: set[str] = set()
    combined_deny: set[str] = set()

    for pat, ra in resource_map.items():
        if _resource_matches(pat, resource):
            combined_allow.update(ra.allow)
            combined_deny.update(ra.deny)

    return frozenset(combined_allow - combined_deny)


# ---------------------------------------------------------------------------
# Diff data structures
# ---------------------------------------------------------------------------


class ChangeKind(Enum):
    ADDED = "+"
    REMOVED = "-"
    EQUAL = " "


@dataclass
class ActionDiff:
    kind: ChangeKind
    action: str


@dataclass
class ResourceDiff:
    resource: str
    left_ra: ResourceAccess | None
    right_ra: ResourceAccess | None

    @property
    def action_diffs(self) -> list[ActionDiff]:
        left_allow = self.left_ra.net_allow if self.left_ra else frozenset()
        right_allow = self.right_ra.net_allow if self.right_ra else frozenset()

        left_deny = self.left_ra.deny if self.left_ra else frozenset()
        right_deny = self.right_ra.deny if self.right_ra else frozenset()

        all_actions = sorted(left_allow | right_allow | left_deny | right_deny)
        diffs: list[ActionDiff] = []
        for action in all_actions:
            # An action on one side is "present" if it is explicitly listed
            # OR if a wildcard pattern on that side covers it.
            l_has = any(_action_matches(pat, action) for pat in (left_allow | left_deny))
            r_has = any(_action_matches(pat, action) for pat in (right_allow | right_deny))
            if l_has and r_has:
                diffs.append(ActionDiff(ChangeKind.EQUAL, action))
            elif r_has:
                diffs.append(ActionDiff(ChangeKind.ADDED, action))
            else:
                diffs.append(ActionDiff(ChangeKind.REMOVED, action))
        return diffs

    @property
    def has_diff(self) -> bool:
        return any(d.kind != ChangeKind.EQUAL for d in self.action_diffs)


@dataclass
class PrincipalDiff:
    principal: str
    resource_diffs: list[ResourceDiff]

    @property
    def has_diff(self) -> bool:
        return any(r.has_diff for r in self.resource_diffs)


# ---------------------------------------------------------------------------
# Core diff computation
# ---------------------------------------------------------------------------


def compute_diff(left: AccessMap, right: AccessMap) -> list[PrincipalDiff]:
    """Return a list of PrincipalDiff covering the union of both maps."""
    all_principals = sorted(set(left) | set(right))
    result: list[PrincipalDiff] = []

    for principal in all_principals:
        left_resources = left.get(principal, {})
        right_resources = right.get(principal, {})
        all_resources = sorted(set(left_resources) | set(right_resources))

        resource_diffs: list[ResourceDiff] = []
        for res in all_resources:
            # Compute effective net-allow for each side by folding in any
            # broader/wildcard resource entries that cover this resource.
            left_effective = _effective_net_allow(res, left_resources)
            right_effective = _effective_net_allow(res, right_resources)

            # Build synthetic ResourceAccess objects that carry the resolved
            # effective permissions so ResourceDiff can diff them cleanly.
            left_ra_eff = ResourceAccess()
            left_ra_eff.allow = set(left_effective)

            right_ra_eff = ResourceAccess()
            right_ra_eff.allow = set(right_effective)

            # Only include this resource entry in the diff when it was
            # explicitly listed in at least one side (avoids phantom entries
            # for resources that only match via wildcard on both sides).
            left_explicit = res in left_resources
            right_explicit = res in right_resources

            if not left_explicit and not right_explicit:
                continue  # shouldn't happen, but guard anyway

            rd = ResourceDiff(
                resource=res,
                left_ra=left_ra_eff if left_explicit or left_effective else None,
                right_ra=right_ra_eff if right_explicit or right_effective else None,
            )
            resource_diffs.append(rd)

        result.append(PrincipalDiff(principal=principal, resource_diffs=resource_diffs))

    return result


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _supports_color(stream: TextIO) -> bool:
    return hasattr(stream, "isatty") and stream.isatty()


def render_diff(
    principal_diffs: list[PrincipalDiff],
    left_label: str,
    right_label: str,
    *,
    show_equal: bool = True,
    use_color: bool | None = None,
    stream: TextIO | None = None,
    only_changed: bool = False,
) -> None:
    """
    Write a human-readable colorized diff to *stream* (default: stdout).

    Args:
        principal_diffs: output of compute_diff()
        left_label:      label for the left side (e.g. role name)
        right_label:     label for the right side
        show_equal:      if False, suppress context (unchanged) action lines
        use_color:       force color on/off; None = auto-detect from stream
        stream:          output stream; defaults to sys.stdout
        only_changed:    if True, skip principals/resources with no diff
    """
    out = stream or sys.stdout
    color = use_color if use_color is not None else _supports_color(out)

    separator = "─" * 60

    # Header
    out.write(_color(f"--- {left_label}\n", RED + BOLD, use_color=color))
    out.write(_color(f"+++ {right_label}\n", GREEN + BOLD, use_color=color))
    out.write(f"{separator}\n\n")

    found_any_diff = False

    for pd in principal_diffs:
        if only_changed and not pd.has_diff:
            continue

        out.write(
            _color(f"Principal: {pd.principal}\n", BOLD + CYAN, use_color=color)
        )

        for rd in pd.resource_diffs:
            if only_changed and not rd.has_diff:
                continue

            # Resource line: mark entirely added/removed resources distinctly
            if rd.left_ra is None:
                res_prefix = _color("  [+] Resource:", GREEN + BOLD, use_color=color)
            elif rd.right_ra is None:
                res_prefix = _color("  [-] Resource:", RED + BOLD, use_color=color)
            else:
                res_prefix = _color("      Resource:", BOLD, use_color=color)

            out.write(f"{res_prefix} {rd.resource}\n")

            for ad in rd.action_diffs:
                if ad.kind == ChangeKind.EQUAL:
                    if show_equal:
                        line = f"          {ad.action}"
                        out.write(_color(line, DIM, use_color=color) + "\n")
                elif ad.kind == ChangeKind.ADDED:
                    found_any_diff = True
                    line = f"       [+] {ad.action}"
                    out.write(_color(line, GREEN, use_color=color) + "\n")
                else:  # REMOVED
                    found_any_diff = True
                    line = f"       [-] {ad.action}"
                    out.write(_color(line, RED, use_color=color) + "\n")

        out.write("\n")

    if not found_any_diff:
        out.write(_color("No differences found.\n", BOLD, use_color=color))
