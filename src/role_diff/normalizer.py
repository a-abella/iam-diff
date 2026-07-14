"""
Policy normalizer.

Collapses a list of AccessStatements into a canonical access map:

    AccessMap = {
        principal: {
            resource: {
                "allow": set[str],   # net-allowed actions
                "deny":  set[str],   # explicit denies
            }
        }
    }

Deny always wins over Allow (standard IAM evaluation logic).
NotAction / NotResource are expanded into a note on the entry rather than
fully enumerated (full enumeration would require the complete AWS action
namespace), but we preserve them so the diff can surface them clearly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from role_diff.fetcher import AccessStatement


@dataclass
class ResourceAccess:
    """Net access for one (principal, resource) pair."""

    allow: set[str] = field(default_factory=set)
    deny: set[str] = field(default_factory=set)
    # Raw not_action / not_resource annotations preserved for display
    not_action_allow: set[str] = field(default_factory=set)
    not_action_deny: set[str] = field(default_factory=set)
    not_resource_actions: set[str] = field(default_factory=set)

    @property
    def net_allow(self) -> frozenset[str]:
        """Effective allow = Allow - Deny."""
        return frozenset(self.allow - self.deny)


# principal -> resource -> ResourceAccess
AccessMap = dict[str, dict[str, ResourceAccess]]


def _get_or_create(access_map: AccessMap, principal: str, resource: str) -> ResourceAccess:
    if principal not in access_map:
        access_map[principal] = {}
    if resource not in access_map[principal]:
        access_map[principal][resource] = ResourceAccess()
    return access_map[principal][resource]


def normalize(statements: list[AccessStatement]) -> AccessMap:
    """
    Build an AccessMap from a flat list of AccessStatements.

    Processing order:
    1. Apply all Allow statements.
    2. Apply all Deny statements (Deny overrides Allow).
    """
    access_map: AccessMap = {}

    # Two-pass: Allows first, then Denies
    for pass_effect in ("Allow", "Deny"):
        for stmt in statements:
            if stmt.effect.lower() != pass_effect.lower():
                continue
            for principal in stmt.principals:
                for resource in stmt.resources:
                    ra = _get_or_create(access_map, principal, resource)
                    if stmt.not_action:
                        # "Everything except these actions"
                        target_set = ra.not_action_allow if not stmt.is_deny else ra.not_action_deny
                        target_set.update(stmt.actions)
                    elif stmt.not_resource:
                        ra.not_resource_actions.update(stmt.actions)
                    elif stmt.is_deny:
                        ra.deny.update(stmt.actions)
                    else:
                        ra.allow.update(stmt.actions)

    return access_map


def to_sorted_dict(access_map: AccessMap) -> dict[str, dict[str, dict[str, Any]]]:
    """
    Convert an AccessMap to a fully serialisable, sorted plain dict for
    display / comparison purposes.

    Shape:
        {
            principal: {
                resource: {
                    "allow": [...sorted...],
                    "deny":  [...sorted...],
                    "not_action_allow": [...],
                    "not_action_deny":  [...],
                    "not_resource_actions": [...],
                }
            }
        }
    """
    result: dict[str, dict[str, dict[str, Any]]] = {}
    for principal in sorted(access_map):
        result[principal] = {}
        for resource in sorted(access_map[principal]):
            ra = access_map[principal][resource]
            result[principal][resource] = {
                "allow": sorted(ra.allow),
                "deny": sorted(ra.deny),
                "not_action_allow": sorted(ra.not_action_allow),
                "not_action_deny": sorted(ra.not_action_deny),
                "not_resource_actions": sorted(ra.not_resource_actions),
            }
    return result
