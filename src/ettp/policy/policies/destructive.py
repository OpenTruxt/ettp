"""Destructive-operation reference policy."""

from collections.abc import Iterable

from ettp.policy.policy import Condition, Policy
from ettp.protocol import Effect


def create_destructive_policy(
    operations: Iterable[str] = ("delete", "destroy", "terminate"),
) -> Policy:
    """Create a block policy for explicitly listed destructive operations."""
    operation_values = tuple(sorted(set(operations)))
    if not operation_values:
        raise ValueError("destructive policy requires at least one operation")
    return Policy(
        id="destructive.operation",
        name="Destructive operation",
        version="1",
        effect=Effect.BLOCK,
        conditions=[
            Condition(field="action.operation", operator="in", value=list(operation_values))
        ],
    )
