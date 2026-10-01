"""Registered-tool reference policy."""

from collections.abc import Iterable

from ettp.policy.policy import Condition, Policy
from ettp.protocol import Effect


def create_registered_tool_policy(registered_tools: Iterable[str]) -> Policy:
    """Create an allow policy for a stable set of registered tool targets."""
    tool_values = tuple(sorted(set(registered_tools)))
    if not tool_values:
        raise ValueError("registered tool policy requires at least one tool")
    return Policy(
        id="unregistered_tool.registered",
        name="Registered tool",
        version="1",
        effect=Effect.ALLOW,
        conditions=[
            Condition(field="action.type", operator="equals", value="TOOL_CALL"),
            Condition(field="action.target", operator="in", value=list(tool_values)),
        ],
    )
