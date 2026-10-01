"""Capability reference policy."""

from ettp.policy.policy import Condition, Policy
from ettp.protocol import Effect


def create_capability_policy(required_capability: str, *, operation: str | None = None) -> Policy:
    """Create an allow policy requiring an entity capability."""
    conditions = [
        Condition(
            field="entity.capabilities",
            operator="contains",
            value=required_capability,
        )
    ]
    if operation is not None:
        conditions.append(Condition(field="action.operation", operator="equals", value=operation))
    return Policy(
        id=f"capability.{required_capability}",
        name="Required capability",
        version="1",
        effect=Effect.ALLOW,
        conditions=conditions,
    )
