"""Financial reference policies."""

from ettp.policy.policy import Condition, Policy
from ettp.protocol import Effect


def create_high_value_policy(amount_threshold: int | float) -> Policy:
    """Create a policy requiring approval above an amount threshold."""
    return Policy(
        id="financial.high_value",
        name="High-value financial action",
        version="1",
        effect=Effect.REQUIRE_APPROVAL,
        conditions=[
            Condition(
                field="action.arguments.amount",
                operator="greater_than",
                value=amount_threshold,
            )
        ],
    )
