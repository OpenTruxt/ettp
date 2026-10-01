from __future__ import annotations

import pytest

from ettp import Action, Entity
from ettp.policy import PolicyEngine, PolicyRegistry
from ettp.policy.policies import (
    create_capability_policy,
    create_destructive_policy,
    create_high_value_policy,
    create_registered_tool_policy,
)


def make_entity(capabilities: list[str] | None = None) -> Entity:
    return Entity(
        id="ent_123",
        type="AI_AGENT",
        name="agent",
        version="1",
        capabilities=capabilities or [],
        metadata={},
        protocol_version="0.1",
    )


def make_action(
    operation: str = "refund", amount: int = 100, target: str = "refund_customer"
) -> Action:
    return Action(
        id="act_123",
        entity_id="ent_123",
        type="TOOL_CALL",
        target=target,
        operation=operation,
        arguments={"amount": amount},
    )


def evaluate(policy, *, entity=None, action=None):
    registry = PolicyRegistry()
    registry.register(policy)
    return PolicyEngine(registry).evaluate(
        entity=entity or make_entity(["refund.execute"]),
        action=action or make_action(),
    )


def test_capability_policy_allows_matching_capability() -> None:
    decision = evaluate(create_capability_policy("refund.execute", operation="refund"))

    assert decision.effect == "ALLOW"


def test_capability_policy_missing_capability_defaults_to_block() -> None:
    decision = evaluate(
        create_capability_policy("refund.execute"), entity=make_entity(), action=make_action()
    )

    assert decision.effect == "BLOCK"


def test_high_value_policy_requires_approval() -> None:
    decision = evaluate(create_high_value_policy(100), action=make_action(amount=101))

    assert decision.effect == "REQUIRE_APPROVAL"


def test_destructive_policy_blocks_delete() -> None:
    decision = evaluate(create_destructive_policy(), action=make_action(operation="delete"))

    assert decision.effect == "BLOCK"


def test_registered_tool_policy_allows_registered_target() -> None:
    decision = evaluate(create_registered_tool_policy(["refund_customer"]))

    assert decision.effect == "ALLOW"


def test_registered_tool_policy_blocks_unknown_target() -> None:
    decision = evaluate(
        create_registered_tool_policy(["refund_customer"]),
        action=make_action(target="unknown_tool"),
    )

    assert decision.effect == "BLOCK"


@pytest.mark.parametrize(
    "factory",
    [
        lambda: create_destructive_policy([]),
        lambda: create_registered_tool_policy([]),
    ],
)
def test_policy_factories_reject_empty_security_sets(factory) -> None:
    with pytest.raises(ValueError):
        factory()
