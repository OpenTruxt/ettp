from __future__ import annotations

import json
from itertools import permutations

from hypothesis import given, settings
from hypothesis import strategies as st

from ettp import Action, Entity
from ettp.policy import Condition, Policy, PolicyEngine, PolicyRegistry


def make_entity() -> Entity:
    return Entity(
        id="ent_123",
        type="AI_AGENT",
        name="agent",
        version="1",
        capabilities=["refund.execute"],
        metadata={},
        protocol_version="0.1",
    )


def make_action() -> Action:
    return Action(
        id="act_123",
        entity_id="ent_123",
        type="TOOL_CALL",
        target="refund_customer",
        operation="refund",
        arguments={"amount": 100},
    )


def make_policy(policy_id: str, effect: str) -> Policy:
    return Policy(
        id=policy_id,
        version="1",
        effect=effect,
        conditions=[Condition(field="action.operation", operator="equals", value="refund")],
    )


POLICIES = (
    make_policy("policy.allow", "ALLOW"),
    make_policy("policy.approval", "REQUIRE_APPROVAL"),
    make_policy("policy.block", "BLOCK"),
)


@given(st.permutations(POLICIES))
@settings(deadline=None)
def test_registration_order_does_not_change_decision(policy_order: tuple[Policy, ...]) -> None:
    registry = PolicyRegistry()
    for policy in policy_order:
        registry.register(policy)

    decision = PolicyEngine(registry).evaluate(entity=make_entity(), action=make_action())

    assert decision.effect == "BLOCK"
    assert decision.policy_id == "policy.block"


def test_all_permutations_have_identical_decision_projection() -> None:
    projections = set()
    for policy_order in permutations(POLICIES):
        registry = PolicyRegistry()
        for policy in policy_order:
            registry.register(policy)
        decision = PolicyEngine(registry).evaluate(entity=make_entity(), action=make_action())
        projections.add(json.dumps(decision.model_dump(mode="json"), sort_keys=True))

    assert len(projections) == 1
