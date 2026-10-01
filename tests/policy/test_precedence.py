from __future__ import annotations

import pytest

from ettp import Action, Entity
from ettp.policy import Condition, EvaluationContext, Policy, PolicyEvaluator, PolicyRegistry
from ettp.policy.precedence import PrecedenceResolver
from ettp.policy.registry import PolicyRegistryError


def make_context() -> EvaluationContext:
    entity = Entity(
        id="ent_123",
        type="AI_AGENT",
        name="agent",
        version="1",
        capabilities=["refund.execute"],
        metadata={},
        protocol_version="0.1",
    )
    action = Action(
        id="act_123",
        entity_id="ent_123",
        type="TOOL_CALL",
        target="refund_customer",
        operation="refund",
        arguments={"amount": 100},
    )
    return EvaluationContext(entity=entity, action=action)


def make_policy(policy_id: str, effect: str, priority: int | None = None) -> Policy:
    return Policy(
        id=policy_id,
        version="1",
        effect=effect,
        priority=priority,
        conditions=[Condition(field="action.operation", operator="equals", value="refund")],
    )


def evaluate(policy: Policy):
    return PolicyEvaluator().evaluate(policy, make_context())


def test_block_wins_over_allow_independent_of_input_order() -> None:
    allow = evaluate(make_policy("policy.allow", "ALLOW"))
    block = evaluate(make_policy("policy.block", "BLOCK"))
    resolver = PrecedenceResolver()

    first = resolver.resolve((allow, block))
    second = resolver.resolve((block, allow))

    assert first is not None
    assert second is not None
    assert first.evaluation.policy_id == "policy.block"
    assert second.evaluation.policy_id == first.evaluation.policy_id


def test_explicit_priority_wins_before_effect_severity() -> None:
    low_block = evaluate(make_policy("policy.block", "BLOCK", priority=1))
    high_allow = evaluate(make_policy("policy.allow", "ALLOW", priority=2))

    result = PrecedenceResolver().resolve((low_block, high_allow))

    assert result is not None
    assert result.evaluation.policy_id == "policy.allow"


def test_registry_retrieval_is_sorted_and_duplicates_are_rejected() -> None:
    registry = PolicyRegistry()
    registry.register(make_policy("policy.b", "ALLOW"))
    registry.register(make_policy("policy.a", "ALLOW"))

    assert [policy.id for policy in registry.list()] == ["policy.a", "policy.b"]
    with pytest.raises(PolicyRegistryError):
        registry.register(make_policy("policy.a", "BLOCK"))


def test_registry_disable_excludes_policy_without_removing_it() -> None:
    registry = PolicyRegistry()
    registry.register(make_policy("policy.a", "ALLOW"))

    registry.disable("policy.a")

    assert registry.list() == ()
    assert registry.list(enabled_only=False)[0].id == "policy.a"
