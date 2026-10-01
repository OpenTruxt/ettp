from __future__ import annotations

from ettp import Action, Entity
from ettp.policy import Condition, EvaluationContext, Policy
from ettp.policy.evaluator import PolicyEvaluator


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


def test_policy_evaluator_requires_all_conditions() -> None:
    policy = Policy(
        id="policy.refund",
        version="1",
        effect="ALLOW",
        conditions=[
            Condition(field="action.operation", operator="equals", value="refund"),
            Condition(field="action.arguments.amount", operator="greater_than", value=50),
        ],
    )

    result = PolicyEvaluator().evaluate(policy, make_context())

    assert result.matched is True
    assert len(result.condition_results) == 2
    assert "2/2" in result.explanation


def test_policy_evaluator_explains_failed_conditions() -> None:
    policy = Policy(
        id="policy.refund",
        version="1",
        effect="ALLOW",
        conditions=[
            Condition(field="action.operation", operator="equals", value="delete"),
        ],
    )

    result = PolicyEvaluator().evaluate(policy, make_context())

    assert result.matched is False
    assert result.condition_results[0].matched is False
    assert "did not match" in result.condition_results[0].explanation


def test_policy_with_no_conditions_matches_deterministically() -> None:
    policy = Policy(id="policy.empty", version="1", effect="BLOCK", conditions=[])

    result = PolicyEvaluator().evaluate(policy, make_context())

    assert result.matched is True
    assert result.explanation.endswith("0/0 conditions matched")
