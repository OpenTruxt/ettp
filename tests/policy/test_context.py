from __future__ import annotations

import pytest
from pydantic import ValidationError

from ettp import Action, Entity
from ettp.policy import ConditionOperator, EvaluationContext


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


def test_evaluation_context_uses_existing_protocol_models() -> None:
    context = make_context()

    assert context.entity.id == context.action.entity_id
    assert context.trust_context == {}
    assert context.environment == {}


def test_evaluation_context_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        EvaluationContext(**make_context().model_dump(), unexpected=True)


def test_condition_operators_are_closed_and_protocol_named() -> None:
    assert ConditionOperator.GREATER_THAN.value == "greater_than"
    assert ConditionOperator.NOT_EXISTS.value == "not_exists"
