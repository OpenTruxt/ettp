from __future__ import annotations

import pytest

from ettp import Action, Entity
from ettp.policy import Condition, EvaluationContext
from ettp.policy.condition import ConditionEvaluationError, ConditionEvaluator
from ettp.policy.resolver import FieldResolutionError, resolve_field


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


def test_resolve_protocol_model_field() -> None:
    found, value = resolve_field(make_context(), "action.arguments.amount")

    assert found is True
    assert value == 100


def test_resolve_missing_field_without_guessing() -> None:
    found, value = resolve_field(make_context(), "action.arguments.currency")

    assert found is False
    assert value is None


def test_resolve_rejects_unknown_roots_and_private_paths() -> None:
    context = make_context()

    with pytest.raises(FieldResolutionError):
        resolve_field(context, "settings.secret")
    with pytest.raises(FieldResolutionError):
        resolve_field(context, "action.__class__")


def test_resolve_optional_resource_as_missing() -> None:
    context = EvaluationContext(
        entity=make_context().entity,
        action=make_context().action,
    )

    found, value = resolve_field(context, "resource.id")

    assert found is False
    assert value is None


def test_condition_evaluator_supports_explicit_comparison() -> None:
    condition = Condition(
        field="action.arguments.amount",
        operator="greater_than",
        value=50,
    )

    result = ConditionEvaluator().evaluate(condition, make_context())

    assert result.matched is True
    assert "condition matched" in result.explanation


def test_condition_evaluator_handles_missing_fields_explicitly() -> None:
    condition = Condition(field="action.arguments.currency", operator="exists", value=True)

    result = ConditionEvaluator().evaluate(condition, make_context())

    assert result.matched is False


def test_condition_evaluator_rejects_unknown_operators() -> None:
    condition = Condition(field="action.type", operator="eval", value="anything")

    with pytest.raises(ConditionEvaluationError):
        ConditionEvaluator().evaluate(condition, make_context())


def test_condition_evaluator_supports_all_any_and_not_groups() -> None:
    context = make_context()
    evaluator = ConditionEvaluator()

    all_result = evaluator.evaluate(
        Condition(
            all=[
                Condition(field="action.operation", operator="equals", value="refund"),
                Condition(field="action.arguments.amount", operator="greater_than", value=50),
            ]
        ),
        context,
    )
    any_result = evaluator.evaluate(
        Condition(
            any=[
                Condition(field="action.operation", operator="equals", value="delete"),
                Condition(field="action.operation", operator="equals", value="refund"),
            ]
        ),
        context,
    )
    not_result = evaluator.evaluate(
        Condition(
            not_condition=Condition(field="action.operation", operator="equals", value="delete")
        ),
        context,
    )

    assert all_result.matched is True
    assert any_result.matched is True
    assert not_result.matched is True
