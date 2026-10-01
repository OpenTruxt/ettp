"""Controlled condition operators for deterministic policy evaluation."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from ettp.policy.context import EvaluationContext
from ettp.policy.policy import Condition
from ettp.policy.resolver import FieldResolutionError, resolve_field


class ConditionOperator(StrEnum):
    """Operators supported by the Sprint 3 condition evaluator."""

    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    IN = "in"
    NOT_IN = "not_in"
    GREATER_THAN = "greater_than"
    GREATER_THAN_OR_EQUAL = "greater_than_or_equal"
    LESS_THAN = "less_than"
    LESS_THAN_OR_EQUAL = "less_than_or_equal"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"


class ConditionEvaluationError(ValueError):
    """Raised when a condition cannot be evaluated safely."""


@dataclass(frozen=True)
class ConditionResult:
    """Deterministic result and explanation for one condition."""

    matched: bool
    explanation: str
    children: tuple["ConditionResult", ...] = ()


class ConditionEvaluator:
    """Evaluate the closed condition language against an evaluation context."""

    def evaluate(self, condition: Condition, context: EvaluationContext) -> ConditionResult:
        if condition.all is not None:
            children = tuple(self.evaluate(child, context) for child in condition.all)
            matched = all(child.matched for child in children)
            return ConditionResult(
                matched, f"all conditions {'matched' if matched else 'did not match'}", children
            )
        if condition.any is not None:
            children = tuple(self.evaluate(child, context) for child in condition.any)
            matched = any(child.matched for child in children)
            return ConditionResult(
                matched, f"any condition {'matched' if matched else 'did not match'}", children
            )
        if condition.not_condition is not None:
            child = self.evaluate(condition.not_condition, context)
            return ConditionResult(
                not child.matched,
                f"not condition {'matched' if not child.matched else 'did not match'}",
                (child,),
            )
        if condition.field is None or condition.operator is None:
            raise ConditionEvaluationError("Condition is missing its leaf fields")
        try:
            operator = ConditionOperator(condition.operator)
        except ValueError as error:
            raise ConditionEvaluationError(
                f"Unsupported condition operator: {condition.operator!r}"
            ) from error

        try:
            found, actual = resolve_field(context, condition.field)
        except FieldResolutionError as error:
            raise ConditionEvaluationError(str(error)) from error

        matched = self._apply(operator, found, actual, condition.value)
        status = "matched" if matched else "did not match"
        return ConditionResult(
            matched=matched,
            explanation=(
                f"{condition.field} {condition.operator} {condition.value!r}; condition {status}"
            ),
        )

    @staticmethod
    def _apply(operator: ConditionOperator, found: bool, actual: Any, expected: Any) -> bool:
        if operator is ConditionOperator.EXISTS:
            return found
        if operator is ConditionOperator.NOT_EXISTS:
            return not found
        if not found:
            return False
        if operator is ConditionOperator.EQUALS:
            return bool(actual == expected)
        if operator is ConditionOperator.NOT_EQUALS:
            return bool(actual != expected)
        if operator is ConditionOperator.CONTAINS:
            try:
                return expected in actual
            except TypeError:
                return False
        if operator is ConditionOperator.IN:
            try:
                return actual in expected
            except TypeError:
                return False
        if operator is ConditionOperator.NOT_IN:
            try:
                return actual not in expected
            except TypeError:
                return False
        if operator is ConditionOperator.GREATER_THAN:
            return ConditionEvaluator._compare(actual, expected, lambda left, right: left > right)
        if operator is ConditionOperator.GREATER_THAN_OR_EQUAL:
            return ConditionEvaluator._compare(actual, expected, lambda left, right: left >= right)
        if operator is ConditionOperator.LESS_THAN:
            return ConditionEvaluator._compare(actual, expected, lambda left, right: left < right)
        if operator is ConditionOperator.LESS_THAN_OR_EQUAL:
            return ConditionEvaluator._compare(actual, expected, lambda left, right: left <= right)
        raise ConditionEvaluationError(f"Unhandled condition operator: {operator.value!r}")

    @staticmethod
    def _compare(actual: Any, expected: Any, operation: Any) -> bool:
        try:
            return bool(operation(actual, expected))
        except TypeError:
            return False
