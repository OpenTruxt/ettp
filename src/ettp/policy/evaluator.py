"""Deterministic policy-level evaluation."""

from dataclasses import dataclass

from ettp.policy.condition import ConditionEvaluator, ConditionResult
from ettp.policy.context import EvaluationContext
from ettp.policy.policy import Condition, Policy
from ettp.protocol import Effect


@dataclass(frozen=True)
class PolicyEvaluation:
    """The condition results and outcome for one policy."""

    policy_id: str
    policy_version: str
    effect: Effect
    priority: int
    matched: bool
    condition_results: tuple[ConditionResult, ...]
    explanation: str

    @property
    def matched_explanations(self) -> tuple[str, ...]:
        return tuple(result.explanation for result in self._flatten() if result.matched)

    @property
    def failed_explanations(self) -> tuple[str, ...]:
        return tuple(result.explanation for result in self._flatten() if not result.matched)

    def _flatten(self) -> tuple[ConditionResult, ...]:
        flattened: list[ConditionResult] = []
        for result in self.condition_results:
            flattened.extend(_flatten_result(result))
        return tuple(flattened)


def _flatten_result(result: ConditionResult) -> tuple[ConditionResult, ...]:
    if not result.children:
        return (result,)
    flattened: list[ConditionResult] = [result]
    for child in result.children:
        flattened.extend(_flatten_result(child))
    return tuple(flattened)


class PolicyEvaluator:
    """Evaluate every condition in a policy using deterministic AND semantics."""

    def __init__(self, condition_evaluator: ConditionEvaluator | None = None) -> None:
        self._condition_evaluator = condition_evaluator or ConditionEvaluator()

    def evaluate(self, policy: Policy, context: EvaluationContext) -> PolicyEvaluation:
        results = tuple(
            self._evaluate_condition(condition, context) for condition in policy.conditions
        )
        matched = all(result.matched for result in results)
        status = "matched" if matched else "did not match"
        return PolicyEvaluation(
            policy_id=policy.id,
            policy_version=policy.version,
            priority=policy.priority or 0,
            effect=policy.effect,
            matched=matched,
            condition_results=results,
            explanation=f"Policy {policy.id!r} {status}; "
            f"{sum(result.matched for result in results)}/{len(results)} conditions matched",
        )

    def _evaluate_condition(
        self, condition: Condition, context: EvaluationContext
    ) -> ConditionResult:
        return self._condition_evaluator.evaluate(condition, context)
