"""Deterministic conflict resolution for matched policy evaluations."""

from dataclasses import dataclass
from typing import ClassVar

from ettp.policy.evaluator import PolicyEvaluation
from ettp.protocol import Effect


@dataclass(frozen=True)
class ResolvedOutcome:
    """The selected matched policy evaluation."""

    evaluation: PolicyEvaluation


class PrecedenceResolver:
    """Resolve matches by effect severity, then stable policy identity."""

    _EFFECT_PRIORITY: ClassVar[dict[Effect, int]] = {
        Effect.BLOCK: 4,
        Effect.REQUIRE_APPROVAL: 3,
        Effect.REDACT: 2,
        Effect.ALLOW: 1,
    }

    def resolve(self, evaluations: tuple[PolicyEvaluation, ...]) -> ResolvedOutcome | None:
        matches = tuple(evaluation for evaluation in evaluations if evaluation.matched)
        if not matches:
            return None
        selected = max(
            matches,
            key=lambda evaluation: (
                evaluation.priority,
                self._EFFECT_PRIORITY[evaluation.effect],
                evaluation.policy_id,
                evaluation.policy_version,
            ),
        )
        return ResolvedOutcome(evaluation=selected)
