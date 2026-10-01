"""Policy response layer for normalized sensitive-data matches."""

from dataclasses import dataclass

from ettp.protocol import Effect

from .match import SensitiveMatch
from .types import SensitiveCategory


@dataclass(frozen=True)
class SensitiveDataPolicy:
    """Declarative response for one or more sensitive-data categories."""

    policy_id: str
    version: str
    categories: frozenset[SensitiveCategory]
    effect: Effect

    def __post_init__(self) -> None:
        if not self.policy_id or not self.version or not self.categories:
            raise ValueError("sensitive-data policies require ID, version, and categories")
        if self.effect not in {Effect.BLOCK, Effect.REDACT}:
            raise ValueError("sensitive-data policies only support BLOCK or REDACT")


@dataclass(frozen=True)
class SensitivePolicyResult:
    """The selected sensitive-data response and non-secret explanation data."""

    policy: SensitiveDataPolicy
    matches: tuple[SensitiveMatch, ...]

    @property
    def reason(self) -> str:
        categories = ", ".join(sorted({match.category.value for match in self.matches}))
        detectors = ", ".join(sorted({match.detector_id for match in self.matches}))
        fields = sorted({match.field for match in self.matches if match.field})
        field_text = ", ".join(fields) if fields else "unstructured"
        return (
            f"Sensitive data detected: categories={categories}; detectors={detectors}; "
            f"fields={field_text}"
        )


def select_sensitive_policy(
    matches: tuple[SensitiveMatch, ...],
    policies: tuple[SensitiveDataPolicy, ...],
) -> SensitivePolicyResult | None:
    """Select the strongest matching response independent of registration order."""
    applicable = [
        policy
        for policy in policies
        if any(match.category in policy.categories for match in matches)
    ]
    if not applicable:
        return None
    selected = max(
        applicable,
        key=lambda policy: (
            2 if policy.effect is Effect.BLOCK else 1,
            policy.policy_id,
            policy.version,
        ),
    )
    selected_matches = tuple(match for match in matches if match.category in selected.categories)
    return SensitivePolicyResult(selected, selected_matches)
