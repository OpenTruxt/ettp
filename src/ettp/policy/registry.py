"""Deterministic in-memory policy registry."""

from ettp.policy.policy import Policy


class PolicyRegistryError(ValueError):
    """Raised when a policy registry operation violates its contract."""


class PolicyRegistry:
    """Store one active policy version per stable policy identifier."""

    def __init__(self) -> None:
        self._policies: dict[str, Policy] = {}
        self._disabled: set[str] = set()

    def register(self, policy: Policy) -> None:
        if policy.id in self._policies:
            raise PolicyRegistryError(f"Policy is already registered: {policy.id!r}")
        self._policies[policy.id] = policy

    def get(self, policy_id: str) -> Policy:
        try:
            return self._policies[policy_id]
        except KeyError as error:
            raise PolicyRegistryError(f"Unknown policy: {policy_id!r}") from error

    def remove(self, policy_id: str) -> Policy:
        policy = self.get(policy_id)
        del self._policies[policy_id]
        self._disabled.discard(policy_id)
        return policy

    def enable(self, policy_id: str) -> None:
        self.get(policy_id)
        self._disabled.discard(policy_id)

    def disable(self, policy_id: str) -> None:
        self.get(policy_id)
        self._disabled.add(policy_id)

    def list(self, *, enabled_only: bool = True) -> tuple[Policy, ...]:
        policies = (
            policy
            for policy_id, policy in self._policies.items()
            if not enabled_only or policy_id not in self._disabled
        )
        return tuple(sorted(policies, key=lambda policy: (policy.id, policy.version)))
