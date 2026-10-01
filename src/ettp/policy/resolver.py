"""Safe resolution of protocol-approved fields for policy conditions."""

from typing import Any

from ettp.policy.context import EvaluationContext


class FieldResolutionError(ValueError):
    """Raised when a condition refers to an unsupported or unavailable field."""


_ROOT_FIELDS = frozenset({"action", "entity", "resource", "trust_context", "environment"})


def resolve_field(context: EvaluationContext, field: str) -> tuple[bool, Any]:
    """Resolve a dotted protocol field without arbitrary attribute access."""
    segments = field.split(".")
    if not field or any(not segment or segment.startswith("_") for segment in segments):
        raise FieldResolutionError(f"Invalid condition field: {field!r}")
    if segments[0] not in _ROOT_FIELDS:
        raise FieldResolutionError(f"Unsupported condition root: {segments[0]!r}")

    value: Any = getattr(context, segments[0])
    for segment in segments[1:]:
        if isinstance(value, dict):
            if segment not in value:
                return False, None
            value = value[segment]
        elif hasattr(value, segment) and not segment.startswith("_"):
            value = getattr(value, segment)
        else:
            return False, None
    return True, value
