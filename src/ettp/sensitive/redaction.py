"""Deterministic redaction for sensitive matches."""

from collections.abc import Mapping
from typing import Any

from ettp.actions import Action

from .match import SensitiveMatch

REDACTED_VALUE = "[REDACTED]"


def redact_action(action: Action, matches: tuple[SensitiveMatch, ...]) -> Action:
    """Return an action copy with sensitive arguments redacted."""
    return action.model_copy(
        update={"arguments": redact(action.arguments, matches, field="arguments")}
    )


def redact_text(value: str, matches: tuple[SensitiveMatch, ...]) -> str:
    """Replace all overlapping text matches as complete ranges, right to left."""
    selected = _merge_ranges(matches)
    result = value
    for start, end in reversed(selected):
        result = f"{result[:start]}{REDACTED_VALUE}{result[end:]}"
    return result


def redact(value: Any, matches: tuple[SensitiveMatch, ...], *, field: str = "") -> Any:
    """Return a redacted copy of nested data without mutating the input."""
    by_field: dict[str, list[SensitiveMatch]] = {}
    for match in matches:
        if match.field is not None:
            by_field.setdefault(match.field, []).append(match)
    return _redact_value(value, by_field, field)


def _redact_value(value: Any, by_field: dict[str, list[SensitiveMatch]], field: str) -> Any:
    if isinstance(value, str):
        return redact_text(value, tuple(by_field.get(field, ())))
    if isinstance(value, Mapping):
        return {
            key: _redact_value(item, by_field, f"{field}.{key}" if field else str(key))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [
            _redact_value(item, by_field, f"{field}[{index}]") for index, item in enumerate(value)
        ]
    if isinstance(value, tuple):
        return tuple(
            _redact_value(item, by_field, f"{field}[{index}]") for index, item in enumerate(value)
        )
    return value


def _merge_ranges(matches: tuple[SensitiveMatch, ...]) -> tuple[tuple[int, int], ...]:
    ranges = sorted((match.start, match.end) for match in matches)
    merged: list[tuple[int, int]] = []
    for start, end in ranges:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return tuple(merged)
