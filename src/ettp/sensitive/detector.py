"""Detector interface and common detection helpers."""

from collections.abc import Mapping
from typing import Any, Protocol

from .match import SensitiveMatch
from .types import SensitiveCategory


class SensitiveDetector(Protocol):
    """Protocol implemented by deterministic sensitive-data detectors."""

    detector_id: str
    categories: frozenset[SensitiveCategory]

    def detect(self, value: Any, *, field: str = "") -> tuple[SensitiveMatch, ...]:
        """Return deterministic, normalized matches without mutating the input."""


def iter_string_values(value: Any, *, field: str = "") -> tuple[tuple[str, str], ...]:
    """Flatten strings in mappings/sequences with controlled path semantics."""
    if isinstance(value, str):
        return ((field, value),)
    if isinstance(value, Mapping):
        values: list[tuple[str, str]] = []
        for key in sorted(value, key=str):
            path = f"{field}.{key}" if field else str(key)
            values.extend(iter_string_values(value[key], field=path))
        return tuple(values)
    if isinstance(value, (list, tuple)):
        values = []
        for index, item in enumerate(value):
            values.extend(iter_string_values(item, field=f"{field}[{index}]"))
        return tuple(values)
    return ()
