"""Configurable structured-field detector."""

from collections.abc import Iterable
from typing import Any

from ..detector import iter_string_values
from ..match import SensitiveMatch
from ..types import SensitiveCategory


class SensitiveFieldDetector:
    """Detect configured dotted fields in nested mappings and sequences."""

    detector_id = "sensitive_field.configurable"
    categories = frozenset({SensitiveCategory.SENSITIVE_FIELD})

    def __init__(self, fields: Iterable[str]) -> None:
        self._fields = frozenset(field for field in fields if field)
        if not self._fields:
            raise ValueError("sensitive field detector requires at least one field")

    def detect(self, value: Any, *, field: str = "") -> tuple[SensitiveMatch, ...]:
        matches: list[SensitiveMatch] = []
        for path, text in iter_string_values(value, field=field):
            if path in self._fields or path.rsplit(".", 1)[-1] in self._fields:
                matches.append(
                    SensitiveMatch(
                        SensitiveCategory.SENSITIVE_FIELD,
                        self.detector_id,
                        0,
                        len(text),
                        field=path,
                        normalized_length=len(text),
                    )
                )
        return tuple(sorted(matches, key=SensitiveMatch.sort_key))
