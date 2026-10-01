"""Normalized sensitive-data detection results."""

from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Any

from .types import SensitiveCategory


@dataclass(frozen=True)
class SensitiveMatch:
    """A deterministic match that intentionally does not retain the raw secret."""

    category: SensitiveCategory
    detector_id: str
    start: int
    end: int
    field: str | None = None
    confidence: float = 1.0
    normalized_length: int | None = None
    fingerprint: str | None = None
    metadata: tuple[tuple[str, Any], ...] = dataclass_field(default_factory=tuple)

    def __post_init__(self) -> None:
        if self.start < 0 or self.end <= self.start:
            raise ValueError("sensitive match range must be non-empty and non-negative")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("sensitive match confidence must be between 0 and 1")
        if self.normalized_length is not None and self.normalized_length <= 0:
            raise ValueError("normalized match length must be positive")

    @property
    def length(self) -> int:
        """Return the matched source range length."""
        return self.end - self.start

    def sort_key(self) -> tuple[int, int, str, str, str]:
        """Return the stable ordering key for collections of matches."""
        return (
            self.start,
            self.end,
            self.category.value,
            self.detector_id,
            self.field or "",
        )
