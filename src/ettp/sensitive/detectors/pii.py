"""Bounded PII pattern detector for email, phone, and IP values."""

import re
from typing import Any

from ..detector import iter_string_values
from ..match import SensitiveMatch
from ..types import SensitiveCategory


class PIIDetector:
    """Recognize explicitly supported PII-shaped strings, not all PII."""

    detector_id = "pii.patterns"
    categories = frozenset({SensitiveCategory.PII})
    _PATTERNS = (
        ("email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
        ("phone", re.compile(r"(?<!\d)(?:\+?\d[\d ().-]{7,}\d)(?!\d)")),
        ("ip_address", re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")),
    )

    def detect(self, value: Any, *, field: str = "") -> tuple[SensitiveMatch, ...]:
        matches: list[SensitiveMatch] = []
        for path, text in iter_string_values(value, field=field):
            for kind, pattern in self._PATTERNS:
                for found in pattern.finditer(text):
                    if kind == "ip_address" and any(
                        int(part) > 255 for part in found.group().split(".")
                    ):
                        continue
                    matches.append(
                        SensitiveMatch(
                            SensitiveCategory.PII,
                            self.detector_id,
                            found.start(),
                            found.end(),
                            field=path,
                            normalized_length=len(found.group()),
                            metadata=(("kind", kind),),
                        )
                    )
        return tuple(sorted(matches, key=SensitiveMatch.sort_key))
