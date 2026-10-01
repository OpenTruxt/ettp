"""Known-format and configurable API-key detector."""

import re
from typing import Any

from ..detector import iter_string_values
from ..match import SensitiveMatch
from ..types import SensitiveCategory


class APIKeyDetector:
    """Detect supported provider-style key prefixes and generic configured keys."""

    detector_id = "api_key.patterns"
    categories = frozenset({SensitiveCategory.API_KEY})
    _PATTERN = re.compile(r"\b(?:sk_(?:live|test)_[A-Za-z0-9]{12,}|AKIA[0-9A-Z]{16})\b")

    def detect(self, value: Any, *, field: str = "") -> tuple[SensitiveMatch, ...]:
        matches: list[SensitiveMatch] = []
        for path, text in iter_string_values(value, field=field):
            for found in self._PATTERN.finditer(text):
                matches.append(
                    SensitiveMatch(
                        SensitiveCategory.API_KEY,
                        self.detector_id,
                        found.start(),
                        found.end(),
                        field=path,
                        normalized_length=len(found.group()),
                    )
                )
        return tuple(sorted(matches, key=SensitiveMatch.sort_key))
