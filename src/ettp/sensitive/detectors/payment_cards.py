"""Payment-card pattern detector with deterministic Luhn validation."""

import re
from typing import Any

from ..detector import iter_string_values
from ..match import SensitiveMatch
from ..types import SensitiveCategory


class PaymentCardDetector:
    """Recognize plausible card-number patterns, not confirmed payment cards."""

    detector_id = "payment_card.pattern"
    categories = frozenset({SensitiveCategory.PAYMENT_CARD})
    _PATTERN = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")

    def detect(self, value: Any, *, field: str = "") -> tuple[SensitiveMatch, ...]:
        matches: list[SensitiveMatch] = []
        for path, text in iter_string_values(value, field=field):
            for found in self._PATTERN.finditer(text):
                digits = re.sub(r"[ -]", "", found.group())
                if 13 <= len(digits) <= 19 and self._luhn_valid(digits):
                    matches.append(
                        SensitiveMatch(
                            SensitiveCategory.PAYMENT_CARD,
                            self.detector_id,
                            found.start(),
                            found.end(),
                            field=path,
                            normalized_length=len(digits),
                        )
                    )
        return tuple(sorted(matches, key=SensitiveMatch.sort_key))

    @staticmethod
    def _luhn_valid(digits: str) -> bool:
        checksum = 0
        parity = len(digits) % 2
        for index, digit in enumerate(digits):
            value = int(digit)
            if index % 2 == parity:
                value = value * 2
                if value > 9:
                    value -= 9
            checksum += value
        return checksum % 10 == 0
