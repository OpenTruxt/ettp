"""Structured credential-field detector."""

from typing import Any

from ..detector import iter_string_values
from ..match import SensitiveMatch
from ..types import SensitiveCategory


class CredentialDetector:
    """Detect values under credential-shaped structured fields."""

    detector_id = "credential.fields"
    categories = frozenset({SensitiveCategory.CREDENTIAL})
    _FIELD_NAMES = frozenset(
        {"password", "passwd", "passphrase", "authorization", "private_key", "credential"}
    )

    def detect(self, value: Any, *, field: str = "") -> tuple[SensitiveMatch, ...]:
        matches: list[SensitiveMatch] = []
        for path, text in iter_string_values(value, field=field):
            name = path.rsplit(".", 1)[-1].lower()
            if name in self._FIELD_NAMES and text:
                matches.append(
                    SensitiveMatch(
                        SensitiveCategory.CREDENTIAL,
                        self.detector_id,
                        0,
                        len(text),
                        field=path,
                        normalized_length=len(text),
                    )
                )
        return tuple(sorted(matches, key=SensitiveMatch.sort_key))
