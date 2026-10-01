from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from ettp.sensitive import SensitiveCategory, SensitiveMatch, redact_text


@given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=100))
def test_redaction_is_deterministic(value: str) -> None:
    if not value:
        return
    match = SensitiveMatch(SensitiveCategory.SENSITIVE_FIELD, "field", 0, len(value))

    assert redact_text(value, (match,)) == "[REDACTED]"


@given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=100))
def test_redaction_does_not_mutate_strings(value: str) -> None:
    if not value:
        return
    match = SensitiveMatch(SensitiveCategory.SENSITIVE_FIELD, "field", 0, len(value))
    original = value

    redact_text(value, (match,))

    assert value == original
