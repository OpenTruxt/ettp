from __future__ import annotations

from ettp.sensitive import SensitiveCategory, redact_text
from ettp.sensitive.detectors import APIKeyDetector, PIIDetector


def test_detector_matches_never_contain_raw_secret_values() -> None:
    secret = "sk_live_abcdefghijklmnop"
    matches = APIKeyDetector().detect(secret)

    assert matches
    serialized = repr(matches)
    assert secret not in serialized


def test_redaction_removes_complete_secret_span() -> None:
    secret = "sk_live_abcdefghijklmnop"
    value = f"authorization={secret}"
    match = APIKeyDetector().detect(value)[0]

    redacted = redact_text(value, (match,))

    assert secret not in redacted
    assert redacted == "authorization=[REDACTED]"


def test_multiple_pii_matches_have_stable_order() -> None:
    value = "alice@example.com and bob@example.org"
    matches = PIIDetector().detect(value)

    assert [match.start for match in matches] == sorted(match.start for match in matches)
    assert all(match.category is SensitiveCategory.PII for match in matches)
