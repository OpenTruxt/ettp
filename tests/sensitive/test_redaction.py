from __future__ import annotations

from ettp.sensitive import SensitiveCategory, SensitiveMatch, redact, redact_text


def match(start: int, end: int, field: str | None = None) -> SensitiveMatch:
    return SensitiveMatch(SensitiveCategory.API_KEY, "api_key.patterns", start, end, field=field)


def test_redact_text_merges_overlapping_ranges() -> None:
    value = "prefix-secret-suffix"

    assert redact_text(value, (match(7, 13), match(10, 13))) == "prefix-[REDACTED]-suffix"


def test_redact_nested_data_without_mutating_input() -> None:
    value = {"user": {"token": "synthetic-secret"}, "name": "Alice"}
    matches = (match(0, len("synthetic-secret"), "user.token"),)

    result = redact(value, matches)

    assert result == {"user": {"token": "[REDACTED]"}, "name": "Alice"}
    assert value["user"]["token"] == "synthetic-secret"


def test_redaction_is_idempotent() -> None:
    value = "email alice@example.com"
    first = redact_text(value, (match(6, 23),))

    assert redact_text(first, (match(6, 16),)) == first
