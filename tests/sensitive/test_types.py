from __future__ import annotations

import pytest

from ettp.sensitive import DetectorRegistry, SensitiveCategory, SensitiveMatch


def test_sensitive_match_never_requires_raw_value() -> None:
    match = SensitiveMatch(
        category=SensitiveCategory.API_KEY,
        detector_id="api_key.generic",
        start=2,
        end=10,
        field="authorization",
        normalized_length=8,
    )

    assert match.length == 8
    assert not hasattr(match, "matched_value")


def test_sensitive_match_rejects_invalid_ranges_and_confidence() -> None:
    with pytest.raises(ValueError):
        SensitiveMatch(SensitiveCategory.PII, "pii.email", 4, 4)
    with pytest.raises(ValueError):
        SensitiveMatch(SensitiveCategory.PII, "pii.email", 1, 2, confidence=2.0)


def test_detector_registry_is_sorted_and_controls_lifecycle() -> None:
    class Detector:
        detector_id = "z.detector"
        categories = frozenset({SensitiveCategory.PII})

        def detect(self, value: object, *, field: str = "") -> tuple[SensitiveMatch, ...]:
            return ()

    registry = DetectorRegistry()
    registry.register(Detector())
    registry.disable("z.detector")

    assert registry.list() == ()
    assert registry.list(enabled_only=False)[0].detector_id == "z.detector"
