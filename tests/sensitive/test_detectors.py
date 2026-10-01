from __future__ import annotations

from ettp.sensitive.detectors import (
    APIKeyDetector,
    CredentialDetector,
    PaymentCardDetector,
    PIIDetector,
    SensitiveFieldDetector,
)


def test_pii_detector_finds_supported_patterns_and_nested_values() -> None:
    matches = PIIDetector().detect({"customer": {"email": "alice@example.com"}})

    assert [(match.field, match.metadata) for match in matches] == [
        ("customer.email", (("kind", "email"),))
    ]


def test_credential_detector_avoids_ordinary_prose() -> None:
    assert CredentialDetector().detect("The password policy changed.") == ()
    matches = CredentialDetector().detect({"password": "synthetic-secret"})

    assert len(matches) == 1
    assert matches[0].field == "password"


def test_api_key_detector_does_not_expose_key_value() -> None:
    matches = APIKeyDetector().detect("key=sk_live_abcdefghijklmnop")

    assert len(matches) == 1
    assert not hasattr(matches[0], "matched_value")


def test_payment_card_detector_uses_luhn_validation() -> None:
    assert PaymentCardDetector().detect("4111 1111 1111 1111")
    assert PaymentCardDetector().detect("4111 1111 1111 1112") == ()


def test_sensitive_field_detector_supports_nested_paths_and_leaf_names() -> None:
    detector = SensitiveFieldDetector(["token"])
    matches = detector.detect({"user": {"credentials": {"token": "synthetic"}}})

    assert len(matches) == 1
    assert matches[0].field == "user.credentials.token"
