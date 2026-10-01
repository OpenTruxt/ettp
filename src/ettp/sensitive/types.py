"""Controlled sensitive-data categories."""

from enum import StrEnum


class SensitiveCategory(StrEnum):
    """Sensitive-data categories supported by Sprint 4."""

    PII = "pii"
    CREDENTIAL = "credential"
    API_KEY = "api_key"
    PAYMENT_CARD = "payment_card"
    SENSITIVE_FIELD = "sensitive_field"
