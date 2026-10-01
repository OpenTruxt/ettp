"""Closed value sets defined by the ETTP v1 schemas."""

from enum import StrEnum


class EntityStatus(StrEnum):
    """Lifecycle status values for an identity record."""

    PROPOSED = "PROPOSED"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    TERMINATED = "TERMINATED"


class DelegationStatus(StrEnum):
    """Lifecycle state values for delegated authority."""

    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    PENDING = "PENDING"


class RevocationStatus(StrEnum):
    """Lifecycle state values for revocation records."""

    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"


class Effect(StrEnum):
    """Policy and decision outcome values."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    REDACT = "REDACT"
