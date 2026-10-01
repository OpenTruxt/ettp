"""ETTP evidence model."""

from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import uuid4

from pydantic import AliasChoices, ConfigDict, Field, field_validator, model_validator

from ettp.actions import Action
from ettp.protocol import ETTPModel

_SENSITIVE_EXTENSION_KEY = re.compile(
    r"password|secret|token|api[_-]?key|private[_-]?key|credential|card[_-]?number|authorization",
    re.IGNORECASE,
)
_SENSITIVE_VALUE = re.compile(
    r"Bearer\s+\S+|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9_-]{8,}\b|\bAKIA[0-9A-Z]{16}\b",
    re.IGNORECASE,
)


class EvidenceEventType(StrEnum):
    """Protocol-defined event categories for governance and lifecycle records."""

    POLICY_DECISION = "POLICY_DECISION"
    ACTION_EXECUTED = "ACTION_EXECUTED"
    ACTION_BLOCKED = "ACTION_BLOCKED"
    REDACTION_APPLIED = "REDACTION_APPLIED"
    ENFORCEMENT_FAILURE = "ENFORCEMENT_FAILURE"
    AUTHORIZATION_FAILURE = "AUTHORIZATION_FAILURE"
    POLICY_EVALUATION_FAILURE = "POLICY_EVALUATION_FAILURE"
    SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY"
    QUARANTINE = "QUARANTINE"
    ISOLATE = "ISOLATE"
    ESCALATE = "ESCALATE"
    CHALLENGE = "CHALLENGE"
    REAUTHENTICATE = "REAUTHENTICATE"
    DENY_AUTHORITY = "DENY_AUTHORITY"
    AUTHORITY_GRANTED = "AUTHORITY_GRANTED"
    AUTHORITY_WITHDRAWN = "AUTHORITY_WITHDRAWN"
    DELEGATION_CREATED = "DELEGATION_CREATED"
    DELEGATION_ACCEPTED = "DELEGATION_ACCEPTED"
    DELEGATION_ATTENUATED = "DELEGATION_ATTENUATED"
    DELEGATION_RENEWED = "DELEGATION_RENEWED"
    DELEGATION_EXPIRED = "DELEGATION_EXPIRED"
    DELEGATION_REVOKED = "DELEGATION_REVOKED"
    DELEGATION_CHAIN_INVALIDATED = "DELEGATION_CHAIN_INVALIDATED"
    INVALIDATE_AUTHORITY = "INVALIDATE_AUTHORITY"
    INVALIDATE_DELEGATION = "INVALIDATE_DELEGATION"
    INVALIDATE_CREDENTIAL = "INVALIDATE_CREDENTIAL"
    INVALIDATE_CAPABILITY = "INVALIDATE_CAPABILITY"
    DELEGATION_DEPTH_VIOLATION = "DELEGATION_DEPTH_VIOLATION"
    UNAUTHORIZED_DELEGATION_ATTEMPT = "UNAUTHORIZED_DELEGATION_ATTEMPT"
    AUTHORITY_ESCALATION_ATTEMPT = "AUTHORITY_ESCALATION_ATTEMPT"
    INDEPENDENT_AUTHORITY_RESOLVED = "INDEPENDENT_AUTHORITY_RESOLVED"
    CAPABILITY_GRANTED = "CAPABILITY_GRANTED"
    CAPABILITY_REVOKED = "CAPABILITY_REVOKED"
    CREDENTIAL_ISSUED = "CREDENTIAL_ISSUED"
    CREDENTIAL_EXPIRED = "CREDENTIAL_EXPIRED"
    CREDENTIAL_REVOKED = "CREDENTIAL_REVOKED"
    KEY_REVOKED = "KEY_REVOKED"
    ENTITY_SUSPENDED = "ENTITY_SUSPENDED"
    ENTITY_ACTIVATED = "ENTITY_ACTIVATED"
    ENTITY_RESUMED = "ENTITY_RESUMED"
    ENTITY_REVOKED = "ENTITY_REVOKED"
    ENTITY_EXPIRED = "ENTITY_EXPIRED"
    ENTITY_TERMINATED = "ENTITY_TERMINATED"
    ENTITY_LIFECYCLE_TRANSITION = "ENTITY_LIFECYCLE_TRANSITION"
    LIFECYCLE_TRANSITION_NOOP = "LIFECYCLE_TRANSITION_NOOP"
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    IDENTITY_VERIFICATION = "IDENTITY_VERIFICATION"
    CREDENTIAL_VERIFICATION = "CREDENTIAL_VERIFICATION"
    ATTESTATION = "ATTESTATION"
    TRUST_EVALUATION = "TRUST_EVALUATION"
    POLICY_CONFLICT = "POLICY_CONFLICT"
    POLICY_OVERRIDE = "POLICY_OVERRIDE"
    APPROVAL_REQUESTED = "APPROVAL_REQUESTED"
    APPROVAL_GRANTED = "APPROVAL_GRANTED"
    APPROVAL_DENIED = "APPROVAL_DENIED"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    SECURITY_VIOLATION = "SECURITY_VIOLATION"
    POLICY_BYPASS_ATTEMPT = "POLICY_BYPASS_ATTEMPT"
    PRIVILEGE_ESCALATION_ATTEMPT = "PRIVILEGE_ESCALATION_ATTEMPT"
    REPLAY_DETECTED = "REPLAY_DETECTED"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    INVALID_CREDENTIAL = "INVALID_CREDENTIAL"
    EXPIRED_CREDENTIAL = "EXPIRED_CREDENTIAL"
    REVOKED_CREDENTIAL = "REVOKED_CREDENTIAL"
    TERMINATED_ENTITY_ACTIVITY = "TERMINATED_ENTITY_ACTIVITY"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
    EVIDENCE_VERIFICATION_FAILURE = "EVIDENCE_VERIFICATION_FAILURE"


class Evidence(ETTPModel):
    """A record of an action outcome and associated protocol objects."""

    id: str = Field(min_length=1)
    event: str = Field(min_length=1)
    timestamp: datetime
    entity_id: str = Field(min_length=1)
    action_id: str = Field(min_length=1)
    policy_id: str | None = Field(default=None, min_length=1)
    decision_id: str = Field(min_length=1)
    executed: dict[str, Any] | None = None
    extensions: dict[str, Any] | None = None


class EvidenceEvent(ETTPModel):
    """A schema-compatible, tamper-evident governance event."""

    model_config = ConfigDict(frozen=True)

    id: str = Field(min_length=1, validation_alias=AliasChoices("id", "event_id"))
    event: str = Field(default="Governance event", min_length=1)
    protocol_version: Literal["0.1"] = "0.1"
    event_type: EvidenceEventType = EvidenceEventType.POLICY_DECISION
    timestamp: datetime
    entity_id: str = Field(min_length=1)
    action_id: str = Field(min_length=1)
    policy_id: str | None = Field(default=None, min_length=1)
    decision_id: str = Field(default="pending", min_length=1)
    decision: str | None = Field(default=None, min_length=1)
    request_id: str | None = Field(default=None, min_length=1)
    actor_entity_id: str | None = Field(default=None, min_length=1)
    authority_id: str | None = Field(default=None, min_length=1)
    delegation_chain: list[str] | None = None
    lifecycle_state: str | None = Field(default=None, min_length=1)
    enforcement: str | None = Field(default=None, min_length=1)
    references: list[str] | None = None
    affected_entity_ids: list[str] | None = None
    invalidated_authority_ids: list[str] | None = None
    from_lifecycle_state: str | None = Field(default=None, min_length=1)
    to_lifecycle_state: str | None = Field(default=None, min_length=1)
    invalidation_scope: (
        Literal[
            "SELF",
            "DESCENDANTS",
            "DELEGATION_CHAIN",
            "CREDENTIAL_DEPENDENTS",
            "CAPABILITY_DEPENDENTS",
            "ORGANIZATIONAL_SCOPE",
        ]
        | None
    ) = None
    previous_event_hash: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    event_hash: str | None = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")
    extensions: dict[str, Any] | None = None

    @model_validator(mode="before")
    @classmethod
    def populate_protocol_defaults(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        payload = dict(value)
        event_id = payload.get("id", payload.get("event_id"))
        if payload.get("decision_id") in (None, "pending"):
            payload["decision_id"] = f"decision:{payload.get('action_id', event_id)}"
        _validate_evidence_text(payload.get("event"))
        _validate_extensions(payload.get("extensions"))
        return payload

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def compute_hash(self) -> EvidenceEvent:
        if self.event_hash is not None:
            return self
        payload = self.model_dump(mode="json", exclude_none=True, exclude={"event_hash"})
        digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        object.__setattr__(self, "event_hash", digest)
        return self

    @property
    def event_id(self) -> str:
        """Backward-compatible name for the schema's ``id`` field."""
        return self.id

    def with_previous_event_hash(self, previous_event_hash: str | None) -> EvidenceEvent:
        """Return a newly hashed event linked to the supplied chain predecessor."""
        payload = self.model_dump(mode="json", exclude={"event_hash"})
        payload["previous_event_hash"] = previous_event_hash
        return type(self).model_validate(payload)

    def with_request_id(self, request_id: str) -> EvidenceEvent:
        """Return a newly hashed event carrying the supplied correlation identifier."""
        payload = self.model_dump(mode="json", exclude={"event_hash"})
        payload["request_id"] = request_id
        return type(self).model_validate(payload)

    @classmethod
    def from_decision(
        cls,
        *,
        event_id: str | None = None,
        entity_id: str | None = None,
        action_id: str | None = None,
        decision: str | object,
        action: Action | None = None,
        event_type: EvidenceEventType = EvidenceEventType.POLICY_DECISION,
        request_id: str | None = None,
        decision_id: str | None = None,
        policy_id: str | None = None,
        actor_entity_id: str | None = None,
        authority_id: str | None = None,
        delegation_chain: list[str] | None = None,
        previous_event_hash: str | None = None,
        timestamp: datetime | str | None = None,
        protocol_version: Literal["0.1"] = "0.1",
        extensions: dict[str, Any] | None = None,
    ) -> EvidenceEvent:
        if action is not None:
            action_id = action_id or action.id
            entity_id = entity_id or action.entity_id
        if entity_id is None or action_id is None:
            raise ValueError("entity_id and action_id are required directly or through action")
        effect = getattr(decision, "effect", decision)
        decision_value = effect.value if hasattr(effect, "value") else str(effect)
        decision_id = decision_id or getattr(decision, "id", None) or f"decision:{action_id}"
        policy_id = policy_id or getattr(decision, "policy_id", None)
        request_id = request_id or getattr(decision, "request_id", None)
        occurred_at = _parse_timestamp(timestamp) if timestamp is not None else datetime.now(UTC)
        return cls(
            id=event_id or f"evt_{uuid4().hex}",
            protocol_version=protocol_version,
            event=f"Policy decision: {decision_value}",
            event_type=event_type,
            timestamp=occurred_at,
            entity_id=entity_id,
            action_id=action_id,
            policy_id=policy_id,
            decision_id=decision_id,
            decision=decision_value,
            request_id=request_id or f"req_{uuid4().hex}",
            actor_entity_id=actor_entity_id or entity_id,
            authority_id=authority_id,
            delegation_chain=delegation_chain,
            previous_event_hash=previous_event_hash,
            extensions=extensions,
        )

    @classmethod
    def from_governance_event(
        cls,
        *,
        event_id: str,
        event_type: EvidenceEventType,
        event: str,
        entity_id: str,
        action_id: str,
        decision: str | None = None,
        actor_entity_id: str | None = None,
        decision_id: str | None = None,
        policy_id: str | None = None,
        request_id: str | None = None,
        authority_id: str | None = None,
        delegation_chain: list[str] | None = None,
        lifecycle_state: str | None = None,
        enforcement: str | None = None,
        references: list[str] | None = None,
        affected_entity_ids: list[str] | None = None,
        invalidated_authority_ids: list[str] | None = None,
        from_lifecycle_state: str | None = None,
        to_lifecycle_state: str | None = None,
        invalidation_scope: Literal[
            "SELF",
            "DESCENDANTS",
            "DELEGATION_CHAIN",
            "CREDENTIAL_DEPENDENTS",
            "CAPABILITY_DEPENDENTS",
            "ORGANIZATIONAL_SCOPE",
        ]
        | None = None,
        previous_event_hash: str | None = None,
        timestamp: datetime | str | None = None,
        extensions: dict[str, Any] | None = None,
    ) -> EvidenceEvent:
        """Create typed evidence for lifecycle, authority, or security operations."""
        occurred_at = _parse_timestamp(timestamp) if timestamp is not None else datetime.now(UTC)
        return cls(
            id=event_id,
            event=event,
            event_type=event_type,
            timestamp=occurred_at,
            entity_id=entity_id,
            action_id=action_id,
            decision_id=decision_id or f"decision:{action_id}",
            decision=decision,
            policy_id=policy_id,
            request_id=request_id or f"req_{uuid4().hex}",
            actor_entity_id=actor_entity_id,
            authority_id=authority_id,
            delegation_chain=delegation_chain,
            lifecycle_state=lifecycle_state,
            enforcement=enforcement,
            references=references,
            affected_entity_ids=affected_entity_ids,
            invalidated_authority_ids=invalidated_authority_ids,
            from_lifecycle_state=from_lifecycle_state,
            to_lifecycle_state=to_lifecycle_state,
            invalidation_scope=invalidation_scope,
            previous_event_hash=previous_event_hash,
            extensions=extensions,
        )

    def model_dump(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        data = super().model_dump(*args, **kwargs)
        if isinstance(data.get("timestamp"), datetime):
            data["timestamp"] = data["timestamp"].astimezone(UTC).isoformat().replace("+00:00", "Z")
        return data


def canonical_json(payload: dict[str, Any]) -> str:
    """Serialize values using RFC 8785 JSON Canonicalization Scheme (JCS)."""
    if not isinstance(payload, dict):
        raise TypeError("canonical evidence payload must be a JSON object")
    return _canonical_value(payload)


def _canonical_value(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        _validate_unicode(value)
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, int):
        if abs(value) > 9_007_199_254_740_991:
            raise ValueError("JCS integers must be within the interoperable safe integer range")
        return str(value)
    if isinstance(value, float):
        return _canonical_number(value)
    if isinstance(value, list):
        return "[" + ",".join(_canonical_value(item) for item in value) + "]"
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("JCS object keys must be strings")
        for key in value:
            _validate_unicode(key)
        keys = sorted(value, key=lambda key: key.encode("utf-16be"))
        return (
            "{"
            + ",".join(f"{_canonical_value(key)}:{_canonical_value(value[key])}" for key in keys)
            + "}"
        )
    raise TypeError(f"unsupported JSON value in evidence payload: {type(value).__name__}")


def _canonical_number(value: float) -> str:
    if not math.isfinite(value):
        raise ValueError("JCS does not permit NaN or infinite numbers")
    if value == 0:
        return "0"

    raw = repr(value).lower()
    sign = "-" if raw.startswith("-") else ""
    raw = raw.removeprefix("-")
    mantissa, _, exponent_text = raw.partition("e")
    exponent = int(exponent_text) if exponent_text else 0
    whole, _, fractional = mantissa.partition(".")
    digits = whole + fractional
    decimal_position = len(whole) + exponent
    leading_zeros = len(digits) - len(digits.lstrip("0"))
    digits = digits.lstrip("0") or "0"
    decimal_position -= leading_zeros
    digits = digits.rstrip("0") or "0"

    if -6 < decimal_position <= 21:
        if decimal_position <= 0:
            return f"{sign}0.{('0' * -decimal_position)}{digits}"
        if decimal_position >= len(digits):
            return f"{sign}{digits}{'0' * (decimal_position - len(digits))}"
        return f"{sign}{digits[:decimal_position]}.{digits[decimal_position:]}"

    scientific_exponent = decimal_position - 1
    coefficient = digits[0] + (f".{digits[1:]}" if len(digits) > 1 else "")
    exponent_sign = "+" if scientific_exponent >= 0 else ""
    return f"{sign}{coefficient}e{exponent_sign}{scientific_exponent}"


def _validate_unicode(value: str) -> None:
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        raise ValueError("JCS strings must not contain unpaired UTF-16 surrogates")


def _validate_evidence_text(value: Any) -> None:
    if isinstance(value, str) and _SENSITIVE_VALUE.search(value):
        raise ValueError("evidence event descriptions must not contain secret material")


def _validate_extensions(value: Any) -> None:
    if value is None:
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str) and _SENSITIVE_EXTENSION_KEY.search(key):
                raise ValueError(f"sensitive extension field is not permitted: {key}")
            _validate_extensions(item)
    elif isinstance(value, list):
        for item in value:
            _validate_extensions(item)
    elif isinstance(value, str) and _SENSITIVE_VALUE.search(value):
        raise ValueError("evidence extensions must not contain secret material")


def _parse_timestamp(value: datetime | str) -> datetime:
    if isinstance(value, datetime):
        return value
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed


# Backward-compatible alias retained for older ETTP integrations.
EvidenceEventAlias = EvidenceEvent
