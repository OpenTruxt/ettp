from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from ettp import Action
from ettp.decisions import Decision
from ettp.evidence import EvidenceEvent, EvidenceEventType
from ettp.protocol import Effect
from schema_support import SCHEMA_ROOT, load_json, make_validator


def test_event_creation_and_required_fields() -> None:
    event = EvidenceEvent(
        event_id="evt_001",
        protocol_version="0.1",
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        entity_id="ent_123",
        action_id="act_123",
        decision="ALLOW",
        request_id="req_123",
        previous_event_hash=None,
    )

    assert event.event_id == "evt_001"
    assert event.protocol_version == "0.1"
    assert event.entity_id == "ent_123"
    assert event.action_id == "act_123"
    assert event.decision == "ALLOW"
    assert event.request_id == "req_123"
    assert event.previous_event_hash is None


def test_event_serialization_is_stable() -> None:
    event = EvidenceEvent(
        event_id="evt_001",
        protocol_version="0.1",
        timestamp=datetime(2025, 1, 1, 12, 0, 0, tzinfo=UTC),
        entity_id="ent_123",
        action_id="act_123",
        decision="ALLOW",
        request_id="req_123",
        previous_event_hash="a" * 64,
    )

    payload = event.model_dump(mode="json")
    assert payload["id"] == "evt_001"
    assert payload["timestamp"] == "2025-01-01T12:00:00Z"
    assert payload["protocol_version"] == "0.1"

    serialised = event.model_dump_json()
    assert serialised
    assert '"id"' in serialised
    assert "decision" in serialised


def test_event_from_decision_builds_expected_fields() -> None:
    event = EvidenceEvent.from_decision(
        event_id="evt_002",
        entity_id="ent_123",
        action_id="act_123",
        decision="BLOCK",
        request_id="req_123",
        previous_event_hash="b" * 64,
    )

    assert event.decision == "BLOCK"
    assert event.previous_event_hash == "b" * 64
    assert event.entity_id == "ent_123"
    assert event.action_id == "act_123"
    assert event.request_id == "req_123"
    assert event.event_hash


def test_event_factory_generates_request_id_when_missing() -> None:
    event = EvidenceEvent.from_decision(
        event_id="evt_generated_request",
        entity_id="ent_123",
        action_id="act_123",
        decision="BLOCK",
    )

    assert event.request_id is not None
    assert event.request_id.startswith("req_")


def test_event_factory_accepts_action_and_decision_objects() -> None:
    action = Action(
        id="act_from_models",
        entity_id="eid:entity:1",
        type="TOOL_CALL",
        target="read",
        operation="read",
        arguments={},
    )
    decision = Decision(
        id="decision-from-models",
        action_id=action.id,
        effect=Effect.ALLOW,
        policy_id="policy-read",
    )

    event = EvidenceEvent.from_decision(action=action, decision=decision)

    assert event.action_id == action.id
    assert event.entity_id == action.entity_id
    assert event.decision_id == decision.id
    assert event.policy_id == decision.policy_id


def test_serialized_event_conforms_to_protocol_schema() -> None:
    event = EvidenceEvent.from_decision(
        event_id="evt_schema_001",
        entity_id="ent_123",
        action_id="act_123",
        decision="ALLOW",
        policy_id="policy.example",
    )

    make_validator(load_json(SCHEMA_ROOT / "evidence.schema.json")).validate(
        event.model_dump(mode="json")
    )


def test_lifecycle_event_carries_invalidation_scope_and_transition() -> None:
    event = EvidenceEvent.from_governance_event(
        event_id="evt_termination_001",
        event_type="ENTITY_TERMINATED",
        event="Entity terminated; descendant authority invalidated",
        entity_id="eid:agent:root",
        action_id="act_termination_001",
        actor_entity_id="eid:operator:1",
        from_lifecycle_state="ACTIVE",
        to_lifecycle_state="TERMINATED",
        invalidation_scope="DESCENDANTS",
        affected_entity_ids=["eid:agent:child"],
        invalidated_authority_ids=["auth-derived-1"],
    )

    payload = event.model_dump(mode="json")
    make_validator(load_json(SCHEMA_ROOT / "evidence.schema.json")).validate(payload)
    assert payload["invalidation_scope"] == "DESCENDANTS"
    assert payload["invalidated_authority_ids"] == ["auth-derived-1"]


def test_event_type_vocabulary_matches_protocol_schema() -> None:
    schema = load_json(SCHEMA_ROOT / "evidence.schema.json")
    schema_types = schema["properties"]["event_type"]["enum"]

    assert set(schema_types) == {event_type.value for event_type in EvidenceEventType}


@pytest.mark.parametrize(
    "extensions",
    [
        {"api_key": "sk_test_do_not_persist_123456"},
        {"metadata": {"private_key": "sensitive"}},
        {"safe_label": "Bearer abcdef123456"},
    ],
)
def test_evidence_rejects_secret_bearing_extensions(extensions) -> None:
    with pytest.raises(ValidationError, match=r"sensitive|secret"):
        EvidenceEvent.from_governance_event(
            event_id="evt_secret_rejected",
            event_type=EvidenceEventType.SECURITY_VIOLATION,
            event="Credential exposure attempt rejected",
            entity_id="ent_123",
            action_id="act_secret",
            extensions=extensions,
        )
