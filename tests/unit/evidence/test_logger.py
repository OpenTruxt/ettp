from __future__ import annotations

from ettp import Action, Entity
from ettp.decisions import Decision
from ettp.evidence import EvidenceEvent, EvidenceEventType, EvidenceLogger
from ettp.protocol import Effect


def test_logger_records_decision_and_governance_event(tmp_path) -> None:
    logger = EvidenceLogger(tmp_path / "events.jsonl")
    entity = Entity(
        id="entity-1",
        eid="eid:entity:1",
        type="SERVICE",
        name="service",
        version="1",
        capabilities=[],
        metadata={},
        protocol_version="0.1",
    )
    action = Action(
        id="action-1",
        entity_id=entity.id,
        type="TOOL_CALL",
        target="read",
        operation="read",
        arguments={"secret": "must-not-be-copied"},
    )
    decision = Decision(
        id="decision-1",
        action_id=action.id,
        effect=Effect.BLOCK,
        policy_id="policy-1",
        reason_code="POLICY_BLOCK",
    )
    policy_event = logger.record_decision(
        action=action,
        decision=decision,
        entity=entity,
        request_id="req-1",
    )
    lifecycle_event = EvidenceEvent.from_governance_event(
        event_id="event-2",
        event_type=EvidenceEventType.AUTHORITY_WITHDRAWN,
        event="Authority withdrawn",
        entity_id=entity.eid or entity.id,
        action_id="action-2",
        actor_entity_id="eid:operator:1",
        authority_id="authority-1",
    )
    logged_lifecycle_event = logger.record_event(lifecycle_event)

    assert policy_event.entity_id == "eid:entity:1"
    assert logged_lifecycle_event.previous_event_hash == policy_event.event_hash
    assert logger.store.count() == 2
    assert [event.id for event in logger.store] == [policy_event.id, "event-2"]
    assert logger.verify().valid
    assert "must-not-be-copied" not in logger.store.path.read_text(encoding="utf-8")
