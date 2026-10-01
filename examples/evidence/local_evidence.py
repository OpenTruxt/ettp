from __future__ import annotations

from ettp import Action, Entity
from ettp.evidence import EvidenceLogger
from ettp.policy import PolicyEngine, PolicyRegistry


def make_entity() -> Entity:
    return Entity(
        id="ent_123",
        eid="eid:agent:123",
        type="AI_AGENT",
        name="agent",
        version="1",
        capabilities=["refund.execute"],
        metadata={},
        protocol_version="0.1",
    )


def make_action() -> Action:
    return Action(
        id="act_123",
        entity_id="ent_123",
        type="TOOL_CALL",
        target="refund_customer",
        operation="refund",
        arguments={"amount": 100},
    )


def main() -> None:
    registry = PolicyRegistry()
    # In production, register the actual conditions and policies relevant to the workflow.
    # This example keeps the setup intentionally small and clear.
    entity = make_entity()
    action = make_action()
    logger = EvidenceLogger(".ettp/events.jsonl")

    decision = PolicyEngine(registry, evidence_store=logger.store).evaluate(
        entity=entity,
        action=action,
        request_id="req_001",
    )

    verification = logger.verify()
    event = logger.store.read()[-1]
    print(f"decision: {decision.effect.value}")
    print(f"event id: {event.id}")
    print(f"event valid: {verification.valid}")
    print(f"reason: {verification.reason}")

    logger.export_jsonl(".ettp/export/events.jsonl")
    print("Evidence export created at .ettp/export/events.jsonl")


if __name__ == "__main__":
    main()
