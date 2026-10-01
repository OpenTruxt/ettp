from __future__ import annotations

import pytest

from ettp import Action, Entity
from ettp.evidence import EvidenceEventType, JSONLStore
from ettp.policy import Condition, Policy, PolicyEngine, PolicyRegistry
from ettp.protocol import Effect


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


def make_action(
    entity_id: str = "ent_123",
    *,
    operation: str = "refund",
    amount: int = 100,
) -> Action:
    return Action(
        id="act_123",
        entity_id=entity_id,
        type="TOOL_CALL",
        target="refund_customer",
        operation=operation,
        arguments={"amount": amount},
    )


@pytest.mark.parametrize(
    "effect",
    [Effect.ALLOW, Effect.BLOCK, Effect.REQUIRE_APPROVAL, Effect.REDACT],
)
def test_governed_actions_generate_evidence(tmp_path, effect: Effect) -> None:
    registry = PolicyRegistry()
    registry.register(
        Policy(
            id=f"policy.refund.{effect.value.lower()}",
            version="1",
            effect=effect,
            conditions=[Condition(field="action.operation", operator="equals", value="refund")],
        )
    )

    store = JSONLStore(tmp_path / "events.jsonl")
    engine = PolicyEngine(registry, evidence_store=store)
    entity = make_entity()
    secret = "sk_test_do_not_persist_123456"
    action = make_action()
    action.arguments["credential"] = secret

    decision = engine.evaluate(entity=entity, action=action, request_id="req_integration")
    events = store.read()

    assert decision.effect == effect
    assert len(events) == 1
    event = events[0]
    assert event.decision == effect.value
    assert event.decision_id == decision.id
    assert event.policy_id == decision.policy_id
    assert event.entity_id == entity.eid
    assert event.action_id == "act_123"
    assert event.request_id == "req_integration"
    expected_event_type = {
        Effect.REDACT: EvidenceEventType.REDACTION_APPLIED,
        Effect.REQUIRE_APPROVAL: EvidenceEventType.APPROVAL_REQUESTED,
    }.get(effect, EvidenceEventType.POLICY_DECISION)
    assert event.event_type is expected_event_type
    assert secret not in event.model_dump_json()


def test_default_deny_is_recorded(tmp_path) -> None:
    store = JSONLStore(tmp_path / "events.jsonl")
    engine = PolicyEngine(PolicyRegistry(), evidence_store=store)

    decision = engine.evaluate(entity=make_entity(), action=make_action())

    assert decision.effect == Effect.BLOCK
    assert decision.reason_code == "DEFAULT_DENY"
    assert len(store.read()) == 1
    assert store.read()[0].decision == "BLOCK"


def test_unexpected_evaluation_failure_is_fail_closed_and_recorded(
    tmp_path,
    monkeypatch,
) -> None:
    store = JSONLStore(tmp_path / "events.jsonl")
    engine = PolicyEngine(PolicyRegistry(), evidence_store=store)

    def fail_evaluation(action):
        raise RuntimeError("sensitive exception details must not enter evidence")

    monkeypatch.setattr(engine, "_evaluate_sensitive", fail_evaluation)
    decision = engine.evaluate(entity=make_entity(), action=make_action())

    assert decision.effect == Effect.BLOCK
    assert decision.reason_code == "POLICY_EVALUATION_FAILED"
    serialized = store.path.read_text(encoding="utf-8")
    assert "sensitive exception details" not in serialized
    assert len(store.read()) == 1
    assert store.read()[0].event_type is EvidenceEventType.POLICY_EVALUATION_FAILURE


def test_evidence_write_failure_blocks_action(tmp_path, monkeypatch) -> None:
    store = JSONLStore(tmp_path / "events.jsonl")
    registry = PolicyRegistry()
    registry.register(
        Policy(
            id="policy.refund",
            version="1",
            effect=Effect.ALLOW,
            conditions=[Condition(field="action.operation", operator="equals", value="refund")],
        )
    )

    def fail_write(**kwargs):
        raise OSError("disk details must not leak into the decision")

    monkeypatch.setattr(store, "record_decision", fail_write)
    engine = PolicyEngine(registry, evidence_store=store)

    decision = engine.evaluate(entity=make_entity(), action=make_action())

    assert decision.effect is Effect.BLOCK
    assert decision.reason_code == "EVIDENCE_WRITE_FAILED"
    assert "disk details" not in (decision.reason or "")


def test_policy_engine_persists_by_default_without_store_configuration(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ETTP_EVIDENCE_PATH", raising=False)
    registry = PolicyRegistry()
    registry.register(
        Policy(
            id="policy.refund.default-store",
            version="1",
            effect=Effect.ALLOW,
            conditions=[Condition(field="action.operation", operator="equals", value="refund")],
        )
    )

    decision = PolicyEngine(registry).evaluate(entity=make_entity(), action=make_action())

    default_store = JSONLStore(tmp_path / ".ettp" / "events.jsonl")
    events = default_store.read()
    assert decision.effect is Effect.ALLOW
    assert len(events) == 1
    assert events[0].decision == "ALLOW"
