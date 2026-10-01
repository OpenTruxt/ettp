from __future__ import annotations

from ettp import Action, Entity
from ettp.policy import PolicyEngine, PolicyRegistry
from ettp.protocol import Effect
from ettp.sensitive import (
    DetectorRegistry,
    SensitiveCategory,
    SensitiveDataPolicy,
    SensitiveFieldDetector,
)


def make_action() -> Action:
    return Action(
        id="act_sensitive",
        entity_id="ent_sensitive",
        type="TOOL_CALL",
        target="send_email",
        operation="send",
        arguments={"password": "synthetic-secret", "body": "hello"},
    )


def make_entity() -> Entity:
    return Entity(
        id="ent_sensitive",
        type="AI_AGENT",
        name="agent",
        version="1",
        capabilities=["email.send"],
        metadata={},
        protocol_version="0.1",
    )


def make_engine(effect: Effect) -> PolicyEngine:
    detectors = DetectorRegistry()
    detectors.register(SensitiveFieldDetector(["password"]))
    policies = (
        SensitiveDataPolicy(
            policy_id=f"sensitive.password.{effect.value.lower()}",
            version="1",
            categories=frozenset({SensitiveCategory.SENSITIVE_FIELD}),
            effect=effect,
        ),
    )
    return PolicyEngine(
        PolicyRegistry(), sensitive_detectors=detectors, sensitive_policies=policies
    )


def test_sensitive_policy_blocks_without_leaking_secret() -> None:
    decision = make_engine(Effect.BLOCK).evaluate(entity=make_entity(), action=make_action())

    assert decision.effect is Effect.BLOCK
    assert "synthetic-secret" not in (decision.reason or "")
    assert decision.policy_id == "sensitive.password.block"


def test_sensitive_policy_redacts_action_arguments() -> None:
    engine = make_engine(Effect.REDACT)
    action = make_action()

    decision = engine.evaluate(entity=make_entity(), action=action)
    redacted = engine.redact_action(action)

    assert decision.effect is Effect.REDACT
    assert redacted.arguments["password"] == "[REDACTED]"
    assert action.arguments["password"] == "synthetic-secret"
