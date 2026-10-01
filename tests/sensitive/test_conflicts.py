from __future__ import annotations

from itertools import permutations

from ettp import Action, Entity
from ettp.policy import PolicyEngine, PolicyRegistry
from ettp.protocol import Effect
from ettp.sensitive import (
    DetectorRegistry,
    SensitiveCategory,
    SensitiveDataPolicy,
    SensitiveFieldDetector,
)


def make_inputs() -> tuple[Entity, Action]:
    entity = Entity(
        id="ent_sensitive",
        type="AI_AGENT",
        name="agent",
        version="1",
        capabilities=[],
        metadata={},
        protocol_version="0.1",
    )
    action = Action(
        id="act_sensitive",
        entity_id=entity.id,
        type="TOOL_CALL",
        target="tool",
        operation="send",
        arguments={"token": "synthetic-token"},
    )
    return entity, action


def test_block_beats_redact_independent_of_registration_order() -> None:
    detectors = DetectorRegistry()
    detectors.register(SensitiveFieldDetector(["token"]))
    policies = (
        SensitiveDataPolicy(
            "sensitive.redact", "1", frozenset({SensitiveCategory.SENSITIVE_FIELD}), Effect.REDACT
        ),
        SensitiveDataPolicy(
            "sensitive.block", "1", frozenset({SensitiveCategory.SENSITIVE_FIELD}), Effect.BLOCK
        ),
    )
    entity, action = make_inputs()
    projections = set()
    for policy_order in permutations(policies):
        decision = PolicyEngine(
            PolicyRegistry(), sensitive_detectors=detectors, sensitive_policies=policy_order
        ).evaluate(entity=entity, action=action)
        projections.add((decision.effect, decision.policy_id, decision.reason))

    assert projections == {
        (
            Effect.BLOCK,
            "sensitive.block",
            "Sensitive data detected: categories=sensitive_field; "
            "detectors=sensitive_field.configurable; fields=arguments.token",
        )
    }
