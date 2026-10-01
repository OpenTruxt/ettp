from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ettp import Action, ActionContext, Entity
from ettp.identity import Authority, Delegation, EntityRelationship
from ettp.policy import Condition, Policy, PolicyEngine, PolicyRegistry
from ettp.protocol import Effect, EntityStatus


def make_entity(status: EntityStatus = EntityStatus.ACTIVE) -> Entity:
    return Entity(
        id="ent_123",
        type="AI_AGENT",
        name="agent",
        version="1",
        capabilities=["refund.execute"],
        metadata={},
        protocol_version="0.1",
        status=status,
    )


def make_action(entity_id: str = "ent_123") -> Action:
    return Action(
        id="act_123",
        entity_id=entity_id,
        type="TOOL_CALL",
        target="refund_customer",
        operation="refund",
        arguments={"amount": 100},
    )


def make_policy(policy_id: str, effect: str, operation: str = "refund") -> Policy:
    return Policy(
        id=policy_id,
        version="1",
        effect=effect,
        conditions=[Condition(field="action.operation", operator="equals", value=operation)],
    )


def test_engine_returns_matching_policy_decision() -> None:
    registry = PolicyRegistry()
    registry.register(make_policy("policy.refund", "ALLOW"))

    decision = PolicyEngine(registry).evaluate(entity=make_entity(), action=make_action())

    assert decision.effect == "ALLOW"
    assert decision.policy_id == "policy.refund"
    assert "matched" in (decision.reason or "")
    assert "version 1" in (decision.reason or "")


def test_engine_preserves_each_protocol_effect() -> None:
    for effect in Effect:
        registry = PolicyRegistry()
        registry.register(make_policy(f"policy.{effect.value.lower()}", effect.value))

        decision = PolicyEngine(registry).evaluate(entity=make_entity(), action=make_action())

        assert decision.effect is effect
        assert decision.policy_id is not None
        assert decision.reason is not None


def test_engine_returns_structured_policy_metadata_and_condition_status() -> None:
    registry = PolicyRegistry()
    registry.register(
        Policy(
            id="policy.refund",
            version="2",
            effect="ALLOW",
            conditions=[
                Condition(
                    any=[
                        Condition(field="action.operation", operator="equals", value="refund"),
                        Condition(field="action.operation", operator="equals", value="delete"),
                    ]
                ),
            ],
        )
    )

    decision = PolicyEngine(registry).evaluate(entity=make_entity(), action=make_action())

    assert decision.policy_version == "2"
    assert decision.reason_code == "POLICY_ALLOW"
    assert decision.matched_conditions
    assert decision.failed_conditions


def test_engine_defaults_to_block_when_no_policy_matches() -> None:
    registry = PolicyRegistry()
    registry.register(make_policy("policy.delete", "ALLOW", operation="delete"))

    decision = PolicyEngine(registry).evaluate(entity=make_entity(), action=make_action())

    assert decision.effect == "BLOCK"
    assert decision.policy_id is None
    assert "default deny" in (decision.reason or "")


def test_engine_blocks_entity_action_mismatch() -> None:
    decision = PolicyEngine(PolicyRegistry()).evaluate(
        entity=make_entity(), action=make_action(entity_id="ent_other")
    )

    assert decision.effect == "BLOCK"
    assert "does not match" in (decision.reason or "")


def test_engine_output_is_deterministic() -> None:
    registry = PolicyRegistry()
    registry.register(make_policy("policy.refund", "ALLOW"))
    engine = PolicyEngine(registry)

    first = engine.evaluate(entity=make_entity(), action=make_action()).model_dump()
    second = engine.evaluate(entity=make_entity(), action=make_action()).model_dump()

    assert first == second


def test_engine_fails_closed_for_unknown_operator() -> None:
    registry = PolicyRegistry()
    registry.register(
        Policy(
            id="policy.invalid",
            version="1",
            effect="ALLOW",
            conditions=[Condition(field="action.operation", operator="eval", value="refund")],
        )
    )

    decision = PolicyEngine(registry).evaluate(entity=make_entity(), action=make_action())

    assert decision.effect == "BLOCK"
    assert "failed safely" in (decision.reason or "")


@pytest.mark.parametrize(
    "status",
    [
        EntityStatus.PROPOSED,
        EntityStatus.SUSPENDED,
        EntityStatus.REVOKED,
        EntityStatus.EXPIRED,
        EntityStatus.TERMINATED,
    ],
)
def test_non_active_entity_never_receives_allow(status: EntityStatus) -> None:
    registry = PolicyRegistry()
    registry.register(make_policy("policy.refund", "ALLOW"))

    decision = PolicyEngine(registry).evaluate(entity=make_entity(status), action=make_action())

    assert decision.effect is Effect.BLOCK
    assert decision.reason_code == f"ENTITY_{status.value}"


def test_expired_authority_never_receives_allow() -> None:
    registry = PolicyRegistry()
    registry.register(make_policy("policy.refund", "ALLOW"))
    authority = Authority(
        id="auth-expired",
        action="refund",
        capabilities=["refund"],
        grantor="root",
        grantee="ent_123",
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )

    decision = PolicyEngine(registry).evaluate(
        entity=make_entity(),
        action=make_action(),
        authority=authority,
    )

    assert decision.effect is Effect.BLOCK
    assert decision.reason_code == "AUTHORITY_EXPIRED"


def test_context_authority_identifier_alone_does_not_authorize_controlled_entity() -> None:
    entity = make_entity()
    entity.relationships = [
        EntityRelationship(
            source="root",
            relationship="subAgentOf",
            target=entity.id,
        )
    ]
    action = make_action()
    action.context = ActionContext(authority="authority-id-only")
    registry = PolicyRegistry()
    registry.register(make_policy("policy.refund", "ALLOW"))

    decision = PolicyEngine(registry).evaluate(
        entity=entity,
        action=action,
        context=action.context,
    )

    assert decision.effect is Effect.BLOCK
    assert decision.reason_code == "CONTROL_TREE_UNAUTHORIZED"


def make_delegation_chain(
    root_expired: bool = False,
    root_authority_expired: bool = False,
) -> tuple[Delegation, Delegation]:
    authority_expiration = (
        datetime.now(UTC) - timedelta(seconds=1) if root_authority_expired else None
    )
    root = Delegation(
        delegation_id="delegation-root",
        grantor="root",
        grantee="agent-parent",
        authority=Authority(
            id="authority-root",
            action="refund",
            capabilities=["refund"],
            constraints={"max_amount": 1000},
            expires_at=authority_expiration,
        ),
        capabilities=["refund"],
        constraints={"max_amount": 1000},
        expires_at=(datetime.now(UTC) - timedelta(seconds=1)) if root_expired else None,
    )
    child = Delegation(
        delegation_id="delegation-child",
        grantor="agent-parent",
        grantee="ent_123",
        authority=Authority(
            id="authority-child",
            action="refund",
            capabilities=["refund"],
            constraints={"max_amount": 500},
        ),
        capabilities=["refund"],
        constraints={"max_amount": 500},
        parent_delegation=root.delegation_id,
        depth=1,
    )
    return root, child


def test_full_valid_delegation_chain_can_authorize_scoped_action() -> None:
    registry = PolicyRegistry()
    registry.register(make_policy("policy.refund", "ALLOW"))
    root, child = make_delegation_chain()

    decision = PolicyEngine(registry).evaluate(
        entity=make_entity(),
        action=make_action(),
        delegation=child,
        delegation_chain=[root, child],
    )

    assert decision.effect is Effect.ALLOW


def test_expired_delegation_ancestor_invalidates_leaf_authority() -> None:
    registry = PolicyRegistry()
    registry.register(make_policy("policy.refund", "ALLOW"))
    root, child = make_delegation_chain(root_expired=True)

    decision = PolicyEngine(registry).evaluate(
        entity=make_entity(),
        action=make_action(),
        delegation=child,
        delegation_chain=[root, child],
    )

    assert decision.effect is Effect.BLOCK
    assert decision.reason_code == "DELEGATION_ANCESTOR_EXPIRED"


def test_expired_ancestor_authority_invalidates_leaf_grant() -> None:
    registry = PolicyRegistry()
    registry.register(make_policy("policy.refund", "ALLOW"))
    root, child = make_delegation_chain(root_authority_expired=True)

    decision = PolicyEngine(registry).evaluate(
        entity=make_entity(),
        action=make_action(),
        delegation=child,
        delegation_chain=[root, child],
    )

    assert decision.effect is Effect.BLOCK
    assert decision.reason_code == "DELEGATED_AUTHORITY_EXPIRED"
