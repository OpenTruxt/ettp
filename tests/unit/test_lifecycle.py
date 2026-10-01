from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ettp import Action
from ettp.evidence import EvidenceEventType, JSONLStore, Verifier
from ettp.identity import (
    Authority,
    Delegation,
    Entity,
    EntityRelationship,
    LifecycleManager,
    LifecycleTransitionError,
)
from ettp.policy import Policy, PolicyEngine, PolicyRegistry
from ettp.protocol import Effect, EntityStatus


def make_entity(status: EntityStatus = EntityStatus.ACTIVE) -> Entity:
    return Entity(
        id="entity-1",
        eid="eid:entity:1",
        type="AUTONOMOUS_ENTITY",
        name="agent",
        version="1",
        capabilities=["entity.suspend", "entity.lifecycle.transition"],
        metadata={},
        protocol_version="0.1",
        status=status,
    )


def make_authority(
    actor: str = "operator-1",
    action: str = "entity.lifecycle.transition",
    **kwargs,
) -> Authority:
    return Authority(
        id="auth-lifecycle",
        action=action,
        capabilities=[action],
        grantor="root",
        grantee=actor,
        **kwargs,
    )


def test_lifecycle_transition_is_evidenced_and_enforced(tmp_path) -> None:
    store = JSONLStore(tmp_path / "events.jsonl")
    manager = LifecycleManager(store)
    result = manager.transition_entity(
        entity=make_entity(),
        to_status=EntityStatus.SUSPENDED,
        action_id="act-suspend",
        actor_entity_id="operator-1",
        authority=make_authority(),
        event_id="evt-suspend",
    )

    assert result.changed
    assert result.entity.status is EntityStatus.SUSPENDED
    assert result.event.event_type is EvidenceEventType.ENTITY_SUSPENDED
    assert result.event.from_lifecycle_state == "ACTIVE"
    assert result.event.to_lifecycle_state == "SUSPENDED"
    assert Verifier.verify(store).valid

    registry = PolicyRegistry()
    registry.register(Policy(id="policy.allow", version="1", effect=Effect.ALLOW, conditions=[]))
    decision = PolicyEngine(registry).evaluate(
        entity=result.entity,
        action=Action(
            id="act-test",
            entity_id=result.entity.id,
            type="TOOL_CALL",
            target="tool",
            operation="read",
            arguments={},
        ),
    )
    assert decision.effect is Effect.BLOCK
    assert decision.reason_code == "ENTITY_SUSPENDED"


def test_resume_and_idempotent_transition_emit_audit_event(tmp_path) -> None:
    store = JSONLStore(tmp_path / "events.jsonl")
    manager = LifecycleManager(store)
    suspended = make_entity(EntityStatus.SUSPENDED)
    result = manager.transition_entity(
        entity=suspended,
        to_status=EntityStatus.ACTIVE,
        action_id="act-resume",
        actor_entity_id="operator-1",
        authority=make_authority(),
        event_id="evt-resume",
    )
    repeated = manager.transition_entity(
        entity=result.entity,
        to_status=EntityStatus.ACTIVE,
        action_id="act-resume-repeat",
        actor_entity_id="operator-1",
        authority=make_authority(),
        event_id="evt-resume-repeat",
    )

    assert result.entity.status is EntityStatus.ACTIVE
    assert repeated.changed is False
    assert repeated.event.event_type is EvidenceEventType.LIFECYCLE_TRANSITION_NOOP
    assert len(store.read()) == 2


def test_lifecycle_rejects_unauthorized_and_terminal_transitions(tmp_path) -> None:
    store = JSONLStore(tmp_path / "events.jsonl")
    manager = LifecycleManager(store)
    with pytest.raises(LifecycleTransitionError, match="grantee"):
        manager.transition_entity(
            entity=make_entity(),
            to_status=EntityStatus.SUSPENDED,
            action_id="act-suspend",
            actor_entity_id="intruder",
            authority=make_authority(),
            event_id="evt-unauthorized",
        )

    terminal_store = JSONLStore(tmp_path / "terminal-events.jsonl")
    terminal_manager = LifecycleManager(terminal_store)
    with pytest.raises(LifecycleTransitionError, match="not permitted"):
        terminal_manager.transition_entity(
            entity=make_entity(EntityStatus.TERMINATED),
            to_status=EntityStatus.ACTIVE,
            action_id="act-reactivate",
            actor_entity_id="operator-1",
            authority=make_authority(),
            event_id="evt-reactivate",
        )

    rejected = store.read() + terminal_store.read()
    assert len(rejected) == 2
    assert all(event.decision == "BLOCK" for event in rejected)
    assert all(event.event_type is EvidenceEventType.AUTHORIZATION_FAILURE for event in rejected)


def test_termination_requires_explicit_scope_and_preserves_independent_authority(
    tmp_path,
) -> None:
    store = JSONLStore(tmp_path / "events.jsonl")
    manager = LifecycleManager(store)
    entity = make_entity()
    derived = Authority(
        id="auth-derived",
        action="tool.read",
        capabilities=["read"],
        grantor="eid:entity:1",
        grantee="child-1",
    )
    parent_delegation = Delegation(
        delegation_id="delegation-root",
        grantor="root-operator",
        grantee="eid:entity:1",
        authority=Authority(
            id="auth-root",
            action="tool.read",
            capabilities=["read"],
        ),
        capabilities=["read"],
    )
    child_delegation = Delegation(
        delegation_id="delegation-child",
        grantor="eid:entity:1",
        grantee="child-1",
        authority=derived,
        parent_delegation="delegation-root",
        capabilities=["read"],
        status="ACTIVE",
    )
    independent = Authority(
        id="auth-independent",
        action="tool.read",
        capabilities=["read"],
        grantor="independent-root",
        grantee="child-1",
    )
    child_entity = Entity(
        id="child-1",
        eid="eid:child-1",
        type="AUTONOMOUS_ENTITY",
        name="child",
        version="1",
        capabilities=["read"],
        metadata={},
        protocol_version="0.1",
        relationships=[
            EntityRelationship(
                source="eid:entity:1",
                relationship="subAgentOf",
                target="eid:child-1",
            )
        ],
    )

    with pytest.raises(LifecycleTransitionError, match="explicit affected"):
        manager.transition_entity(
            entity=entity,
            to_status=EntityStatus.TERMINATED,
            action_id="act-terminate",
            actor_entity_id="operator-1",
            authority=make_authority(action="entity.terminate"),
            event_id="evt-terminate-no-plan",
            invalidation_scope="DESCENDANTS",
        )

    result = manager.transition_entity(
        entity=entity,
        to_status=EntityStatus.TERMINATED,
        action_id="act-terminate",
        actor_entity_id="operator-1",
        authority=make_authority(action="entity.terminate"),
        event_id="evt-terminate",
        invalidation_scope="DESCENDANTS",
        affected_entity_ids=["eid:child-1"],
        invalidated_authority_ids=[derived.id],
        known_delegations=[parent_delegation, child_delegation],
        known_entities=[entity, child_entity],
    )

    assert result.event.invalidation_scope == "DESCENDANTS"
    assert result.event.invalidated_authority_ids == [derived.id]
    assert independent.id not in result.event.invalidated_authority_ids
    assert result.affected_entities[0].status is EntityStatus.TERMINATED
    assert result.invalidated_delegations[0].status == "REVOKED"
    assert child_entity.status is EntityStatus.ACTIVE


def test_revoking_delegation_invalidates_only_its_descendant_chain(tmp_path) -> None:
    store = JSONLStore(tmp_path / "events.jsonl")
    manager = LifecycleManager(store)
    root = Delegation(
        delegation_id="delegation-root",
        grantor="operator-1",
        grantee="agent-1",
        authority=Authority(id="auth-root", action="read", capabilities=["read"]),
        capabilities=["read"],
    )
    child = Delegation(
        delegation_id="delegation-child",
        grantor="agent-1",
        grantee="agent-2",
        authority=Authority(id="auth-child", action="read", capabilities=["read"]),
        capabilities=["read"],
        parent_delegation=root.delegation_id,
    )
    independent = Delegation(
        delegation_id="delegation-independent",
        grantor="other-root",
        grantee="agent-2",
        authority=Authority(id="auth-independent", action="read", capabilities=["read"]),
        capabilities=["read"],
    )

    result = manager.revoke_delegation_tree(
        delegation_id=root.delegation_id,
        delegations=[root, child, independent],
        action_id="act-revoke",
        actor_entity_id="operator-1",
        authority=make_authority(action="delegation.revoke"),
        event_id="evt-revoke-tree",
    )

    assert [item.delegation_id for item in result.delegations] == [
        "delegation-root",
        "delegation-child",
    ]
    assert all(item.status == "REVOKED" for item in result.delegations)
    assert result.event.invalidated_authority_ids == ["auth-child", "auth-root"]
    assert "auth-independent" not in result.event.invalidated_authority_ids
    assert independent.status == "ACTIVE"
    assert Verifier.verify(store).valid


def test_delegation_revocation_fails_closed_on_invalid_child_provenance(tmp_path) -> None:
    store = JSONLStore(tmp_path / "events.jsonl")
    manager = LifecycleManager(store)
    root = Delegation(
        delegation_id="delegation-root",
        grantor="operator-1",
        grantee="agent-1",
        authority=Authority(id="auth-root", action="read", capabilities=["read"]),
    )
    invalid_child = Delegation(
        delegation_id="delegation-child",
        grantor="unrelated-agent",
        grantee="agent-2",
        authority=Authority(id="auth-child", action="read", capabilities=["read"]),
        parent_delegation=root.delegation_id,
    )

    with pytest.raises(LifecycleTransitionError, match="grantor"):
        manager.revoke_delegation_tree(
            delegation_id=root.delegation_id,
            delegations=[root, invalid_child],
            action_id="act-revoke",
            actor_entity_id="operator-1",
            authority=make_authority(action="delegation.revoke"),
            event_id="evt-invalid-revoke",
        )
    events = store.read()
    assert len(events) == 1
    assert events[0].event_type is EvidenceEventType.AUTHORIZATION_FAILURE
    assert events[0].decision == "BLOCK"
    assert events[0].extensions == {"reason_code": "DELEGATION_REVOCATION_REJECTED"}


@pytest.mark.parametrize(
    "scope",
    [
        "DELEGATION_CHAIN",
        "CREDENTIAL_DEPENDENTS",
        "CAPABILITY_DEPENDENTS",
        "ORGANIZATIONAL_SCOPE",
    ],
)
def test_scoped_termination_requires_and_applies_dependency_graph(tmp_path, scope: str) -> None:
    manager = LifecycleManager(JSONLStore(tmp_path / f"{scope}.jsonl"))
    entity = make_entity()
    child = Entity(
        id="child-1",
        eid="eid:child-1",
        type="SERVICE",
        name="child",
        version="1",
        capabilities=[],
        metadata={},
        protocol_version="0.1",
    )
    delegation = Delegation(
        delegation_id="delegation-derived",
        grantor=entity.eid or entity.id,
        grantee=child.eid or child.id,
        authority=Authority(
            id="authority-derived",
            action="read",
            capabilities=["read"],
        ),
        capabilities=["read"],
    )
    graph = {scope: [child.eid or child.id]}

    if scope == "DELEGATION_CHAIN":
        with pytest.raises(LifecycleTransitionError, match="known delegation graph"):
            manager.transition_entity(
                entity=entity,
                to_status=EntityStatus.TERMINATED,
                action_id="act-terminate",
                actor_entity_id="operator-1",
                authority=make_authority(action="entity.terminate"),
                event_id=f"evt-no-graph-{scope}",
                invalidation_scope=scope,
                affected_entity_ids=[child.eid or child.id],
                invalidated_authority_ids=["authority-derived"],
                known_entities=[entity, child],
            )
    else:
        with pytest.raises(LifecycleTransitionError, match="dependency graph"):
            manager.transition_entity(
                entity=entity,
                to_status=EntityStatus.TERMINATED,
                action_id="act-terminate",
                actor_entity_id="operator-1",
                authority=make_authority(action="entity.terminate"),
                event_id=f"evt-no-graph-{scope}",
                invalidation_scope=scope,
                affected_entity_ids=[child.eid or child.id],
                invalidated_authority_ids=["authority-derived"],
                known_entities=[entity, child],
                known_delegations=[delegation],
            )

    result = manager.transition_entity(
        entity=entity,
        to_status=EntityStatus.TERMINATED,
        action_id="act-terminate",
        actor_entity_id="operator-1",
        authority=make_authority(action="entity.terminate"),
        event_id=f"evt-terminate-{scope}",
        invalidation_scope=scope,
        affected_entity_ids=[child.eid or child.id],
        invalidated_authority_ids=["authority-derived"],
        known_entities=[entity, child],
        known_delegations=[delegation],
        scope_dependencies=graph if scope != "DELEGATION_CHAIN" else None,
    )

    assert result.affected_entities[0].eid == child.eid
    assert result.affected_entities[0].status is EntityStatus.TERMINATED
    assert result.invalidated_delegations[0].status == "REVOKED"


def test_delegation_revocation_is_idempotent(tmp_path) -> None:
    manager = LifecycleManager(JSONLStore(tmp_path / "events.jsonl"))
    root = Delegation(
        delegation_id="delegation-idempotent",
        grantor="operator-1",
        grantee="agent-1",
        authority=Authority(id="auth-idempotent", action="read", capabilities=["read"]),
        status="REVOKED",
        revocation_reference="old-revocation",
    )

    result = manager.revoke_delegation_tree(
        delegation_id=root.delegation_id,
        delegations=[root],
        action_id="act-revoke-repeat",
        actor_entity_id="operator-1",
        authority=make_authority(action="delegation.revoke"),
        event_id="evt-revoke-repeat",
    )

    assert result.changed is False
    assert result.event.event_type is EvidenceEventType.LIFECYCLE_TRANSITION_NOOP


def test_cyclic_delegation_tree_cannot_be_revoked_as_valid_provenance(tmp_path) -> None:
    store = JSONLStore(tmp_path / "events.jsonl")
    manager = LifecycleManager(store)
    first = Delegation(
        delegation_id="delegation-first",
        grantor="agent-b",
        grantee="agent-a",
        authority=Authority(id="auth-first", action="read", capabilities=["read"]),
        parent_delegation="delegation-second",
    )
    second = Delegation(
        delegation_id="delegation-second",
        grantor="agent-a",
        grantee="agent-b",
        authority=Authority(id="auth-second", action="read", capabilities=["read"]),
        parent_delegation="delegation-first",
    )

    with pytest.raises(LifecycleTransitionError, match="cycle"):
        manager.revoke_delegation_tree(
            delegation_id=first.delegation_id,
            delegations=[first, second],
            action_id="act-revoke-cycle",
            actor_entity_id="agent-b",
            authority=make_authority(actor="agent-b", action="delegation.revoke"),
            event_id="evt-revoke-cycle",
        )
    events = store.read()
    assert len(events) == 1
    assert events[0].decision == "BLOCK"


def test_lifecycle_manager_reuses_and_updates_registered_graph(tmp_path) -> None:
    store = JSONLStore(tmp_path / "events.jsonl")
    root = make_entity()
    child = Entity(
        id="child-1",
        eid="eid:child-1",
        type="SERVICE",
        name="child",
        version="1",
        capabilities=["read"],
        metadata={},
        protocol_version="0.1",
        relationships=[
            EntityRelationship(
                source=root.eid or root.id,
                relationship="subAgentOf",
                target="eid:child-1",
            )
        ],
    )
    delegation = Delegation(
        delegation_id="root-derived-delegation",
        grantor=root.eid or root.id,
        grantee=child.eid or child.id,
        authority=Authority(
            id="root-derived-authority",
            action="read",
            capabilities=["read"],
        ),
        capabilities=["read"],
    )
    manager = LifecycleManager(
        store,
        entities=[root, child],
        delegations=[delegation],
    )

    termination = manager.transition_entity(
        entity=root,
        to_status=EntityStatus.TERMINATED,
        action_id="act-terminate-registered",
        actor_entity_id="operator-1",
        authority=make_authority(action="entity.terminate"),
        event_id="evt-terminate-registered",
        invalidation_scope="DESCENDANTS",
        affected_entity_ids=[child.eid or child.id],
        invalidated_authority_ids=["root-derived-authority"],
    )
    revocation = manager.revoke_delegation_tree(
        delegation_id=delegation.delegation_id,
        action_id="act-revoke-registered",
        actor_entity_id=root.eid or root.id,
        authority=Authority(
            id="auth-revoke",
            action="delegation.revoke",
            capabilities=["delegation.revoke"],
            grantor="operator-1",
            grantee=root.eid or root.id,
        ),
        event_id="evt-revoke-registered",
    )

    assert termination.affected_entities[0].status is EntityStatus.TERMINATED
    assert revocation.changed is False
    assert manager.get_entity(child.id).status is EntityStatus.TERMINATED
    assert manager.get_delegation(delegation.delegation_id).status == "REVOKED"
    assert Verifier.verify(store).valid


def test_lifecycle_rejects_expired_authority(tmp_path) -> None:
    manager = LifecycleManager(JSONLStore(tmp_path / "events.jsonl"))
    expired = make_authority(expires_at=datetime.now(UTC) - timedelta(seconds=1))

    with pytest.raises(LifecycleTransitionError, match="expired"):
        manager.transition_entity(
            entity=make_entity(),
            to_status=EntityStatus.SUSPENDED,
            action_id="act-suspend",
            actor_entity_id="operator-1",
            authority=expired,
            event_id="evt-expired-authority",
        )
