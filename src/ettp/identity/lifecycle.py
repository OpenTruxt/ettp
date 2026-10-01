"""Fail-closed entity lifecycle transitions with evidence capture."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from threading import RLock
from typing import TYPE_CHECKING, Literal
from uuid import uuid4

from ettp.protocol import EntityStatus

from .authority import Authority
from .delegation import Delegation
from .entity import Entity
from .revocation import Revocation

if TYPE_CHECKING:
    from ettp.evidence import EvidenceEvent, EvidenceEventType, JSONLStore

InvalidationScope = Literal[
    "SELF",
    "DESCENDANTS",
    "DELEGATION_CHAIN",
    "CREDENTIAL_DEPENDENTS",
    "CAPABILITY_DEPENDENTS",
    "ORGANIZATIONAL_SCOPE",
]

_TRANSITIONS: dict[EntityStatus, frozenset[EntityStatus]] = {
    EntityStatus.PROPOSED: frozenset(
        {EntityStatus.ACTIVE, EntityStatus.REVOKED, EntityStatus.TERMINATED}
    ),
    EntityStatus.ACTIVE: frozenset(
        {
            EntityStatus.SUSPENDED,
            EntityStatus.REVOKED,
            EntityStatus.EXPIRED,
            EntityStatus.TERMINATED,
        }
    ),
    EntityStatus.SUSPENDED: frozenset(
        {
            EntityStatus.ACTIVE,
            EntityStatus.REVOKED,
            EntityStatus.EXPIRED,
            EntityStatus.TERMINATED,
        }
    ),
    EntityStatus.REVOKED: frozenset(),
    EntityStatus.EXPIRED: frozenset(),
    EntityStatus.TERMINATED: frozenset(),
}


@dataclass(frozen=True)
class LifecycleTransitionResult:
    """A validated entity state change and its persisted evidence event."""

    entity: Entity
    event: EvidenceEvent
    changed: bool
    affected_entities: tuple[Entity, ...] = ()
    invalidated_delegations: tuple[Delegation, ...] = ()


@dataclass(frozen=True)
class DelegationRevocationResult:
    """A revocation record, its affected delegation subtree, and audit evidence."""

    revocation: Revocation
    delegations: tuple[Delegation, ...]
    event: EvidenceEvent
    changed: bool


class LifecycleTransitionError(ValueError):
    """Raised when a lifecycle command is invalid, unauthorized, or unevidenced."""


class LifecycleManager:
    """Apply explicit entity status transitions and persist their evidence first."""

    def __init__(
        self,
        evidence_store: JSONLStore,
        *,
        entities: list[Entity] | None = None,
        delegations: list[Delegation] | None = None,
        scope_dependencies: dict[InvalidationScope, list[str]] | None = None,
    ) -> None:
        self._evidence_store = evidence_store
        self._lock = RLock()
        self._entities: dict[str, Entity] = {}
        self._delegations: dict[str, Delegation] = {}
        self._scope_dependencies: dict[InvalidationScope, set[str]] = {}
        self._entity_graph_complete = entities is not None
        self._delegation_graph_complete = delegations is not None
        if entities is not None:
            self.register_entities(entities, complete=True)
        if delegations is not None:
            self.register_delegations(delegations, complete=True)
        if scope_dependencies is not None:
            for scope, references in scope_dependencies.items():
                self.register_scope_dependencies(scope, references)

    def register_entities(self, entities: list[Entity], *, complete: bool = False) -> None:
        """Register trusted entity records; set complete only for a full authoritative graph."""
        with self._lock:
            if complete:
                self._entities.clear()
            for entity in entities:
                for reference, existing in list(self._entities.items()):
                    if existing.id == entity.id:
                        self._entities.pop(reference)
                self._entities[entity.id] = entity
                if entity.eid is not None:
                    self._entities[entity.eid] = entity
            if complete:
                self._entity_graph_complete = True

    def register_delegations(
        self,
        delegations: list[Delegation],
        *,
        complete: bool = False,
    ) -> None:
        """Register trusted delegation records, including revoked/expired state."""
        with self._lock:
            if complete:
                self._delegations.clear()
            for delegation in delegations:
                self._delegations[delegation.delegation_id] = delegation
            if complete:
                self._delegation_graph_complete = True

    def register_scope_dependencies(
        self,
        scope: InvalidationScope,
        entity_ids: list[str],
    ) -> None:
        """Register the authoritative entity set for a non-structural termination scope."""
        if scope not in {
            "CREDENTIAL_DEPENDENTS",
            "CAPABILITY_DEPENDENTS",
            "ORGANIZATIONAL_SCOPE",
        }:
            raise LifecycleTransitionError(f"scope dependency maps are not applicable to {scope}")
        with self._lock:
            self._scope_dependencies[scope] = set(entity_ids)

    def register_graph(
        self,
        *,
        entities: list[Entity],
        delegations: list[Delegation],
        scope_dependencies: dict[InvalidationScope, list[str]] | None = None,
    ) -> None:
        """Seed the manager once from the caller's authoritative governance graph."""
        with self._lock:
            self._scope_dependencies.clear()
            self.register_entities(entities, complete=True)
            self.register_delegations(delegations, complete=True)
            for scope, references in (scope_dependencies or {}).items():
                self.register_scope_dependencies(scope, references)

    def get_entity(self, entity_id: str) -> Entity | None:
        """Return the manager's current registered entity state by ID or EID."""
        with self._lock:
            return self._entities.get(entity_id)

    def get_delegation(self, delegation_id: str) -> Delegation | None:
        """Return the manager's current registered delegation state."""
        with self._lock:
            return self._delegations.get(delegation_id)

    def transition_entity(
        self,
        *,
        entity: Entity,
        to_status: EntityStatus | str,
        action_id: str,
        actor_entity_id: str,
        authority: Authority,
        event_id: str,
        request_id: str | None = None,
        invalidation_scope: InvalidationScope | None = None,
        affected_entity_ids: list[str] | None = None,
        invalidated_authority_ids: list[str] | None = None,
        known_entities: list[Entity] | None = None,
        scope_dependencies: dict[InvalidationScope, list[str]] | None = None,
        delegation_chain: list[Delegation] | None = None,
        known_delegations: list[Delegation] | None = None,
    ) -> LifecycleTransitionResult:
        with self._lock:
            if known_entities is not None:
                self.register_entities(known_entities, complete=True)
            if known_delegations is not None:
                self.register_delegations(known_delegations, complete=True)
            if scope_dependencies is not None:
                for scope, references in scope_dependencies.items():
                    self.register_scope_dependencies(scope, references)

            subject = (
                self._entities.get(entity.id) or self._entities.get(entity.eid or "") or entity
            )
            self.register_entities([subject])
            current_entities = list({item.id: item for item in self._entities.values()}.values())
            current_delegations = list(self._delegations.values())
            current_dependencies = {
                scope: sorted(references) for scope, references in self._scope_dependencies.items()
            }
            graph_entities = current_entities if self._entity_graph_complete else None
            graph_delegations = current_delegations if self._delegation_graph_complete else None
        self._lock.acquire()
        try:
            result = self._transition_entity(
                entity=subject,
                to_status=to_status,
                action_id=action_id,
                actor_entity_id=actor_entity_id,
                authority=authority,
                event_id=event_id,
                request_id=request_id,
                invalidation_scope=invalidation_scope,
                affected_entity_ids=affected_entity_ids,
                invalidated_authority_ids=invalidated_authority_ids,
                known_entities=graph_entities,
                scope_dependencies=current_dependencies,
                delegation_chain=delegation_chain,
                known_delegations=graph_delegations,
            )
            self.register_entities([result.entity, *result.affected_entities])
            self.register_delegations(list(result.invalidated_delegations))
            return result
        except LifecycleTransitionError as error:
            if "evidence persistence failed" not in str(error):
                self._record_rejected_operation(
                    event_type="AUTHORIZATION_FAILURE",
                    event="Entity lifecycle operation rejected",
                    entity_id=entity.eid or entity.id,
                    action_id=action_id,
                    actor_entity_id=actor_entity_id,
                    authority_id=authority.id,
                    request_id=request_id,
                    reason_code="LIFECYCLE_TRANSITION_REJECTED",
                )
            raise
        finally:
            self._lock.release()

    def _transition_entity(
        self,
        *,
        entity: Entity,
        to_status: EntityStatus | str,
        action_id: str,
        actor_entity_id: str,
        authority: Authority,
        event_id: str,
        request_id: str | None = None,
        invalidation_scope: InvalidationScope | None = None,
        affected_entity_ids: list[str] | None = None,
        invalidated_authority_ids: list[str] | None = None,
        known_entities: list[Entity] | None = None,
        scope_dependencies: dict[InvalidationScope, list[str]] | None = None,
        delegation_chain: list[Delegation] | None = None,
        known_delegations: list[Delegation] | None = None,
    ) -> LifecycleTransitionResult:
        """Transition an entity only under an active, scoped grant and log the result.

        Broader termination scopes require an explicit affected-entity and authority
        plan. Authority IDs in that plan must be derived from the supplied delegation
        ancestry; independent authority is never implicitly swept into a cascade.
        """
        from ettp.evidence import EvidenceEvent

        try:
            target = EntityStatus(to_status)
        except ValueError as error:
            raise LifecycleTransitionError(f"unknown lifecycle state: {to_status}") from error

        self._authorize_transition(
            authority=authority,
            actor_entity_id=actor_entity_id,
            entity=entity,
            target=target,
        )
        current = entity.status
        unchanged = current is target
        if not unchanged and target not in _TRANSITIONS[current]:
            raise LifecycleTransitionError(
                f"lifecycle transition {current.value} -> {target.value} is not permitted"
            )

        scope = invalidation_scope or "SELF"
        if target is not EntityStatus.TERMINATED and invalidation_scope is not None:
            raise LifecycleTransitionError("invalidation scope is only valid for termination")
        entity_ref_map = {
            reference: item.eid or item.id
            for item in known_entities or []
            for reference in {item.id, item.eid or item.id}
        }
        affected = sorted(
            {
                entity_ref_map.get(reference, reference)
                for reference in (affected_entity_ids or [entity.eid or entity.id])
            }
        )
        invalidated = sorted(set(invalidated_authority_ids or []))
        affected_entities: tuple[Entity, ...] = ()
        invalidated_delegations: tuple[Delegation, ...] = ()
        if target is EntityStatus.TERMINATED and scope != "SELF":
            if affected_entity_ids is None or invalidated_authority_ids is None:
                raise LifecycleTransitionError(
                    "non-self termination requires explicit affected entity and authority plans"
                )
            if known_entities is None:
                raise LifecycleTransitionError(
                    "scoped termination requires the known entity records"
                )
            if scope == "DESCENDANTS":
                if known_entities is None:
                    raise LifecycleTransitionError(
                        "descendant termination requires the known entity relationship graph"
                    )
                expected_affected = self._entity_descendants(entity, known_entities)
                if set(affected) != expected_affected:
                    raise LifecycleTransitionError(
                        "termination affected entities do not match the descendant graph"
                    )
            elif scope in {
                "CREDENTIAL_DEPENDENTS",
                "CAPABILITY_DEPENDENTS",
                "ORGANIZATIONAL_SCOPE",
            }:
                declared_dependencies = (scope_dependencies or {}).get(scope)
                if declared_dependencies is None:
                    raise LifecycleTransitionError(
                        f"{scope} termination requires its explicit dependency graph"
                    )
                expected_affected = {
                    entity_ref_map.get(reference, reference) for reference in declared_dependencies
                }
                if set(affected) != expected_affected:
                    raise LifecycleTransitionError(
                        f"termination affected entities do not match the {scope} dependency graph"
                    )
            if known_delegations is None:
                raise LifecycleTransitionError(
                    "scoped termination requires the known delegation graph"
                )
            derived_delegation_ids = self._derived_delegation_ids(
                entity=entity,
                delegations=known_delegations or [],
                delegation_chain=delegation_chain or [],
            )

            if scope in {
                "DESCENDANTS",
                "CREDENTIAL_DEPENDENTS",
                "CAPABILITY_DEPENDENTS",
                "ORGANIZATIONAL_SCOPE",
            }:
                selected_delegation_ids = self._delegations_for_grantees(
                    derived_delegation_ids,
                    known_delegations,
                    set(affected),
                    entity_ref_map,
                )
            elif scope == "DELEGATION_CHAIN":
                selected_delegation_ids = derived_delegation_ids
            else:
                selected_delegation_ids = {
                    item.delegation_id
                    for item in known_delegations
                    if item.delegation_id in derived_delegation_ids
                    and (
                        item.authority.id
                        if isinstance(item.authority, Authority)
                        else f"{item.delegation_id}:authority"
                    )
                    in invalidated
                }

            expected_authorities = {
                item.authority.id
                if isinstance(item.authority, Authority)
                else f"{item.delegation_id}:authority"
                for item in known_delegations
                if item.delegation_id in selected_delegation_ids
            }
            if set(invalidated) != expected_authorities:
                raise LifecycleTransitionError(
                    "termination authority plan does not match the derived delegation scope"
                )
            if scope == "DELEGATION_CHAIN":
                expected_affected = {
                    entity_ref_map.get(item.grantee, item.grantee)
                    for item in (known_delegations or [])
                    if item.delegation_id in selected_delegation_ids
                }
                if set(affected) != expected_affected:
                    raise LifecycleTransitionError(
                        "termination affected entities do not match the delegation graph"
                    )
            invalidated_delegations = tuple(
                item.model_copy(
                    update={"status": "REVOKED", "revocation_reference": event_id},
                    deep=True,
                )
                for item in known_delegations
                if item.delegation_id in selected_delegation_ids
            )
            if known_entities is not None:
                known_by_reference = {
                    reference: item
                    for item in known_entities or []
                    for reference in {item.id, item.eid or item.id}
                }
                affected_entities = tuple(
                    known_by_reference[reference].model_copy(
                        update={"status": EntityStatus.TERMINATED},
                        deep=True,
                    )
                    for reference in affected
                    if reference in known_by_reference
                )

        event_type = self._event_type(current, target, unchanged)
        event = EvidenceEvent.from_governance_event(
            event_id=event_id,
            event_type=event_type,
            event=(
                f"Idempotent lifecycle request for {target.value}"
                if unchanged
                else f"Entity lifecycle transition {current.value} -> {target.value}"
            ),
            entity_id=entity.eid or entity.id,
            action_id=action_id,
            actor_entity_id=actor_entity_id,
            authority_id=authority.id,
            request_id=request_id,
            delegation_chain=(
                [item.delegation_id for item in delegation_chain] if delegation_chain else None
            ),
            from_lifecycle_state=current.value,
            to_lifecycle_state=target.value,
            lifecycle_state=target.value,
            invalidation_scope=scope if target is EntityStatus.TERMINATED else None,
            affected_entity_ids=affected if target is EntityStatus.TERMINATED else None,
            invalidated_authority_ids=invalidated if target is EntityStatus.TERMINATED else None,
        )
        try:
            persisted = self._evidence_store.append(event)
        except Exception as error:
            raise LifecycleTransitionError(
                f"lifecycle transition was not applied because evidence persistence failed: "
                f"{type(error).__name__}"
            ) from error

        result_entity = (
            entity
            if unchanged
            else Entity.model_validate(entity.model_dump(mode="python") | {"status": target})
        )
        return LifecycleTransitionResult(
            entity=result_entity,
            event=persisted,
            changed=not unchanged,
            affected_entities=affected_entities,
            invalidated_delegations=invalidated_delegations,
        )

    def revoke_delegation_tree(
        self,
        *,
        delegation_id: str,
        delegations: list[Delegation] | None = None,
        action_id: str,
        actor_entity_id: str,
        authority: Authority,
        event_id: str,
        request_id: str | None = None,
    ) -> DelegationRevocationResult:
        with self._lock:
            if delegations is not None:
                self.register_delegations(delegations, complete=True)
            graph = list(self._delegations.values())
            graph_complete = self._delegation_graph_complete
        self._lock.acquire()
        try:
            if not graph_complete:
                raise LifecycleTransitionError(
                    "delegation revocation requires a complete registered delegation graph"
                )
            result = self._revoke_delegation_tree(
                delegation_id=delegation_id,
                delegations=graph,
                action_id=action_id,
                actor_entity_id=actor_entity_id,
                authority=authority,
                event_id=event_id,
                request_id=request_id,
            )
            self.register_delegations(list(result.delegations), complete=True)
            return result
        except LifecycleTransitionError as error:
            if "evidence persistence failed" not in str(error):
                target = next(
                    (item for item in graph if item.delegation_id == delegation_id),
                    None,
                )
                self._record_rejected_operation(
                    event_type="AUTHORIZATION_FAILURE",
                    event="Delegation revocation operation rejected",
                    entity_id=target.grantee if target else delegation_id,
                    action_id=action_id,
                    actor_entity_id=actor_entity_id,
                    authority_id=authority.id,
                    request_id=request_id,
                    reason_code="DELEGATION_REVOCATION_REJECTED",
                    references=[delegation_id],
                )
            raise
        finally:
            self._lock.release()

    def _revoke_delegation_tree(
        self,
        *,
        delegation_id: str,
        delegations: list[Delegation],
        action_id: str,
        actor_entity_id: str,
        authority: Authority,
        event_id: str,
        request_id: str | None = None,
    ) -> DelegationRevocationResult:
        """Revoke a delegation and every descendant derived from that grant.

        Independent delegation roots are not included. A malformed, cyclic, or
        ambiguous ancestry fails closed without changing the supplied models.
        """
        from ettp.evidence import EvidenceEvent, EvidenceEventType

        by_id = {item.delegation_id: item for item in delegations}
        if len(by_id) != len(delegations):
            raise LifecycleTransitionError("delegation IDs are not unique")
        authority_ids = [
            item.authority.id
            if isinstance(item.authority, Authority)
            else f"{item.delegation_id}:authority"
            for item in delegations
        ]
        if len(authority_ids) != len(set(authority_ids)):
            raise LifecycleTransitionError("delegated authority IDs are not unique")
        root = by_id.get(delegation_id)
        if root is None:
            raise LifecycleTransitionError(f"delegation not found: {delegation_id}")
        self._authorize_delegation_revocation(
            authority,
            actor_entity_id,
            root,
        )

        selected = [root]
        selected_ids = {root.delegation_id}
        frontier = [root.delegation_id]
        while frontier:
            parent_id = frontier.pop(0)
            children = sorted(
                (item for item in delegations if item.parent_delegation == parent_id),
                key=lambda item: item.delegation_id,
            )
            for child in children:
                if child.delegation_id in selected_ids:
                    raise LifecycleTransitionError("delegation ancestry contains a cycle")
                parent = by_id[parent_id]
                if child.grantor != parent.grantee:
                    raise LifecycleTransitionError(
                        "delegation descendant grantor does not match its parent grantee"
                    )
                selected.append(child)
                selected_ids.add(child.delegation_id)
                frontier.append(child.delegation_id)

        changed = any(item.status != "REVOKED" for item in selected)
        revoked = tuple(
            item.model_copy(
                update={"status": "REVOKED", "revocation_reference": event_id},
                deep=True,
            )
            for item in selected
        )
        authority_ids = sorted(
            {
                item.authority.id
                if isinstance(item.authority, Authority)
                else f"{item.delegation_id}:authority"
                for item in selected
            }
        )
        affected_entities = sorted({item.grantee for item in selected})
        revocation = Revocation(
            id=event_id,
            target_type="delegation",
            target_id=delegation_id,
            action="REVOKE_DELEGATION",
            actor=actor_entity_id,
            issued_at=datetime.now(UTC),
            status="ACTIVE",
        )
        event = EvidenceEvent.from_governance_event(
            event_id=event_id,
            event_type=(
                EvidenceEventType.LIFECYCLE_TRANSITION_NOOP
                if not changed
                else EvidenceEventType.DELEGATION_CHAIN_INVALIDATED
                if len(selected) > 1
                else EvidenceEventType.DELEGATION_REVOKED
            ),
            event=(
                "Delegation revocation was already applied"
                if not changed
                else "Delegation revoked and derived descendant authority invalidated"
            ),
            entity_id=root.grantee,
            action_id=action_id,
            actor_entity_id=actor_entity_id,
            authority_id=authority.id,
            request_id=request_id,
            delegation_chain=[item.delegation_id for item in selected],
            references=[item.delegation_id for item in selected],
            affected_entity_ids=affected_entities,
            invalidated_authority_ids=authority_ids,
            lifecycle_state="REVOKED",
            enforcement="DERIVED_AUTHORITY_INVALIDATED",
        )
        try:
            persisted = self._evidence_store.append(event)
        except Exception as error:
            raise LifecycleTransitionError(
                f"delegation revocation was not applied because evidence persistence failed: "
                f"{type(error).__name__}"
            ) from error
        return DelegationRevocationResult(
            revocation=revocation,
            delegations=revoked,
            event=persisted,
            changed=changed,
        )

    def _record_rejected_operation(
        self,
        *,
        event_type: str,
        event: str,
        entity_id: str,
        action_id: str,
        actor_entity_id: str,
        authority_id: str,
        request_id: str | None,
        reason_code: str,
        references: list[str] | None = None,
    ) -> None:
        from ettp.evidence import EvidenceEvent, EvidenceEventType

        try:
            self._evidence_store.append(
                EvidenceEvent.from_governance_event(
                    event_id=f"evt_{uuid4().hex}",
                    event_type=EvidenceEventType(event_type),
                    event=event,
                    entity_id=entity_id,
                    action_id=action_id,
                    actor_entity_id=actor_entity_id,
                    authority_id=authority_id,
                    request_id=request_id,
                    decision="BLOCK",
                    enforcement="REJECTED",
                    references=references,
                    extensions={"reason_code": reason_code},
                )
            )
        except Exception as error:
            raise LifecycleTransitionError(
                f"governance operation was rejected and rejection evidence could not be persisted: "
                f"{type(error).__name__}"
            ) from error

    @staticmethod
    def _authorize_delegation_revocation(
        authority: Authority,
        actor_entity_id: str,
        delegation: Delegation,
    ) -> None:
        now = datetime.now(UTC)
        if authority.grantee != actor_entity_id:
            raise LifecycleTransitionError("authority grantee does not match the acting entity")
        if authority.issued_at is not None and _utc(authority.issued_at) > now:
            raise LifecycleTransitionError("authority is not active yet")
        if authority.expires_at is not None and _utc(authority.expires_at) <= now:
            raise LifecycleTransitionError("authority has expired")
        permitted = {"delegation.revoke", "delegation.revoke.any"}
        if authority.action not in permitted and not (set(authority.capabilities) & permitted):
            raise LifecycleTransitionError("authority does not permit delegation revocation")
        global_revocation = "delegation.revoke.any" in authority.capabilities
        if delegation.grantor != actor_entity_id and not global_revocation:
            raise LifecycleTransitionError("actor is not the delegation grantor")
        if authority.scope not in {None, "*", delegation.delegation_id}:
            raise LifecycleTransitionError("authority scope does not cover the delegation")
        allowed_delegations = authority.constraints.get("allowed_delegation_ids")
        if allowed_delegations is not None and delegation.delegation_id not in allowed_delegations:
            raise LifecycleTransitionError(
                "authority constraints do not permit revoking this delegation"
            )

    @staticmethod
    def _authorize_transition(
        *,
        authority: Authority,
        actor_entity_id: str,
        entity: Entity,
        target: EntityStatus,
    ) -> None:
        now = datetime.now(UTC)
        if authority.grantee != actor_entity_id:
            raise LifecycleTransitionError("authority grantee does not match the acting entity")
        if authority.issued_at is not None and _utc(authority.issued_at) > now:
            raise LifecycleTransitionError("authority is not active yet")
        if authority.expires_at is not None and _utc(authority.expires_at) <= now:
            raise LifecycleTransitionError("authority has expired")
        if authority.scope not in {None, "*", entity.id, entity.eid}:
            raise LifecycleTransitionError("authority scope does not cover the affected entity")

        operation = {
            EntityStatus.ACTIVE: "entity.resume",
            EntityStatus.SUSPENDED: "entity.suspend",
            EntityStatus.REVOKED: "entity.revoke",
            EntityStatus.EXPIRED: "entity.expire",
            EntityStatus.TERMINATED: "entity.terminate",
            EntityStatus.PROPOSED: "entity.propose",
        }[target]
        permitted = {operation}
        if target is EntityStatus.TERMINATED:
            if authority.action not in permitted and not (set(authority.capabilities) & permitted):
                raise LifecycleTransitionError(
                    "termination requires explicit emergency termination authority"
                )
        else:
            permitted.add("entity.lifecycle.transition")
        if authority.action not in permitted and not (set(authority.capabilities) & permitted):
            raise LifecycleTransitionError("authority does not permit this lifecycle command")
        allowed_states = authority.constraints.get("allowed_states")
        if allowed_states is not None and target.value not in allowed_states:
            raise LifecycleTransitionError("authority constraints do not permit the target state")

    @staticmethod
    def _event_type(
        current: EntityStatus,
        target: EntityStatus,
        unchanged: bool,
    ) -> EvidenceEventType:
        from ettp.evidence import EvidenceEventType

        if unchanged:
            return EvidenceEventType.LIFECYCLE_TRANSITION_NOOP
        if current is EntityStatus.SUSPENDED and target is EntityStatus.ACTIVE:
            return EvidenceEventType.ENTITY_RESUMED
        return {
            EntityStatus.PROPOSED: EvidenceEventType.ENTITY_LIFECYCLE_TRANSITION,
            EntityStatus.ACTIVE: EvidenceEventType.ENTITY_ACTIVATED,
            EntityStatus.SUSPENDED: EvidenceEventType.ENTITY_SUSPENDED,
            EntityStatus.REVOKED: EvidenceEventType.ENTITY_REVOKED,
            EntityStatus.EXPIRED: EvidenceEventType.ENTITY_EXPIRED,
            EntityStatus.TERMINATED: EvidenceEventType.ENTITY_TERMINATED,
        }[target]

    @staticmethod
    def _derived_authorities(
        *,
        entity: Entity,
        delegations: list[Delegation],
        delegation_chain: list[Delegation],
    ) -> set[str]:
        """Find only authority IDs attached to delegations rooted at this entity."""
        ids = {item.delegation_id: item for item in delegations}
        ids.update({item.delegation_id: item for item in delegation_chain})
        affected = LifecycleManager._derived_delegation_ids(
            entity=entity,
            delegations=list(ids.values()),
            delegation_chain=[],
        )
        authority_ids: set[str] = set()
        for delegation_id in affected:
            item = ids[delegation_id]
            authority_ids.add(
                item.authority.id
                if isinstance(item.authority, Authority)
                else f"{item.delegation_id}:authority"
            )
        return authority_ids

    @staticmethod
    def _derived_delegation_ids(
        *,
        entity: Entity,
        delegations: list[Delegation],
        delegation_chain: list[Delegation],
    ) -> set[str]:
        ids = {item.delegation_id: item for item in delegations}
        ids.update({item.delegation_id: item for item in delegation_chain})
        roots = {entity.id, entity.eid}
        affected = {item.delegation_id for item in ids.values() if item.grantor in roots}
        changed = True
        while changed:
            changed = False
            for item in ids.values():
                if item.parent_delegation in affected and item.delegation_id not in affected:
                    parent = ids[item.parent_delegation]
                    if item.grantor != parent.grantee:
                        raise LifecycleTransitionError(
                            "delegation descendant grantor does not match its parent grantee"
                        )
                    affected.add(item.delegation_id)
                    changed = True
        for delegation_id in affected:
            visited: set[str] = set()
            current_id: str | None = delegation_id
            while current_id is not None:
                if current_id in visited:
                    raise LifecycleTransitionError("delegation ancestry contains a cycle")
                visited.add(current_id)
                current: Delegation | None = ids.get(current_id)
                if current is None:
                    raise LifecycleTransitionError(
                        f"delegation ancestry references an unknown parent: {current_id}"
                    )
                if current.parent_delegation is not None:
                    ancestor = ids.get(current.parent_delegation)
                    if ancestor is None:
                        raise LifecycleTransitionError(
                            f"delegation ancestry references an unknown parent: "
                            f"{current.parent_delegation}"
                        )
                    if current.grantor != ancestor.grantee:
                        raise LifecycleTransitionError(
                            "delegation descendant grantor does not match its parent grantee"
                        )
                current_id = current.parent_delegation
        return affected

    @staticmethod
    def _delegations_for_grantees(
        derived_ids: set[str],
        delegations: list[Delegation],
        affected_entities: set[str],
        entity_ref_map: dict[str, str],
    ) -> set[str]:
        by_id = {item.delegation_id: item for item in delegations}
        selected = {
            item.delegation_id
            for item in delegations
            if item.delegation_id in derived_ids
            and entity_ref_map.get(item.grantee, item.grantee) in affected_entities
        }
        changed = True
        while changed:
            changed = False
            for item in delegations:
                if (
                    item.delegation_id in derived_ids
                    and item.parent_delegation in selected
                    and item.delegation_id not in selected
                ):
                    selected.add(item.delegation_id)
                    changed = True
        if any(item_id not in by_id for item_id in selected):
            raise LifecycleTransitionError("delegation cascade references an unknown delegation")
        return selected

    @staticmethod
    def _entity_descendants(entity: Entity, entities: list[Entity]) -> set[str]:
        """Resolve known descendants from explicit directional control relationships."""
        forward = {"subAgentOf", "parentOf", "controls", "governs", "delegatesTo"}
        reverse = {"childOf", "controlledBy", "governedBy"}
        edges: dict[str, set[str]] = {}
        known_ids: set[str] = set()
        for item in entities:
            known_ids.update({item.id, item.eid or item.id})
            for relationship in item.relationships or []:
                if relationship.relationship in forward:
                    edges.setdefault(relationship.source, set()).add(relationship.target)
                elif relationship.relationship in reverse:
                    edges.setdefault(relationship.target, set()).add(relationship.source)
        roots = {entity.id, entity.eid or entity.id}
        visited = set(roots)
        frontier = list(roots)
        while frontier:
            parent = frontier.pop(0)
            for child in sorted(edges.get(parent, set())):
                if child in visited:
                    continue
                visited.add(child)
                frontier.append(child)
        return {reference for reference in visited - roots if reference in known_ids}


def _utc(value: datetime) -> datetime:
    """Interpret naive protocol timestamps as UTC for deterministic checks."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
