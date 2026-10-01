from __future__ import annotations

import pytest
from jsonschema.exceptions import ValidationError as SchemaValidationError
from pydantic import ValidationError

from ettp import Action, ActionContext, Entity
from ettp.identity import Authority, Delegation, EntityRelationship, Revocation
from ettp.policy import Policy, PolicyEngine, PolicyRegistry


def test_entity_supports_eid_and_relationships() -> None:
    entity = Entity.model_validate(
        {
            "id": "entity-1",
            "eid": "EID:entity:1",
            "type": "AI_AGENT",
            "name": "Alpha",
            "version": "1.0",
            "issuer": "issuer-1",
            "owner": "owner-1",
            "capabilities": ["refund", "read"],
            "metadata": {"region": "us"},
            "protocol_version": "0.1",
            "relationships": [
                {
                    "source": "EID:root",
                    "relationship": "controls",
                    "target": "EID:entity:1",
                    "metadata": {"strength": "strong"},
                }
            ],
        }
    )

    assert entity.eid == "EID:entity:1"
    assert isinstance(entity.relationships, list)
    assert entity.relationships[0].relationship == "controls"


def test_delegation_attentuates_authority_and_tracks_depth() -> None:
    root = Delegation(
        delegation_id="delegation-root",
        grantor="root",
        grantee="agent-a",
        authority=Authority(
            id="auth-root",
            action="payment.refund",
            capabilities=["refund"],
            constraints={"max_amount": 1000},
        ),
        capabilities=["refund"],
        constraints={"max_amount": 1000},
        scope="payment",
        status="ACTIVE",
        max_delegation_depth=3,
    )

    child = Delegation(
        delegation_id="delegation-child",
        grantor="agent-a",
        grantee="agent-b",
        authority=Authority(
            id="auth-child",
            action="payment.refund",
            capabilities=["refund"],
            constraints={"max_amount": 500},
        ),
        capabilities=["refund"],
        constraints={"max_amount": 500},
        scope="payment",
        parent_delegation=root.delegation_id,
        status="ACTIVE",
        max_delegation_depth=3,
    )

    assert child.depth == 1
    assert child.attenuated_authority([root]).constraints["max_amount"] == 500
    assert child.chain() == [root.delegation_id, child.delegation_id]


def test_delegation_cannot_widen_capabilities_or_constraints() -> None:
    delegation = Delegation(
        delegation_id="delegation-narrowed",
        grantor="agent-a",
        grantee="agent-b",
        authority=Authority(
            id="auth-parent",
            action="payment.refund",
            capabilities=["refund", "read"],
            constraints={"max_amount": 500, "denied_operations": ["delete"]},
            scope="payments/merchant-1",
        ),
        capabilities=["refund", "admin"],
        constraints={"max_amount": 900, "denied_operations": ["export"]},
        scope="payments/merchant-1/refunds",
    )

    attenuated = delegation.attenuated_authority()

    assert attenuated.capabilities == ["refund"]
    assert attenuated.constraints["max_amount"] == 500
    assert attenuated.constraints["denied_operations"] == ["delete", "export"]
    assert attenuated.scope == "payments/merchant-1/refunds"


def test_string_child_delegation_cannot_expand_parent_authority() -> None:
    parent = Delegation(
        delegation_id="parent-1",
        grantor="root",
        grantee="agent-a",
        authority=Authority(
            id="auth-parent",
            action="payment.refund",
            capabilities=["refund"],
            constraints={"max_amount": 100},
            scope="payment",
        ),
        capabilities=["refund"],
        constraints={"max_amount": 100},
        scope="payment",
    )
    child = Delegation(
        delegation_id="child-1",
        grantor="agent-a",
        grantee="agent-b",
        authority="payment.refund",
        capabilities=["refund", "admin"],
        constraints={"max_amount": 500},
        scope="payment/refund",
        parent_delegation=parent.delegation_id,
    )

    attenuated = child.attenuated_authority([parent])

    assert attenuated.capabilities == ["refund"]
    assert attenuated.constraints["max_amount"] == 100
    assert attenuated.scope == "payment/refund"


def test_child_authority_cannot_be_attenuated_without_parent_record() -> None:
    child = Delegation(
        delegation_id="child-missing-parent",
        grantor="agent-a",
        grantee="agent-b",
        authority="payment.refund",
        capabilities=["refund"],
        parent_delegation="unknown-parent",
    )

    with pytest.raises(ValueError, match="parent delegation is required"):
        child.attenuated_authority()


def test_delegation_rejects_scope_outside_parent_authority() -> None:
    delegation = Delegation(
        delegation_id="delegation-broad-scope",
        grantor="agent-a",
        grantee="agent-b",
        authority=Authority(
            id="auth-parent",
            action="payment.refund",
            capabilities=["refund"],
            scope="payments/merchant-1",
        ),
        capabilities=["refund"],
        scope="payments/merchant-10",
    )

    with pytest.raises(ValueError, match="scope exceeds"):
        delegation.attenuated_authority()


def test_delegation_depth_limit_is_enforced() -> None:
    with pytest.raises(ValidationError):
        Delegation(
            delegation_id="delegation-deep",
            grantor="agent-c",
            grantee="agent-d",
            authority=Authority(
                id="auth-deep",
                action="payment.refund",
                capabilities=["refund"],
                constraints={"max_amount": 50},
            ),
            capabilities=["refund"],
            constraints={"max_amount": 50},
            scope="payment",
            depth=4,
            max_delegation_depth=3,
            status="ACTIVE",
        )


def test_revocation_is_explicitly_typed() -> None:
    revocation = Revocation(
        id="revoke-1",
        target_type="delegation",
        target_id="delegation-child",
        action="REVOKE_DELEGATION",
        reason="delegation was cancelled",
    )

    assert revocation.target_type == "delegation"
    assert revocation.action == "REVOKE_DELEGATION"


def test_policy_engine_rejects_over_depth_delegation() -> None:
    registry = PolicyRegistry()
    registry.register(
        Policy(
            id="policy.refund",
            version="1",
            effect="ALLOW",
            conditions=[],
        )
    )
    action = Action(
        id="act-1",
        entity_id="entity-1",
        type="TOOL_CALL",
        target="refund_customer",
        operation="refund",
        arguments={"amount": 100},
        context=ActionContext(
            entity_eid="EID:entity:1",
            authority="payment.refund",
            delegation="deep-delegation",
        ),
    )
    entity = Entity(
        id="entity-1",
        eid="EID:entity:1",
        type="AI_AGENT",
        name="Alpha",
        version="1.0",
        capabilities=["refund"],
        metadata={"region": "us"},
        protocol_version="0.1",
    )
    delegation = Delegation(
        delegation_id="deep-delegation",
        grantor="root",
        grantee="entity-1",
        authority=Authority(
            id="auth-deep",
            action="payment.refund",
            capabilities=["refund"],
            constraints={"max_amount": 50},
        ),
        capabilities=["refund"],
        constraints={"max_amount": 50},
        scope="payment",
        status="ACTIVE",
        depth=3,
        max_delegation_depth=3,
    )

    decision = PolicyEngine(registry).evaluate(
        entity=entity,
        action=action,
        context=action.context,
        delegation=delegation,
    )

    assert decision.effect == "BLOCK"
    assert "delegation depth" in (decision.reason or "").lower()


def test_policy_engine_rejects_revoked_delegation() -> None:
    registry = PolicyRegistry()
    registry.register(
        Policy(
            id="policy.refund",
            version="1",
            effect="ALLOW",
            conditions=[],
        )
    )
    entity = Entity(
        id="entity-1",
        eid="EID:entity:1",
        type="AI_AGENT",
        name="Alpha",
        version="1.0",
        capabilities=["refund"],
        metadata={"region": "us"},
        protocol_version="0.1",
    )
    action = Action(
        id="act-2",
        entity_id="entity-1",
        type="TOOL_CALL",
        target="refund_customer",
        operation="refund",
        arguments={"amount": 10},
        context=ActionContext(
            entity_eid="EID:entity:1",
            authority="payment.refund",
            delegation="delegation-revoked",
        ),
    )
    delegation = Delegation(
        delegation_id="delegation-revoked",
        grantor="root",
        grantee="entity-1",
        authority=Authority(
            id="auth-revoked",
            action="payment.refund",
            capabilities=["refund"],
            constraints={"max_amount": 500},
        ),
        capabilities=["refund"],
        constraints={"max_amount": 500},
        scope="payment",
        status="REVOKED",
        revocation_reference="revoke-1",
        max_delegation_depth=3,
    )

    decision = PolicyEngine(registry).evaluate(
        entity=entity,
        action=action,
        context=action.context,
        delegation=delegation,
    )

    assert decision.effect == "BLOCK"
    assert "not active" in (decision.reason or "").lower()


def test_policy_engine_requires_explicit_emergency_authority_for_control_tree() -> None:
    registry = PolicyRegistry()
    registry.register(
        Policy(
            id="policy.kill",
            version="1",
            effect="ALLOW",
            conditions=[],
        )
    )
    entity = Entity(
        id="sub-agent",
        eid="EID:sub-agent",
        type="AI_AGENT",
        name="Beta",
        version="1.0",
        capabilities=["terminate"],
        metadata={"region": "us"},
        protocol_version="0.1",
        relationships=[
            EntityRelationship(
                source="EID:root-agent",
                relationship="subAgentOf",
                target="EID:sub-agent",
            )
        ],
    )
    action = Action(
        id="act-3",
        entity_id="sub-agent",
        type="CONTROL",
        target="root-agent",
        operation="terminate",
        arguments={"reason": "emergency"},
        context=ActionContext(
            entity_eid="EID:sub-agent",
            emergency_authority=False,
        ),
    )

    decision = PolicyEngine(registry).evaluate(entity=entity, action=action, context=action.context)

    assert decision.effect == "BLOCK"
    assert "control tree" in (decision.reason or "").lower()

    action.context = ActionContext(
        entity_eid="EID:sub-agent",
        emergency_authority=True,
        authority="control.emergency",
    )
    decision = PolicyEngine(registry).evaluate(
        entity=entity,
        action=action,
        context=action.context,
        authority=Authority(
            id="auth-emergency",
            action="control.emergency",
            capabilities=["terminate"],
            constraints={"mode": "emergency"},
        ),
    )

    assert decision.effect == "ALLOW"


def test_delegation_chain_provenance_is_validated() -> None:
    root = Delegation(
        delegation_id="root-del",
        grantor="root",
        grantee="agent-a",
        authority=Authority(
            id="auth-root",
            action="payment.refund",
            capabilities=["refund"],
            constraints={"max_amount": 1000},
        ),
        capabilities=["refund"],
        constraints={"max_amount": 1000},
        scope="payment",
        status="ACTIVE",
        max_delegation_depth=3,
    )
    child = Delegation(
        delegation_id="child-del",
        grantor="agent-a",
        grantee="agent-b",
        authority=Authority(
            id="auth-child",
            action="payment.refund",
            capabilities=["refund"],
            constraints={"max_amount": 250},
        ),
        capabilities=["refund"],
        constraints={"max_amount": 250},
        scope="payment",
        parent_delegation="root-del",
        status="ACTIVE",
        max_delegation_depth=3,
    )

    assert root.chain() == ["root-del"]
    assert child.chain() == ["root-del", "child-del"]

    with pytest.raises(ValueError):
        Delegation(
            delegation_id="bad-chain",
            grantor="agent-b",
            grantee="agent-c",
            authority=Authority(
                id="auth-bad",
                action="payment.refund",
                capabilities=["refund"],
                constraints={"max_amount": 10},
            ),
            capabilities=["refund"],
            constraints={"max_amount": 10},
            scope="payment",
            parent_delegation="missing-parent",
            status="ACTIVE",
            max_delegation_depth=2,
        ).validate_chain([root, child])


def test_sprint5a_schema_examples_validate() -> None:
    from schema_support import SCHEMA_ROOT, load_json, make_validator

    for schema_name, fixture_name in [
        ("authority.schema.json", "authority.json"),
        ("delegation.schema.json", "delegation.json"),
        ("revocation.schema.json", "revocation.json"),
        ("relationship.schema.json", "relationship.json"),
    ]:
        schema = load_json(SCHEMA_ROOT / schema_name)
        fixture = load_json(SCHEMA_ROOT / "examples" / "valid" / fixture_name)
        make_validator(schema).validate(fixture)


def test_sprint5a_negative_schema_examples_are_rejected() -> None:
    from schema_support import SCHEMA_ROOT, load_json, make_validator

    invalid = {
        "id": "",
        "action": "payment.refund",
        "capabilities": ["refund"],
        "constraints": {"max_amount": 1000},
    }
    with pytest.raises(SchemaValidationError):
        make_validator(load_json(SCHEMA_ROOT / "authority.schema.json")).validate(invalid)

    invalid_delegation = {
        "delegation_id": "delegation-2",
        "grantor": "root",
        "grantee": "agent-1",
        "authority": {
            "id": "auth-2",
            "action": "payment.refund",
            "capabilities": ["refund"],
            "constraints": {"max_amount": 1000},
        },
        "capabilities": ["refund"],
        "constraints": {"max_amount": 1000},
        "status": "ACTIVE",
        "depth": 10,
        "max_delegation_depth": 3,
    }
    with pytest.raises(SchemaValidationError):
        make_validator(load_json(SCHEMA_ROOT / "delegation.schema.json")).validate(
            invalid_delegation
        )
