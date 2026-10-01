from __future__ import annotations

from ettp import Decision, Policy
from schema_support import SCHEMA_ROOT, load_json, make_validator


def test_logical_policy_condition_serializes_to_schema() -> None:
    policy = Policy(
        id="p.logical",
        version="1",
        effect="ALLOW",
        conditions=[
            {
                "any": [
                    {"field": "action.operation", "operator": "equals", "value": "refund"},
                    {
                        "not": {
                            "field": "action.operation",
                            "operator": "equals",
                            "value": "delete",
                        }
                    },
                ]
            }
        ],
        priority=5,
    )

    make_validator(load_json(SCHEMA_ROOT / "policy.schema.json")).validate(
        policy.model_dump(mode="json")
    )


def test_structured_decision_metadata_serializes_to_schema() -> None:
    decision = Decision(
        id="d1",
        action_id="a1",
        effect="ALLOW",
        policy_id="p.logical",
        policy_version="1",
        reason_code="POLICY_ALLOW",
        matched_conditions=["matched"],
        failed_conditions=["did not match"],
    )

    make_validator(load_json(SCHEMA_ROOT / "decision.schema.json")).validate(
        decision.model_dump(mode="json")
    )
