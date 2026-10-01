from __future__ import annotations

import json

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import BaseModel, ValidationError

from ettp import Action, Capability, Decision, Entity, Evidence, Identity, Policy, Resource
from schema_support import SCHEMA_ROOT, load_json, make_validator

MODEL_FIXTURES: tuple[tuple[type[BaseModel], str, str], ...] = (
    (Entity, "entity.schema.json", "entity.json"),
    (Identity, "identity.schema.json", "identity.json"),
    (Capability, "capability.schema.json", "capability.json"),
    (Action, "action.schema.json", "action.json"),
    (Resource, "resource.schema.json", "resource.json"),
    (Policy, "policy.schema.json", "policy.json"),
    (Decision, "decision.schema.json", "decision.json"),
    (Evidence, "evidence.schema.json", "evidence.json"),
)

INVALID_FIXTURES: tuple[tuple[type[BaseModel], str], ...] = (
    (Entity, "entity-missing-id.json"),
    (Identity, "identity-invalid-status.json"),
    (Capability, "capability-missing-name.json"),
    (Action, "action-missing-entity.json"),
    (Action, "action-missing-target.json"),
    (Action, "action-invalid-arguments.json"),
    (Resource, "resource-invalid-type.json"),
    (Policy, "policy-invalid-effect.json"),
    (Decision, "decision-invalid-effect.json"),
    (Evidence, "evidence-missing-action.json"),
)

INVALID_VALUES: tuple[tuple[type[BaseModel], str, str, object], ...] = (
    (Entity, "entity.json", "id", 123),
    (Identity, "identity.json", "status", "INVALID"),
    (Capability, "capability.json", "name", ""),
    (Action, "action.json", "arguments", []),
    (Resource, "resource.json", "metadata", []),
    (Policy, "policy.json", "conditions", [{}]),
    (Decision, "decision.json", "effect", "INVALID"),
    (Evidence, "evidence.json", "timestamp", "not-a-timestamp"),
)


@pytest.mark.parametrize(("model", "schema_filename", "fixture_filename"), MODEL_FIXTURES)
def test_valid_fixture_loads_and_serializes_to_schema(
    model: type[BaseModel], schema_filename: str, fixture_filename: str
) -> None:
    fixture = load_json(SCHEMA_ROOT / "examples" / "valid" / fixture_filename)
    schema = load_json(SCHEMA_ROOT / schema_filename)

    instance = model.model_validate(fixture)
    serialized = instance.model_dump(mode="json")

    make_validator(schema).validate(serialized)
    assert model.model_validate(serialized).model_dump(mode="json") == serialized


@pytest.mark.parametrize(("model", "schema_filename", "fixture_filename"), MODEL_FIXTURES)
def test_model_dump_json_is_schema_compatible_and_stable(
    model: type[BaseModel], schema_filename: str, fixture_filename: str
) -> None:
    fixture = load_json(SCHEMA_ROOT / "examples" / "valid" / fixture_filename)
    schema = load_json(SCHEMA_ROOT / schema_filename)
    instance = model.model_validate(fixture)

    json_output = instance.model_dump_json()

    assert json.loads(json_output) == instance.model_dump(mode="json")
    assert json_output == instance.model_dump_json()
    make_validator(schema).validate(json.loads(json_output))


@pytest.mark.parametrize(("model", "fixture_filename"), INVALID_FIXTURES)
def test_invalid_fixture_is_rejected(model: type[BaseModel], fixture_filename: str) -> None:
    fixture = load_json(SCHEMA_ROOT / "examples" / "invalid" / fixture_filename)

    with pytest.raises(ValidationError):
        model.model_validate(fixture)


@pytest.mark.parametrize(("model", "fixture_filename", "field", "value"), INVALID_VALUES)
def test_invalid_field_values_are_rejected(
    model: type[BaseModel], fixture_filename: str, field: str, value: object
) -> None:
    payload = load_json(SCHEMA_ROOT / "examples" / "valid" / fixture_filename)
    payload[field] = value

    with pytest.raises(ValidationError):
        model.model_validate(payload)


def test_unexpected_top_level_fields_are_rejected() -> None:
    with pytest.raises(ValidationError):
        Capability.model_validate({"name": "customer.read", "unexpected": True})


@given(st.sampled_from(MODEL_FIXTURES))
def test_valid_fixture_round_trip_property(
    model_fixture: tuple[type[BaseModel], str, str],
) -> None:
    model, _, fixture_filename = model_fixture
    fixture = load_json(SCHEMA_ROOT / "examples" / "valid" / fixture_filename)

    serialized = model.model_validate(fixture).model_dump(mode="json")

    assert model.model_validate(serialized).model_dump(mode="json") == serialized
