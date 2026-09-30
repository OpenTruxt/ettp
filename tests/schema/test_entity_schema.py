from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from schema_support import make_validator

SCHEMA_ROOT = Path("schemas/ettp/v1")
SCHEMA_PATH = SCHEMA_ROOT / "entity.schema.json"
VALID_FIXTURE_PATH = SCHEMA_ROOT / "examples/valid/entity.json"
INVALID_FIXTURE_PATH = SCHEMA_ROOT / "examples/invalid/entity-missing-id.json"


def load_json(path: Path) -> dict[str, object]:
    """Load a JSON object from a schema or fixture file."""
    with path.open("r", encoding="utf-8") as file:
        value = json.load(file)

    assert isinstance(value, dict)
    return value


def test_entity_schema_matches_schema_contract() -> None:
    schema = load_json(SCHEMA_PATH)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == "https://github.com/OpenTruxt/ettp/schemas/ettp/v1/entity.schema.json"
    assert schema["title"] == "ETTP Entity"
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    Draft202012Validator.check_schema(schema)


def test_valid_entity_fixture_passes() -> None:
    schema = load_json(SCHEMA_PATH)
    instance = load_json(VALID_FIXTURE_PATH)

    make_validator(schema).validate(instance)


def test_entity_with_unknown_type_identifier_passes() -> None:
    schema = load_json(SCHEMA_PATH)
    instance = load_json(VALID_FIXTURE_PATH)
    instance["type"] = "IMPLEMENTATION_DEFINED_ENTITY"

    make_validator(schema).validate(instance)


def test_entity_missing_id_fails() -> None:
    schema = load_json(SCHEMA_PATH)
    instance = load_json(INVALID_FIXTURE_PATH)

    with pytest.raises(ValidationError):
        make_validator(schema).validate(instance)


def test_entity_with_undeclared_protocol_field_fails() -> None:
    schema = load_json(SCHEMA_PATH)
    instance = load_json(VALID_FIXTURE_PATH)
    instance["unrecognized_protocol_field"] = "must not be silently accepted"

    with pytest.raises(ValidationError):
        make_validator(schema).validate(instance)
