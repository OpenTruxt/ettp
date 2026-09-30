from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from schema_support import make_validator

SCHEMA_ROOT = Path("schemas/ettp/v1")
SCHEMA_PATH = SCHEMA_ROOT / "resource.schema.json"
VALID_FIXTURE_PATH = SCHEMA_ROOT / "examples/valid/resource.json"
INVALID_FIXTURE_PATH = SCHEMA_ROOT / "examples/invalid/resource-invalid-type.json"


def load_json(path: Path) -> dict[str, object]:
    """Load a JSON object from a schema or fixture file."""
    with path.open("r", encoding="utf-8") as file:
        value = json.load(file)

    assert isinstance(value, dict)
    return value


def test_resource_schema_matches_schema_contract() -> None:
    schema = load_json(SCHEMA_PATH)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == "https://github.com/OpenTruxt/ettp/schemas/ettp/v1/resource.schema.json"
    assert schema["title"] == "ETTP Resource"
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    Draft202012Validator.check_schema(schema)


def test_valid_resource_fixture_passes() -> None:
    schema = load_json(SCHEMA_PATH)
    instance = load_json(VALID_FIXTURE_PATH)

    make_validator(schema).validate(instance)


def test_resource_type_is_extensible() -> None:
    schema = load_json(SCHEMA_PATH)
    instance = load_json(VALID_FIXTURE_PATH)
    instance["type"] = "implementation_defined_resource_type"

    make_validator(schema).validate(instance)


def test_resource_with_empty_type_fails() -> None:
    schema = load_json(SCHEMA_PATH)
    instance = load_json(INVALID_FIXTURE_PATH)

    with pytest.raises(ValidationError):
        make_validator(schema).validate(instance)


def test_resource_with_undeclared_protocol_field_fails() -> None:
    schema = load_json(SCHEMA_PATH)
    instance = load_json(VALID_FIXTURE_PATH)
    instance["unexpected_protocol_field"] = "must not be accepted"

    with pytest.raises(ValidationError):
        make_validator(schema).validate(instance)
