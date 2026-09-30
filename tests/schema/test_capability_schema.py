from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from schema_support import make_validator

SCHEMA_ROOT = Path("schemas/ettp/v1")
SCHEMA_PATH = SCHEMA_ROOT / "capability.schema.json"
VALID_FIXTURE_PATH = SCHEMA_ROOT / "examples/valid/capability.json"
INVALID_FIXTURE_PATH = SCHEMA_ROOT / "examples/invalid/capability-missing-name.json"


def load_json(path: Path) -> dict[str, object]:
    """Load a JSON object from a schema or fixture file."""
    with path.open("r", encoding="utf-8") as file:
        value = json.load(file)

    assert isinstance(value, dict)
    return value


def test_capability_schema_matches_schema_contract() -> None:
    schema = load_json(SCHEMA_PATH)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == (
        "https://github.com/OpenTruxt/ettp/schemas/ettp/v1/capability.schema.json"
    )
    assert schema["title"] == "ETTP Capability"
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    Draft202012Validator.check_schema(schema)


def test_valid_capability_fixture_passes() -> None:
    schema = load_json(SCHEMA_PATH)
    instance = load_json(VALID_FIXTURE_PATH)

    make_validator(schema).validate(instance)


def test_capability_names_are_extensible() -> None:
    schema = load_json(SCHEMA_PATH)
    instance = load_json(VALID_FIXTURE_PATH)
    instance["name"] = "implementation_defined.capability"

    make_validator(schema).validate(instance)


def test_capability_missing_name_fails() -> None:
    schema = load_json(SCHEMA_PATH)
    instance = load_json(INVALID_FIXTURE_PATH)

    with pytest.raises(ValidationError):
        make_validator(schema).validate(instance)


def test_capability_rejects_empty_name() -> None:
    schema = load_json(SCHEMA_PATH)
    instance = load_json(VALID_FIXTURE_PATH)
    instance["name"] = ""

    with pytest.raises(ValidationError):
        make_validator(schema).validate(instance)


def test_capability_rejects_unmodeled_policy_data() -> None:
    schema = load_json(SCHEMA_PATH)
    instance = load_json(VALID_FIXTURE_PATH)
    instance["authorization"] = True

    with pytest.raises(ValidationError):
        make_validator(schema).validate(instance)
