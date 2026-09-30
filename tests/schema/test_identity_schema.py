from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from schema_support import make_validator

SCHEMA_ROOT = Path("schemas/ettp/v1")
SCHEMA_PATH = SCHEMA_ROOT / "identity.schema.json"
VALID_FIXTURE_PATH = SCHEMA_ROOT / "examples/valid/identity.json"
INVALID_STATUS_FIXTURE_PATH = SCHEMA_ROOT / "examples/invalid/identity-invalid-status.json"


def load_json(path: Path) -> dict[str, object]:
    """Load a JSON object from a repository fixture or schema."""
    with path.open("r", encoding="utf-8") as file:
        value = json.load(file)

    assert isinstance(value, dict)
    return value


def test_identity_schema_matches_schema_contract() -> None:
    schema = load_json(SCHEMA_PATH)

    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["$id"] == (
        "https://github.com/OpenTruxt/ettp/schemas/ettp/v1/identity.schema.json"
    )
    assert schema["title"] == "ETTP Identity"
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is False
    Draft202012Validator.check_schema(schema)


def test_valid_identity_fixture_passes() -> None:
    schema = load_json(SCHEMA_PATH)
    instance = load_json(VALID_FIXTURE_PATH)
    validator = make_validator(schema)

    validator.validate(instance)


def test_identity_with_undefined_status_fails() -> None:
    schema = load_json(SCHEMA_PATH)
    instance = load_json(INVALID_STATUS_FIXTURE_PATH)
    validator = make_validator(schema)

    with pytest.raises(ValidationError):
        validator.validate(instance)
