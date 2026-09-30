from __future__ import annotations

import pytest

from schema_support import SCHEMA_ROOT, load_json, make_validator

PROTOCOL_SCHEMAS = (
    "identity.schema.json",
    "entity.schema.json",
    "capability.schema.json",
    "action.schema.json",
    "resource.schema.json",
    "policy.schema.json",
    "decision.schema.json",
    "evidence.schema.json",
    "error.schema.json",
    "trust-context.schema.json",
)
INVALID_FIXTURES = (
    ("entity.schema.json", "entity-missing-id.json"),
    ("identity.schema.json", "identity-invalid-status.json"),
    ("capability.schema.json", "capability-missing-name.json"),
    ("action.schema.json", "action-missing-entity.json"),
    ("action.schema.json", "action-missing-target.json"),
    ("action.schema.json", "action-invalid-arguments.json"),
    ("resource.schema.json", "resource-invalid-type.json"),
    ("policy.schema.json", "policy-invalid-effect.json"),
    ("decision.schema.json", "decision-invalid-effect.json"),
    ("evidence.schema.json", "evidence-missing-action.json"),
    ("error.schema.json", "error-missing-code.json"),
    ("trust-context.schema.json", "trust-context-invalid.json"),
)


@pytest.mark.parametrize(
    ("schema_filename", "fixture_filename"),
    [(filename, filename.removesuffix(".schema.json") + ".json") for filename in PROTOCOL_SCHEMAS],
)
def test_valid_fixture_passes(schema_filename: str, fixture_filename: str) -> None:
    schema = load_json(SCHEMA_ROOT / schema_filename)
    fixture = load_json(SCHEMA_ROOT / "examples" / "valid" / fixture_filename)

    make_validator(schema).validate(fixture)


@pytest.mark.parametrize(("schema_filename", "fixture_filename"), INVALID_FIXTURES)
def test_invalid_fixture_fails(schema_filename: str, fixture_filename: str) -> None:
    schema = load_json(SCHEMA_ROOT / schema_filename)
    fixture = load_json(SCHEMA_ROOT / "examples" / "invalid" / fixture_filename)

    assert list(make_validator(schema).iter_errors(fixture))
