from __future__ import annotations

from jsonschema import Draft202012Validator

from schema_support import SCHEMA_ROOT, load_json


def test_all_schema_documents_are_valid_draft_2020_12() -> None:
    schema_files = sorted(SCHEMA_ROOT.glob("*.schema.json"))

    for path in schema_files:
        schema = load_json(path)
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert isinstance(schema.get("$id"), str)
        assert isinstance(schema.get("title"), str)
        Draft202012Validator.check_schema(schema)
