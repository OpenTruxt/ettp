from __future__ import annotations

from schema_support import SCHEMA_ROOT

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


def test_all_ten_protocol_schema_files_exist() -> None:
    for filename in PROTOCOL_SCHEMAS:
        assert (SCHEMA_ROOT / filename).is_file()


def test_protocol_schema_documents_have_contract_metadata() -> None:
    import json

    for filename in PROTOCOL_SCHEMAS:
        with (SCHEMA_ROOT / filename).open("r", encoding="utf-8") as file:
            schema = json.load(file)

        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["$id"] == ("https://github.com/OpenTruxt/ettp/schemas/ettp/v1/" + filename)
        assert isinstance(schema["title"], str)
        assert isinstance(schema["description"], str)
        assert schema["type"] == "object"
        assert "required" in schema
