from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

SCHEMA_ROOT = Path("schemas/ettp")


def test_schema_files_are_valid_json_schemas() -> None:
    schema_files = sorted(SCHEMA_ROOT.rglob("*.schema.json"))

    for path in schema_files:
        with path.open("r", encoding="utf-8") as file:
            schema = json.load(file)

        Draft202012Validator.check_schema(schema)
