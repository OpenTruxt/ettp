"""Validate ETTP JSON Schema files."""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

SCHEMA_ROOT = Path("schemas/ettp")


def find_schema_files() -> list[Path]:
    """Return all JSON Schema files in the protocol schema tree."""
    return sorted(SCHEMA_ROOT.rglob("*.schema.json"))


def validate_schema_file(path: Path) -> None:
    """Validate a JSON Schema document against its meta-schema."""
    with path.open("r", encoding="utf-8") as file:
        schema = json.load(file)

    Draft202012Validator.check_schema(schema)


def main() -> int:
    """Validate all ETTP schema files."""
    schema_files = find_schema_files()

    if not schema_files:
        print("No ETTP schema files found.")
        print("Schema validation infrastructure is ready for Sprint 1.")
        return 0

    for path in schema_files:
        validate_schema_file(path)
        print(f"VALID: {path}")

    print(f"Validated {len(schema_files)} schema file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
