from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

SCHEMA_ROOT = Path("schemas/ettp/v1")


def load_json(path: Path) -> dict[str, Any]:
    """Load a JSON object from a schema or fixture file."""
    with path.open("r", encoding="utf-8") as file:
        value = json.load(file)

    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return value


@lru_cache(maxsize=1)
def schema_registry() -> Registry[Any]:
    """Create a registry containing all local v1 schema documents."""
    registry: Registry[Any] = Registry()

    for path in sorted(SCHEMA_ROOT.glob("*.schema.json")):
        schema = load_json(path)
        schema_id = schema.get("$id")
        if not isinstance(schema_id, str):
            raise ValueError(f"Schema has no string $id: {path}")
        registry = registry.with_resource(schema_id, Resource.from_contents(schema))

    return registry


def make_validator(schema: dict[str, Any]) -> Draft202012Validator:
    """Create a validator with local cross-schema references and format checks."""
    return Draft202012Validator(
        schema,
        registry=schema_registry(),
        format_checker=FormatChecker(),
    )
