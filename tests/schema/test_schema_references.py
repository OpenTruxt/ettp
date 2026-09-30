from __future__ import annotations

from typing import Any

from schema_support import SCHEMA_ROOT, load_json, schema_registry


def collect_refs(value: Any) -> list[str]:
    """Collect $ref values recursively from a schema document."""
    refs: list[str] = []
    if isinstance(value, dict):
        ref = value.get("$ref")
        if isinstance(ref, str):
            refs.append(ref)
        for child in value.values():
            refs.extend(collect_refs(child))
    elif isinstance(value, list):
        for child in value:
            refs.extend(collect_refs(child))
    return refs


def test_all_internal_and_cross_schema_references_resolve() -> None:
    registry = schema_registry()

    for path in sorted(SCHEMA_ROOT.glob("*.schema.json")):
        schema = load_json(path)
        resolver = registry.resolver(base_uri=schema["$id"])
        for ref in collect_refs(schema):
            resolver.lookup(ref)
