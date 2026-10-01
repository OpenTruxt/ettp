from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ettp.evidence import EvidenceEvent, HashChain, Verifier
from schema_support import SCHEMA_ROOT, load_json, make_validator

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
VECTOR_PATH = REPOSITORY_ROOT / "conformance" / "v1" / "evidence" / "valid" / "policy-decision.json"


def test_policy_decision_vector_hash_and_schema_conformance() -> None:
    vector: dict[str, Any] = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    event_payload = vector["event"]
    expected_hash = vector["expected_event_hash"]
    event = EvidenceEvent.model_validate(event_payload)

    unhashed_payload = dict(event_payload)
    unhashed_payload.pop("event_hash")
    assert HashChain.compute(unhashed_payload) == expected_hash
    assert event.event_hash == expected_hash
    assert Verifier.verify([event]).valid
    make_validator(load_json(SCHEMA_ROOT / "evidence.schema.json")).validate(event_payload)
