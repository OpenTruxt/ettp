from __future__ import annotations

import math
from datetime import UTC, datetime

import pytest

from ettp.evidence import EvidenceEvent, HashChain


def make_event(event_id: str, previous_hash: str | None = None) -> EvidenceEvent:
    return EvidenceEvent(
        event_id=event_id,
        protocol_version="0.1",
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        entity_id="ent_123",
        action_id=f"act_{event_id[-3:]}",
        decision="ALLOW",
        request_id="req_123",
        previous_event_hash=previous_hash,
    )


def test_hash_chain_links_previous_hash() -> None:
    first = make_event("evt_001")
    second = make_event("evt_002", first.event_hash)
    third = make_event("evt_003", second.event_hash)

    assert first.previous_event_hash is None
    assert second.previous_event_hash == first.event_hash
    assert third.previous_event_hash == second.event_hash


def test_hash_chain_is_deterministic() -> None:
    first = make_event("evt_001")
    second = make_event("evt_001")

    assert first.model_dump_json() == second.model_dump_json()
    assert first.event_hash == second.event_hash


def test_hash_chain_detects_mutation() -> None:
    event = make_event("evt_001")
    mutated = EvidenceEvent(
        event_id="evt_001",
        protocol_version="0.1",
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        entity_id="ent_999",
        action_id="act_123",
        decision="ALLOW",
        request_id="req_123",
        previous_event_hash=None,
    )

    assert event.event_hash != mutated.event_hash
    assert HashChain.compute(event.model_dump(mode="json")) == event.event_hash


def test_hash_chain_uses_jcs_number_and_key_canonicalization() -> None:
    value = {
        "numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 1e-27],
        "\ue000": 1,
        "😀": 2,
    }

    assert HashChain.canonicalize(value) == (
        '{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"😀":2,"":1}'
    )


@pytest.mark.parametrize(
    "value",
    [
        {"number": math.nan},
        {"integer": 9_007_199_254_740_992},
        {"surrogate": "\ud800"},
        {1: "non-string key"},
    ],
)
def test_hash_chain_rejects_non_conformant_json_values(value) -> None:
    with pytest.raises((TypeError, ValueError, UnicodeError)):
        HashChain.canonicalize(value)
