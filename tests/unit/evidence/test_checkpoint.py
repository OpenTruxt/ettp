from __future__ import annotations

from datetime import UTC, datetime

import pytest

from ettp.evidence import ChainCheckpoint, EvidenceEvent, JSONLStore, Verifier
from schema_support import SCHEMA_ROOT, load_json, make_validator


def make_event(event_id: str) -> EvidenceEvent:
    return EvidenceEvent(
        id=event_id,
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        entity_id="eid:entity:1",
        action_id=f"act:{event_id}",
        decision="ALLOW",
    )


def test_checkpoint_is_schema_compatible_and_detects_sequence_truncation(tmp_path) -> None:
    store = JSONLStore(tmp_path / "events.jsonl")
    store.append(make_event("evt-1"))
    store.append(make_event("evt-2"))
    checkpoint = store.create_checkpoint()

    make_validator(load_json(SCHEMA_ROOT / "evidence-checkpoint.schema.json")).validate(
        checkpoint.model_dump()
    )
    assert Verifier.verify(store, checkpoint=checkpoint).valid

    events = store.read()
    store._write_raw(events[:-1])
    result = Verifier.verify(store)

    assert not result.valid
    assert result.reason == "CHECKPOINT_MISMATCH"


def test_checkpoint_digest_detects_modification() -> None:
    checkpoint = ChainCheckpoint.create([make_event("evt-1")])
    modified = checkpoint.model_dump() | {"sequence": 0}

    with pytest.raises(ValueError, match="checkpoint digest"):
        ChainCheckpoint.from_dict(modified)


def test_existing_chain_requires_explicit_trust_to_initialize_checkpoint(tmp_path) -> None:
    store = JSONLStore(tmp_path / "events.jsonl")
    store._write_raw([make_event("evt-1")])

    with pytest.raises(ValueError, match="explicit trust decision"):
        store.create_checkpoint()

    checkpoint = store.create_checkpoint(trust_existing=True)
    assert checkpoint.sequence == 1
    assert Verifier.verify(store).valid


def test_trust_existing_rebuilds_stale_local_checkpoint_after_chain_verification(
    tmp_path,
) -> None:
    store = JSONLStore(tmp_path / "events.jsonl")
    first = store.append(make_event("evt-1"))
    store.append(make_event("evt-2"))
    store.write_checkpoint(ChainCheckpoint.create([first]))

    with pytest.raises(ValueError, match="CHECKPOINT_MISMATCH"):
        store.create_checkpoint()

    checkpoint = store.create_checkpoint(trust_existing=True)
    assert checkpoint.sequence == 2
    assert Verifier.verify(store).valid
