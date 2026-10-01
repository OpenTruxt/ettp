from __future__ import annotations

from datetime import UTC, datetime

from ettp.evidence import ChainCheckpoint, EvidenceEvent, JSONLStore, Verifier


def make_event(
    event_id: str,
    previous_hash: str | None = None,
    *,
    decision: str = "ALLOW",
) -> EvidenceEvent:
    return EvidenceEvent(
        event_id=event_id,
        protocol_version="0.1",
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        entity_id="ent_123",
        action_id=f"act_{event_id[-3:]}",
        decision=decision,
        request_id="req_123",
        previous_event_hash=previous_hash,
    )


def test_verifier_accepts_valid_chain(tmp_path):
    store = JSONLStore(tmp_path / "events.jsonl")
    first = make_event("evt_001")
    second = make_event("evt_002", first.event_hash)
    third = make_event("evt_003", second.event_hash)

    for event in (first, second, third):
        store.append(event)

    result = Verifier.verify(store)
    assert result.valid is True
    assert result.reason is None


def test_verifier_rejects_modified_event(tmp_path):
    store = JSONLStore(tmp_path / "events.jsonl")
    first = make_event("evt_001")
    second = make_event("evt_002", first.event_hash)
    store.append(first)
    store.append(second)

    modified = EvidenceEvent(
        event_id="evt_002",
        protocol_version="0.1",
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        entity_id="ent_999",
        action_id="act_002",
        decision="BLOCK",
        request_id="req_123",
        previous_event_hash=first.event_hash,
        event_hash=second.event_hash,
    )
    store._write_raw([first, modified])

    result = Verifier.verify(store)
    assert result.valid is False
    assert result.reason in {"EVENT_HASH_MISMATCH", "PREVIOUS_HASH_MISMATCH"}


def test_verifier_rejects_reordered_events(tmp_path):
    store = JSONLStore(tmp_path / "events.jsonl")
    first = make_event("evt_001")
    second = make_event("evt_002", first.event_hash)
    third = make_event("evt_003", second.event_hash)
    for event in (first, second, third):
        store.append(event)

    store._write_raw([first, third, second])
    result = Verifier.verify(store)
    assert result.valid is False
    assert result.reason == "CHAIN_ORDER_INVALID"


def test_verifier_rejects_deleted_middle_event(tmp_path):
    store = JSONLStore(tmp_path / "events.jsonl")
    first = make_event("evt_001")
    second = make_event("evt_002", first.event_hash)
    third = make_event("evt_003", second.event_hash)
    for event in (first, second, third):
        store.append(event)

    store._write_raw([first, third])
    result = Verifier.verify(store)

    assert result.valid is False
    assert result.reason == "CHAIN_ORDER_INVALID"


def test_verifier_rejects_duplicate_ids(tmp_path):
    store = JSONLStore(tmp_path / "events.jsonl")
    first = make_event("evt_001")
    duplicate = make_event("evt_001", first.event_hash)
    store._write_raw([first, duplicate])

    result = Verifier.verify(store)

    assert result.valid is False
    assert result.reason == "DUPLICATE_EVENT_ID"


def test_verifier_reports_malformed_jsonl(tmp_path):
    store = JSONLStore(tmp_path / "events.jsonl")
    store.path.write_text("{bad json}\n", encoding="utf-8")

    result = Verifier.verify(store)

    assert result.valid is False
    assert result.reason == "INVALID_JSON"


def test_checkpoint_detects_truncated_valid_suffix_and_external_copy(tmp_path):
    store = JSONLStore(tmp_path / "events.jsonl")
    first = store.append(make_event("evt_001"))
    store.append(make_event("evt_002", first.event_hash))
    external_checkpoint = store.create_checkpoint()

    assert Verifier.verify(store).valid
    store._write_raw([first])

    local_result = Verifier.verify(store)
    external_result = Verifier.verify(store.read(), checkpoint=external_checkpoint)
    assert not local_result.valid
    assert local_result.reason == "CHECKPOINT_MISMATCH"

    store.write_checkpoint(ChainCheckpoint.create([first]))
    assert Verifier.verify(store).valid
    external_result = Verifier.verify(store, checkpoint=external_checkpoint)
    assert not external_result.valid
    assert external_result.reason == "CHECKPOINT_MISMATCH"


def test_valid_nonempty_store_without_checkpoint_fails_closed(tmp_path):
    store = JSONLStore(tmp_path / "events.jsonl")
    store._write_raw([make_event("evt_001")])

    result = Verifier.verify(store)

    assert not result.valid
    assert result.reason == "CHECKPOINT_MISSING"


def test_invalid_checkpoint_digest_is_rejected(tmp_path):
    store = JSONLStore(tmp_path / "events.jsonl")
    event = store.append(make_event("evt_001"))
    checkpoint = store.create_checkpoint().model_dump()
    checkpoint["tail_event_id"] = "evt-other"

    result = Verifier.verify([event], checkpoint=checkpoint)

    assert not result.valid
    assert result.reason == "CHECKPOINT_INVALID"
