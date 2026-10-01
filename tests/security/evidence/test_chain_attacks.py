from __future__ import annotations

from datetime import UTC, datetime

from ettp.evidence import EvidenceEvent, JSONLStore, Verifier


def make_event(event_id: str, predecessor: str | None = None) -> EvidenceEvent:
    return EvidenceEvent(
        id=event_id,
        timestamp=datetime(2026, 1, 1, tzinfo=UTC),
        entity_id="eid:agent:1",
        action_id=f"act:{event_id}",
        decision="ALLOW",
        previous_event_hash=predecessor,
    )


def test_wrong_previous_hash_is_detected(tmp_path) -> None:
    store = JSONLStore(tmp_path / "events.jsonl")
    first = make_event("evt-1")
    second = make_event("evt-2", first.event_hash)
    store._write_raw([first, second])
    tampered_second = EvidenceEvent.model_validate(
        second.model_dump(mode="json") | {"previous_event_hash": "a" * 64}
    )
    store._write_raw([first, tampered_second])

    result = Verifier.verify(store)

    assert not result.valid
    assert result.reason == "EVENT_HASH_MISMATCH"


def test_reordering_and_interior_deletion_are_detected(tmp_path) -> None:
    store = JSONLStore(tmp_path / "events.jsonl")
    first = make_event("evt-1")
    second = make_event("evt-2", first.event_hash)
    third = make_event("evt-3", second.event_hash)

    store._write_raw([first, third, second])
    assert not Verifier.verify(store).valid

    store._write_raw([first, third])
    assert not Verifier.verify(store).valid


def test_duplicate_event_id_is_detected(tmp_path) -> None:
    store = JSONLStore(tmp_path / "events.jsonl")
    first = make_event("evt-duplicate")
    second = make_event("evt-duplicate", first.event_hash)
    store._write_raw([first, second])

    result = Verifier.verify(store)

    assert not result.valid
    assert result.reason == "DUPLICATE_EVENT_ID"


def test_unanchored_valid_prefix_cannot_reveal_deleted_tail(tmp_path) -> None:
    store = JSONLStore(tmp_path / "events.jsonl")
    first = make_event("evt-1")
    second = make_event("evt-2", first.event_hash)
    store._write_raw([first, second])
    store._write_raw([first])

    assert Verifier.verify(store.read()).valid
