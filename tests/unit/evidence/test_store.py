from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from ettp.evidence import EvidenceEvent, JSONLStore, Verifier


@pytest.fixture
def store_path(tmp_path: Path) -> Path:
    return tmp_path / "events.jsonl"


def test_append_and_read_events(store_path: Path) -> None:
    store = JSONLStore(store_path)
    first = EvidenceEvent(
        event_id="evt_001",
        protocol_version="0.1",
        timestamp="2025-01-01T00:00:00Z",
        entity_id="ent_123",
        action_id="act_123",
        decision="ALLOW",
        request_id="req_123",
        previous_event_hash=None,
    )
    second = EvidenceEvent(
        event_id="evt_002",
        protocol_version="0.1",
        timestamp="2025-01-01T00:00:01Z",
        entity_id="ent_123",
        action_id="act_124",
        decision="BLOCK",
        request_id="req_124",
        previous_event_hash=first.event_hash,
    )

    store.append(first)
    store.append(second)
    events = store.read()

    assert len(events) == 2
    assert events[0].event_id == "evt_001"
    assert events[1].event_id == "evt_002"


def test_store_preserves_order_and_handles_empty_file(store_path: Path) -> None:
    store = JSONLStore(store_path)
    assert store.read() == []

    first = EvidenceEvent(
        event_id="evt_001",
        protocol_version="0.1",
        timestamp="2025-01-01T00:00:00Z",
        entity_id="ent_123",
        action_id="act_123",
        decision="ALLOW",
        request_id="req_123",
    )
    store.append(first)
    assert [event.event_id for event in store.read()] == ["evt_001"]


def test_store_rejects_malformed_jsonl(store_path: Path) -> None:
    store_path.write_text("{bad json}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Malformed JSONL"):  # type: ignore[unreachable]
        JSONLStore(store_path).read()


def test_store_rejects_duplicate_json_member_names(store_path: Path) -> None:
    store_path.write_text(
        '{"id":"evt-1","id":"evt-2"}\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate JSON object member"):
        JSONLStore(store_path).read()


def test_store_rejects_blank_jsonl_records(store_path: Path) -> None:
    store_path.write_text("\n", encoding="utf-8")

    with pytest.raises(ValueError, match="blank records"):
        JSONLStore(store_path).read()


def test_append_links_event_to_existing_tail(store_path: Path) -> None:
    store = JSONLStore(store_path)
    first = store.append(
        EvidenceEvent(
            id="evt_001",
            timestamp="2025-01-01T00:00:00Z",
            entity_id="ent_123",
            action_id="act_123",
            decision="ALLOW",
        )
    )
    second = store.append(
        EvidenceEvent(
            id="evt_002",
            timestamp="2025-01-01T00:00:01Z",
            entity_id="ent_123",
            action_id="act_124",
            decision="BLOCK",
        )
    )

    assert second.previous_event_hash == first.event_hash
    assert first.request_id is not None
    assert first.request_id.startswith("req_")
    assert len(store.read()) == 2


def test_append_refuses_corrupt_existing_chain(store_path: Path) -> None:
    store = JSONLStore(store_path)
    first = EvidenceEvent(
        id="evt_001",
        timestamp="2025-01-01T00:00:00Z",
        entity_id="ent_123",
        action_id="act_123",
        decision="ALLOW",
    )
    store._write_raw([first])
    store.path.write_text('{"bad": true}\n', encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid evidence event"):
        store.append(first)


def test_concurrent_store_instances_keep_a_single_valid_chain(store_path: Path) -> None:
    stores = [JSONLStore(store_path), JSONLStore(store_path)]

    def append(index: int) -> None:
        stores[index % 2].append(
            EvidenceEvent(
                id=f"evt-concurrent-{index}",
                timestamp="2025-01-01T00:00:00Z",
                entity_id="ent-1",
                action_id=f"act-{index}",
                decision="ALLOW",
            )
        )

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(append, range(32)))

    assert len(stores[0].read()) == 32
    assert Verifier.verify(stores[0]).valid
