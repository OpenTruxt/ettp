from __future__ import annotations

import json
from pathlib import Path

import pytest

from ettp.evidence import EvidenceEvent, Exporter, JSONLStore, Verifier


def test_exporter_preserves_order_and_validity(tmp_path: Path) -> None:
    store = JSONLStore(tmp_path / "events.jsonl")
    first = EvidenceEvent(
        event_id="evt_001",
        protocol_version="0.1",
        timestamp="2025-01-01T00:00:00Z",
        entity_id="ent_123",
        action_id="act_123",
        decision="ALLOW",
        request_id="req_123",
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

    first = store.append(first)
    store.append(second)

    export_path = tmp_path / "export.jsonl"
    Exporter.export_jsonl(store, export_path)

    exported_events = JSONLStore(export_path).read()
    assert [event.event_id for event in exported_events] == ["evt_001", "evt_002"]
    assert Verifier.verify(JSONLStore(export_path)).valid

    json_path = tmp_path / "export.json"
    Exporter.export_json(store, json_path)
    json_events = json.loads(json_path.read_text(encoding="utf-8"))
    assert [event["id"] for event in json_events] == ["evt_001", "evt_002"]
    json_checkpoint = JSONLStore(json_path).read_checkpoint()
    parsed_json_events = [EvidenceEvent.model_validate(event) for event in json_events]
    assert json_checkpoint is not None
    assert Verifier.verify(parsed_json_events, checkpoint=json_checkpoint).valid


def test_exporter_refuses_invalid_chain(tmp_path: Path) -> None:
    store = JSONLStore(tmp_path / "events.jsonl")
    event = EvidenceEvent(
        id="evt_001",
        timestamp="2025-01-01T00:00:00Z",
        entity_id="ent_123",
        action_id="act_123",
        decision="ALLOW",
    )
    store._write_raw([event])
    store.path.write_text('{"id":"tampered"}\n', encoding="utf-8")

    with pytest.raises(ValueError, match="Cannot export invalid evidence chain"):
        Exporter.export_jsonl(store, tmp_path / "invalid-export.jsonl")


def test_exporter_refuses_checkpoint_mismatch_after_valid_prefix_truncation(
    tmp_path: Path,
) -> None:
    store = JSONLStore(tmp_path / "events.jsonl")
    first = EvidenceEvent(
        id="evt-1",
        timestamp="2025-01-01T00:00:00Z",
        entity_id="ent-1",
        action_id="act-1",
        decision="ALLOW",
    )
    store.append(first)
    store.append(
        EvidenceEvent(
            id="evt-2",
            timestamp="2025-01-01T00:00:01Z",
            entity_id="ent-1",
            action_id="act-2",
            decision="ALLOW",
        )
    )
    store._write_raw([first])

    with pytest.raises(ValueError, match="CHECKPOINT_MISMATCH"):
        Exporter.export_jsonl(store, tmp_path / "truncated-export.jsonl")
