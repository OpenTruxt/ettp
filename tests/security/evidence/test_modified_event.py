from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from ettp.evidence import EvidenceEvent, JSONLStore, Verifier


def test_modified_event_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    store = JSONLStore(path)
    event = EvidenceEvent(
        event_id="evt_001",
        protocol_version="0.1",
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        entity_id="ent_123",
        action_id="act_001",
        decision="ALLOW",
        request_id="req_123",
    )
    store.append(event)

    raw = path.read_text(encoding="utf-8")
    tampered = raw.replace('"decision":"ALLOW"', '"decision":"BLOCK"')
    path.write_text(tampered, encoding="utf-8")

    result = Verifier.verify(store)
    assert result.valid is False
    assert result.reason in {"EVENT_HASH_MISMATCH", "INVALID_EVENT"}
