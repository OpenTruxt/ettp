"""Basic export helpers for ETTP evidence chains."""

from __future__ import annotations

import json
from pathlib import Path

from .checkpoint import ChainCheckpoint
from .evidence import EvidenceEvent
from .store import JSONLStore
from .verifier import Verifier


class Exporter:
    """Export ETTP evidence into portable JSON or JSONL artifacts."""

    @staticmethod
    def export_jsonl(store: JSONLStore, destination: str | Path) -> Path:
        events = Exporter._verified_events(store)
        checkpoint = Exporter._checkpoint_for(events, store)
        destination_path = Path(destination)
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        with destination_path.open("w", encoding="utf-8") as handle:
            for event in events:
                handle.write(event.model_dump_json() + "\n")
            JSONLStore(destination_path).write_checkpoint(checkpoint)
        return destination_path

    @staticmethod
    def export_json(store: JSONLStore, destination: str | Path) -> Path:
        events = Exporter._verified_events(store)
        checkpoint = Exporter._checkpoint_for(events, store)
        destination_path = Path(destination)
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        payload = [event.model_dump(mode="json") for event in events]
        destination_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        JSONLStore(destination_path).write_checkpoint(checkpoint)
        return destination_path

    @staticmethod
    def _verified_events(store: JSONLStore) -> list[EvidenceEvent]:
        try:
            events = store.read()
        except ValueError as error:
            raise ValueError(f"Cannot export invalid evidence chain: {error}") from error
        result = Verifier.verify(store)
        if not result.valid:
            raise ValueError(f"Cannot export invalid evidence chain: {result.reason}")
        return events

    @staticmethod
    def _checkpoint_for(events: list[EvidenceEvent], store: JSONLStore) -> ChainCheckpoint:
        checkpoint = store.read_checkpoint()
        return checkpoint or ChainCheckpoint.create(events)
