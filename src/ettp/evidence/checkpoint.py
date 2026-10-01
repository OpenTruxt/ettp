"""Detached chain checkpoints for detecting valid-prefix truncation."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

from .evidence import EvidenceEvent, canonical_json


@dataclass(frozen=True)
class ChainCheckpoint:
    """A portable commitment to a specific sequence length and chain tail.

    Retain exported checkpoint JSON independently from the JSONL file when protection
    against an attacker replacing both local files is required.
    """

    sequence: int
    tail_event_id: str | None
    tail_event_hash: str | None
    checkpoint_hash: str

    @classmethod
    def create(cls, events: list[EvidenceEvent]) -> ChainCheckpoint:
        payload = cls._payload(
            sequence=len(events),
            tail_event_id=events[-1].id if events else None,
            tail_event_hash=events[-1].event_hash if events else None,
        )
        digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        return cls(**payload, checkpoint_hash=digest)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> ChainCheckpoint:
        if set(value) != {
            "sequence",
            "tail_event_id",
            "tail_event_hash",
            "checkpoint_hash",
        }:
            raise ValueError("checkpoint fields do not match the protocol contract")
        checkpoint = cls(
            sequence=value["sequence"],
            tail_event_id=value.get("tail_event_id"),
            tail_event_hash=value.get("tail_event_hash"),
            checkpoint_hash=value["checkpoint_hash"],
        )
        if not checkpoint.is_valid():
            raise ValueError("checkpoint digest is invalid")
        return checkpoint

    @staticmethod
    def _payload(
        *,
        sequence: int,
        tail_event_id: str | None,
        tail_event_hash: str | None,
    ) -> dict[str, Any]:
        return {
            "sequence": sequence,
            "tail_event_id": tail_event_id,
            "tail_event_hash": tail_event_hash,
        }

    def is_valid(self) -> bool:
        if (
            isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or self.sequence < 0
        ):
            return False
        if self.sequence == 0 and (
            self.tail_event_id is not None or self.tail_event_hash is not None
        ):
            return False
        if self.sequence > 0 and (self.tail_event_id is None or self.tail_event_hash is None):
            return False
        if self.tail_event_hash is not None and not re.fullmatch(
            r"[a-fA-F0-9]{64}", self.tail_event_hash
        ):
            return False
        if not re.fullmatch(r"[a-fA-F0-9]{64}", self.checkpoint_hash):
            return False
        payload = self._payload(
            sequence=self.sequence,
            tail_event_id=self.tail_event_id,
            tail_event_hash=self.tail_event_hash,
        )
        expected = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
        return expected == self.checkpoint_hash

    def matches(self, events: list[EvidenceEvent]) -> bool:
        if not self.is_valid() or self.sequence != len(events):
            return False
        if not events:
            return self.tail_event_id is None and self.tail_event_hash is None
        tail = events[-1]
        return self.tail_event_id == tail.id and self.tail_event_hash == tail.event_hash

    def model_dump(self) -> dict[str, Any]:
        return {
            **self._payload(
                sequence=self.sequence,
                tail_event_id=self.tail_event_id,
                tail_event_hash=self.tail_event_hash,
            ),
            "checkpoint_hash": self.checkpoint_hash,
        }
