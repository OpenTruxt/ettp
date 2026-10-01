"""Validator for ETTP evidence hash chains."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import cast

from .checkpoint import ChainCheckpoint
from .evidence import EvidenceEvent
from .hashchain import HashChain
from .store import JSONLStore


@dataclass(frozen=True)
class VerificationResult:
    """Result of evidence-chain verification."""

    valid: bool
    reason: str | None = None
    event_id: str | None = None


class Verifier:
    """Verify tamper evidence across an ETTP JSONL chain."""

    @staticmethod
    def verify(
        store: JSONLStore | Iterable[object],
        checkpoint: ChainCheckpoint | dict[str, object] | None = None,
    ) -> VerificationResult:
        events: list[object] = []
        if isinstance(store, JSONLStore):
            try:
                events.extend(store.read())
            except ValueError as error:
                reason = (
                    "INVALID_JSON" if str(error).startswith("Malformed JSONL") else "INVALID_EVENT"
                )
                return VerificationResult(valid=False, reason=reason)
        else:
            events.extend(store)
        seen_ids: set[str] = set()

        for index, event in enumerate(events):
            if not isinstance(event, EvidenceEvent):
                return VerificationResult(valid=False, reason="INVALID_EVENT", event_id=None)

            if not event.event_hash:
                return VerificationResult(
                    valid=False,
                    reason="INVALID_EVENT",
                    event_id=event.event_id,
                )

            if event.event_id in seen_ids:
                return VerificationResult(
                    valid=False,
                    reason="DUPLICATE_EVENT_ID",
                    event_id=event.event_id,
                )
            seen_ids.add(event.event_id)

            payload = event.model_dump(mode="json", exclude_none=True)
            payload.pop("event_hash", None)
            expected_hash = HashChain.compute(payload)
            if expected_hash != event.event_hash:
                return VerificationResult(
                    valid=False,
                    reason="EVENT_HASH_MISMATCH",
                    event_id=event.event_id,
                )

            if index == 0:
                if event.previous_event_hash is not None:
                    return VerificationResult(
                        valid=False,
                        reason="CHAIN_ORDER_INVALID",
                        event_id=event.event_id,
                    )
                continue

            previous = cast(EvidenceEvent, events[index - 1])
            if event.previous_event_hash != previous.event_hash:
                return VerificationResult(
                    valid=False,
                    reason=(
                        "CHAIN_ORDER_INVALID"
                        if event.previous_event_hash is not None
                        else "PREVIOUS_HASH_MISMATCH"
                    ),
                    event_id=event.event_id,
                )

        expected_checkpoint: ChainCheckpoint | None
        if checkpoint is not None:
            try:
                expected_checkpoint = (
                    checkpoint
                    if isinstance(checkpoint, ChainCheckpoint)
                    else ChainCheckpoint.from_dict(checkpoint)
                )
            except (KeyError, TypeError, ValueError):
                return VerificationResult(valid=False, reason="CHECKPOINT_INVALID")
        elif isinstance(store, JSONLStore):
            try:
                expected_checkpoint = store.read_checkpoint()
            except ValueError:
                return VerificationResult(valid=False, reason="CHECKPOINT_INVALID")
        else:
            expected_checkpoint = None

        typed_events = [cast(EvidenceEvent, event) for event in events]
        if expected_checkpoint is None:
            if isinstance(store, JSONLStore) and typed_events:
                return VerificationResult(valid=False, reason="CHECKPOINT_MISSING")
        elif not expected_checkpoint.matches(typed_events):
            return VerificationResult(valid=False, reason="CHECKPOINT_MISMATCH")
        return VerificationResult(valid=True, reason=None)
