"""JSONL-backed ETTP evidence storage."""

from __future__ import annotations

import json
import os
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4

from ettp.actions import Action, ActionContext
from ettp.decisions import Decision
from ettp.identity import Authority, Delegation, Entity

from .checkpoint import ChainCheckpoint
from .evidence import EvidenceEvent, EvidenceEventType

_STORE_LOCKS: dict[Path, RLock] = {}
_LOCKS_GUARD = RLock()


class JSONLStore:
    """Persist ETTP evidence records as a tamper-evident JSONL sequence."""

    def __init__(self, path: str | Path, checkpoint_path: str | Path | None = None) -> None:
        self.path = Path(path)
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        self.checkpoint_path = (
            Path(checkpoint_path)
            if checkpoint_path is not None
            else self.path.with_suffix(self.path.suffix + ".checkpoint.json")
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with _LOCKS_GUARD:
            self._lock = _STORE_LOCKS.setdefault(self.path.resolve(), RLock())

    def append(self, event: EvidenceEvent) -> EvidenceEvent:
        """Append an event linked to the verified chain tail; reject corrupt stores."""
        with self._lock, _exclusive_file_lock(self.lock_path):
            existing = self.read()
            from .verifier import Verifier

            checkpoint = self.read_checkpoint()
            if existing and checkpoint is None:
                raise ValueError("Cannot append to evidence without a retained chain checkpoint")
            result = Verifier.verify(existing, checkpoint=checkpoint)
            if not result.valid:
                raise ValueError(f"Cannot append to invalid evidence chain: {result.reason}")
            if any(item.id == event.id for item in existing):
                raise ValueError(f"Duplicate evidence event id: {event.id}")
            tail_hash = existing[-1].event_hash if existing else None
            if event.previous_event_hash is not None and event.previous_event_hash != tail_hash:
                raise ValueError("Event predecessor does not match the current evidence chain tail")
            linked_event = event.with_request_id(
                event.request_id or f"req_{uuid4().hex}"
            ).with_previous_event_hash(tail_hash)
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(linked_event.model_dump_json() + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            self.write_checkpoint(ChainCheckpoint.create([*existing, linked_event]))
            return linked_event

    def read_checkpoint(self) -> ChainCheckpoint | None:
        """Load and authenticate the local checkpoint sidecar, if present."""
        if not self.checkpoint_path.exists():
            return None
        try:
            payload = json.loads(self.checkpoint_path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("checkpoint must be a JSON object")
            return ChainCheckpoint.from_dict(payload)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            raise ValueError(f"Invalid evidence checkpoint: {error}") from error

    def write_checkpoint(self, checkpoint: ChainCheckpoint) -> None:
        """Atomically persist a checkpoint; callers may also retain its JSON elsewhere."""
        if not checkpoint.is_valid():
            raise ValueError("cannot persist an invalid evidence checkpoint")
        self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = self.checkpoint_path.with_name(
            f"{self.checkpoint_path.name}.{uuid4().hex}.tmp"
        )
        try:
            with temporary_path.open("w", encoding="utf-8", newline="\n") as handle:
                handle.write(
                    json.dumps(
                        checkpoint.model_dump(),
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
                handle.flush()
                os.fsync(handle.fileno())
            temporary_path.replace(self.checkpoint_path)
        finally:
            temporary_path.unlink(missing_ok=True)

    def create_checkpoint(self, *, trust_existing: bool = False) -> ChainCheckpoint:
        """Create a portable checkpoint from the currently verifiable chain.

        Copy the returned value to an independently controlled location to protect
        against replacement of both the JSONL file and its local sidecar.
        """
        from .verifier import Verifier

        events = self.read()
        existing_checkpoint = self.read_checkpoint()
        if events and existing_checkpoint is None and not trust_existing:
            raise ValueError(
                "Creating a checkpoint for an existing chain requires an explicit trust decision"
            )
        result = (
            Verifier.verify(events)
            if trust_existing
            else Verifier.verify(self, checkpoint=existing_checkpoint)
            if existing_checkpoint is not None or not events
            else Verifier.verify(events)
        )
        if not result.valid:
            raise ValueError(f"Cannot checkpoint invalid evidence chain: {result.reason}")
        checkpoint = ChainCheckpoint.create(events)
        self.write_checkpoint(checkpoint)
        return checkpoint

    def _write_raw(self, events: Iterable[EvidenceEvent]) -> None:
        serialized = "".join(event.model_dump_json() + "\n" for event in events)
        self.path.write_text(serialized, encoding="utf-8")

    def read(self) -> list[EvidenceEvent]:
        if not self.path.exists():
            return []

        events: list[EvidenceEvent] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                line = raw_line.strip()
                if not line:
                    raise ValueError(
                        f"Malformed JSONL at line {line_number}: blank records are not permitted"
                    )
                try:
                    payload = json.loads(line, object_pairs_hook=_unique_json_object)
                except (
                    json.JSONDecodeError,
                    ValueError,
                    RecursionError,
                ) as exc:  # pragma: no cover - covered by tests
                    message = exc.msg if isinstance(exc, json.JSONDecodeError) else str(exc)
                    raise ValueError(f"Malformed JSONL at line {line_number}: {message}") from exc
                try:
                    events.append(EvidenceEvent.model_validate(payload))
                except (TypeError, ValueError, RecursionError) as exc:
                    raise ValueError(
                        f"Invalid evidence event at line {line_number}: {exc}"
                    ) from exc
        return events

    def __iter__(self) -> Iterator[EvidenceEvent]:
        """Iterate persisted events in append order."""
        return iter(self.read())

    def count(self) -> int:
        """Return the number of persisted non-empty event records."""
        return len(self.read())

    def tail_hash(self) -> str | None:
        events = self.read()
        return events[-1].event_hash if events else None

    def record_decision(
        self,
        *,
        action: Action,
        decision: Decision | str,
        entity: Entity,
        request_id: str | None = None,
        event_id: str | None = None,
        previous_event_hash: str | None = None,
        context: ActionContext | None = None,
        authority: Authority | None = None,
        delegation: Delegation | None = None,
        delegation_chain: list[Delegation] | None = None,
    ) -> EvidenceEvent:
        decision_value = decision.effect if isinstance(decision, Decision) else str(decision)
        decision_id = decision.id if isinstance(decision, Decision) else None
        policy_id = decision.policy_id if isinstance(decision, Decision) else None
        effective_context = context or action.context
        chain_ids = (
            [item.delegation_id for item in delegation_chain]
            if delegation_chain is not None
            else effective_context.delegation_chain
            if effective_context and effective_context.delegation_chain
            else [delegation.delegation_id]
            if delegation is not None
            else None
        )
        event = EvidenceEvent.from_decision(
            event_id=event_id or f"evt_{uuid4().hex}",
            entity_id=entity.eid or entity.id,
            action_id=action.id,
            decision=decision_value,
            event_type=self._decision_event_type(decision),
            request_id=request_id
            or (decision.request_id if isinstance(decision, Decision) else None),
            decision_id=decision_id,
            policy_id=policy_id,
            actor_entity_id=(
                effective_context.identity
                if effective_context and effective_context.identity
                else entity.eid or entity.id
            ),
            authority_id=(
                authority.id
                if authority
                else effective_context.authority
                if effective_context
                else None
            ),
            delegation_chain=chain_ids,
            previous_event_hash=previous_event_hash,
            extensions=(
                {"reason_code": decision.reason_code}
                if isinstance(decision, Decision) and decision.reason_code
                else None
            ),
        )
        return self.append(event)

    @staticmethod
    def _decision_event_type(decision: Decision | str) -> EvidenceEventType:
        if not isinstance(decision, Decision):
            return EvidenceEventType.POLICY_DECISION
        if decision.reason_code == "POLICY_EVALUATION_FAILED":
            return EvidenceEventType.POLICY_EVALUATION_FAILURE
        if decision.effect.value == "REDACT":
            return EvidenceEventType.REDACTION_APPLIED
        if decision.effect.value == "REQUIRE_APPROVAL":
            return EvidenceEventType.APPROVAL_REQUESTED
        if decision.reason_code and any(
            token in decision.reason_code
            for token in ("AUTHORITY", "DELEGATION", "ENTITY_EID", "CONTROL_TREE")
        ):
            return EvidenceEventType.AUTHORIZATION_FAILURE
        return EvidenceEventType.POLICY_DECISION

    def record(self, **kwargs: Any) -> EvidenceEvent:
        return self.record_decision(**kwargs)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object member: {key}")
        result[key] = value
    return result


@contextmanager
def _exclusive_file_lock(path: Path) -> Iterator[None]:
    """Serialize chain-tail transactions across processes on Windows and POSIX."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        if os.name == "nt":
            import msvcrt

            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)  # type: ignore[attr-defined]
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)  # type: ignore[attr-defined]
