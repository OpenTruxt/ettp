"""Small developer-facing API for recording ETTP governance evidence."""

from __future__ import annotations

from pathlib import Path

from ettp.actions import Action, ActionContext
from ettp.decisions import Decision
from ettp.identity import Authority, Delegation, Entity

from .checkpoint import ChainCheckpoint
from .evidence import EvidenceEvent
from .exporter import Exporter
from .store import JSONLStore
from .verifier import VerificationResult, Verifier


class EvidenceLogger:
    """Record protocol events to an offline JSONL store and verify/export them."""

    def __init__(self, store: JSONLStore | str | Path) -> None:
        self.store = store if isinstance(store, JSONLStore) else JSONLStore(store)

    def record_event(self, event: EvidenceEvent) -> EvidenceEvent:
        """Append any typed evidence event, including lifecycle and security events."""
        return self.store.append(event)

    def record_decision(
        self,
        *,
        action: Action,
        decision: Decision | str,
        entity: Entity,
        request_id: str | None = None,
        context: ActionContext | None = None,
        authority: Authority | None = None,
        delegation: Delegation | None = None,
        delegation_chain: list[Delegation] | None = None,
    ) -> EvidenceEvent:
        """Record a decision without persisting the action's raw arguments."""
        return self.store.record_decision(
            action=action,
            decision=decision,
            entity=entity,
            request_id=request_id,
            context=context,
            authority=authority,
            delegation=delegation,
            delegation_chain=delegation_chain,
        )

    def verify(
        self,
        checkpoint: ChainCheckpoint | dict[str, object] | None = None,
    ) -> VerificationResult:
        """Verify the chain against its sidecar or an independently retained checkpoint."""
        return Verifier.verify(self.store, checkpoint=checkpoint)

    def create_checkpoint(self) -> ChainCheckpoint:
        """Create a portable chain checkpoint for independent retention."""
        return self.store.create_checkpoint()

    def export_jsonl(self, destination: str | Path) -> Path:
        """Export a verified chain as newline-delimited JSON."""
        return Exporter.export_jsonl(self.store, destination)

    def export_json(self, destination: str | Path) -> Path:
        """Export a verified chain as a JSON array."""
        return Exporter.export_json(self.store, destination)
