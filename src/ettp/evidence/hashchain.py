"""Hash-chain helpers for ETTP evidence records."""

from __future__ import annotations

import hashlib
from typing import Any

from .evidence import canonical_json


class HashChain:
    """Compute deterministic hashes for ETTP evidence chains."""

    @staticmethod
    def compute(value: str | dict[str, Any]) -> str:
        payload = value if isinstance(value, str) else HashChain.canonicalize(value)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def canonicalize(value: dict[str, Any]) -> str:
        """Return JCS serialization of an event after excluding its stored digest."""
        cleaned = dict(value)
        cleaned.pop("event_hash", None)
        return canonical_json(cleaned)

    @staticmethod
    def link(previous_event_hash: str | None, event_payload: dict[str, Any]) -> str:
        event_payload = dict(event_payload)
        if previous_event_hash is None:
            event_payload.pop("previous_event_hash", None)
        else:
            event_payload["previous_event_hash"] = previous_event_hash
        return HashChain.compute(event_payload)
