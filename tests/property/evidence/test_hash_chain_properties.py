from __future__ import annotations

from datetime import UTC, datetime

from hypothesis import given
from hypothesis import strategies as st

from ettp.evidence import EvidenceEvent, HashChain, JSONLStore, Verifier


@given(
    event_id=st.text(min_size=1, max_size=32),
    entity_id=st.text(min_size=1, max_size=32),
    action_id=st.text(min_size=1, max_size=32),
    decision=st.sampled_from(["ALLOW", "BLOCK", "REQUIRE_APPROVAL", "REDACT"]),
)
def test_event_hash_is_deterministic(
    event_id: str,
    entity_id: str,
    action_id: str,
    decision: str,
) -> None:
    values = {
        "id": event_id,
        "timestamp": datetime(2025, 1, 1, tzinfo=UTC),
        "entity_id": entity_id,
        "action_id": action_id,
        "decision": decision,
    }
    first = EvidenceEvent(**values)
    second = EvidenceEvent(**dict(reversed(list(values.items()))))

    assert first.event_hash == second.event_hash


@given(
    entity_id=st.text(min_size=1, max_size=32),
    changed_entity_id=st.text(min_size=1, max_size=32),
)
def test_hash_covered_field_mutation_changes_hash(entity_id: str, changed_entity_id: str) -> None:
    original = EvidenceEvent(
        id="evt_property",
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        entity_id=entity_id,
        action_id="act_property",
        decision="ALLOW",
    )
    mutated = EvidenceEvent(
        id="evt_property",
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        entity_id=changed_entity_id,
        action_id="act_property",
        decision="ALLOW",
        event_hash=original.event_hash,
    )

    if entity_id != changed_entity_id:
        assert HashChain.compute(mutated.model_dump(mode="json")) != original.event_hash
        assert not Verifier.verify([mutated]).valid


@given(previous=st.one_of(st.none(), st.from_regex(r"[a-f0-9]{64}", fullmatch=True)))
def test_hashchain_compute_ignores_only_stored_hash(previous: str | None) -> None:
    event = EvidenceEvent(
        id="evt_property",
        timestamp=datetime(2025, 1, 1, tzinfo=UTC),
        entity_id="ent_property",
        action_id="act_property",
        decision="ALLOW",
        previous_event_hash=previous,
    )

    assert HashChain.compute(event.model_dump(mode="json")) == event.event_hash


def test_appended_chain_is_contiguous_and_verifiable(tmp_path) -> None:
    store = JSONLStore(tmp_path / "events.jsonl")
    first = store.append(
        EvidenceEvent(
            id="evt_001",
            timestamp=datetime(2025, 1, 1, tzinfo=UTC),
            entity_id="ent_123",
            action_id="act_001",
            decision="ALLOW",
        )
    )
    second = store.append(
        EvidenceEvent(
            id="evt_002",
            timestamp=datetime(2025, 1, 2, tzinfo=UTC),
            entity_id="ent_123",
            action_id="act_002",
            decision="BLOCK",
        )
    )

    assert second.previous_event_hash == first.event_hash
    assert Verifier.verify(store).valid
