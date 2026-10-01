# ETTP Evidence

ETTP evidence records governed decisions and material governance changes without
becoming a general-purpose application log. Events use the protocol's existing v1
evidence envelope and can be stored and verified offline.

## EvidenceEvent

`EvidenceEvent` uses the schema fields `id`, `event`, `timestamp`, `entity_id`,
`action_id`, and `decision_id`. It additionally supports a closed `event_type`
vocabulary, policy/decision effects, correlation IDs, actor EIDs, authority and
delegation provenance, lifecycle transitions, enforcement results, affected entities,
invalidated authority IDs, and scoped invalidation metadata. The Python `event_id`
property remains as a compatibility alias for `id`.

`event_hash` is SHA-256 over UTF-8 bytes of RFC 8785 JSON Canonicalization Scheme
(JCS) serialization with the `event_hash` member omitted. An optional
`previous_event_hash` is part of the hashed payload. The first event has no predecessor.
Non-finite numbers, invalid Unicode, non-string object keys, and unsafe large integers
are rejected rather than producing implementation-dependent hashes.

## Decision and governance flow

```text
Action -> PolicyEngine.evaluate() -> Decision -> JSONLStore -> Verifier / Exporter
```

`PolicyEngine` persists every returned outcome by default to
`.ettp/events.jsonl`; configure `ETTP_EVIDENCE_PATH`, pass `evidence_path`, or inject
an `evidence_store` to select another local destination. This includes
`ALLOW`, `BLOCK`, `REQUIRE_APPROVAL`, `REDACT`, default deny, and fail-closed evaluation
errors. Supply `request_id` when available; otherwise evidence factories create an
opaque correlation ID. If persistence fails, the engine returns `EVIDENCE_WRITE_FAILED`
and blocks the action. Action arguments and raw sensitive payloads are not copied to
evidence.

`EvidenceLogger` provides the small developer-facing API for recording decisions or
typed governance events, verifying a store, and exporting it. `LifecycleManager`
applies explicit entity state transitions and delegation revocation cascades, and
persists their evidence before returning updated models. Non-self termination requires
an explicit dependency plan, known entity records, and a known delegation graph.
Credential-dependent, capability-dependent, and organizational scopes additionally
require caller-provided dependency maps. Descendant entities and derived delegations
are returned as updated values. Independent authority roots are excluded from
delegation cascades. Rejected lifecycle and revocation attempts are recorded as
`AUTHORIZATION_FAILURE` events; if that evidence cannot be persisted, the operation
raises an explicit evidence-persistence failure.

Seed the manager once using `register_graph(...)` or constructor graph arguments. The
manager retains and updates that graph for later transitions and cascades.
Credential-dependent, capability-dependent, and organizational links still must be
registered because ETTP cannot infer relationships absent from its graph.

## JSONL, verification, and export

Evidence is stored as one JSON object per line, for example at `.ettp/events.jsonl`.
Appends are serialized across threads and processes, linked to the verified tail, and refused if
the existing file is malformed, invalid, or inconsistent with its adjacent checkpoint
sidecar (`events.jsonl.checkpoint.json`). Exporters validate both the chain and its
checkpoint before writing portable JSONL or JSON artifacts; each export receives a
matching sibling `.checkpoint.json` file. A non-empty legacy file
without a sidecar fails closed; initialize one with `create_checkpoint(trust_existing=True)`
only after an explicit integrity review.

`JSONLStore.create_checkpoint()` returns a portable `ChainCheckpoint`; retain a copy
outside the evidence directory and pass it to `Verifier.verify(..., checkpoint=...)`
to detect replacement of both local files with an earlier valid prefix. The adjacent
sidecar detects ordinary truncation or accidental replacement, but is not an
independent trust anchor if an attacker can modify both files.
Verifying a bare iterable without a checkpoint checks only the supplied sequence's
hashes and links; it cannot establish that the sequence is complete.

The verifier reports failures such as `INVALID_JSON`, `INVALID_EVENT`,
`EVENT_HASH_MISMATCH`, `PREVIOUS_HASH_MISMATCH`, `CHAIN_ORDER_INVALID`, and
`DUPLICATE_EVENT_ID`.

## Security limits

Hash chaining detects changes to retained events, broken links when later events
remain, reordering, duplicate IDs, and deletion of interior records. A retained
checkpoint detects truncation to an earlier prefix or whole-file replacement. To
resist an attacker who can replace the JSONL and local sidecar together, retain the
checkpoint independently or sign it with a key protected outside the evidence
directory. The log is tamper-evident, not immutable. Applications using multiple
file systems that do not support the platform lock primitives must provide external
coordination.

## Conformance

Cross-language evidence vectors are in [conformance/v1](../../conformance/v1/README.md).
They specify JCS hashing and the expected result for a valid ETTP v1 policy decision.
