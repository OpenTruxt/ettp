# ETTP v1 Conformance Vectors

These vectors are protocol data, not Python fixtures. Implementations in any language
should consume the same JSON input and produce the same protocol result.

## Evidence event hashing

`event_hash` is SHA-256 over the UTF-8 bytes of the event object serialized with the
RFC 8785 JSON Canonicalization Scheme (JCS), after omitting only `event_hash`.
Optional fields with no value are omitted by ETTP event serialization. A serialized
event must not include JSON `null` for an optional top-level field; null values inside
extensions are ordinary JCS values. The event's `previous_event_hash` is part of the
hash input when present. Genesis events omit it.

The implementation MUST use JCS-compatible behavior for:

- lexicographic UTF-16 code-unit ordering of object member names;
- JSON string escaping and UTF-8 encoding;
- finite IEEE-754 binary64 number formatting;
- rejection of non-finite numbers, unpaired surrogates, non-string object keys,
  and integers outside the interoperable safe-integer range.

`evidence/valid/policy-decision.json` is a fixed valid event and expected hash.
Conformance implementations must validate the schema, reproduce the exact hash, and
accept the event as a valid one-event chain.

## Integrity limit

A valid prefix remains valid if later records are deleted. Detecting a truncated tail
or a replaced complete file requires a separately retained checkpoint or signature,
which this local JSONL foundation does not claim to provide.
