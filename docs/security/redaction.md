# Redaction

`REDACT` replaces complete matched ranges with the deterministic marker
`[REDACTED]`. Overlapping matches are merged before replacement, which prevents
partial secrets from remaining visible. Structured mappings and sequences are
copied recursively without mutating the input.

Redaction is deterministic for the same input and match set. The
`PolicyEngine.redact_action()` helper returns a transformed action copy after a
configured sensitive-data policy selects `REDACT`.