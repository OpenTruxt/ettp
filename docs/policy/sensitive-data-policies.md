# Sensitive Data Policies

Sensitive-data policies consume detector matches and select a response. A
`BLOCK` policy prevents the protected flow; a `REDACT` policy permits a caller
to continue with the deterministic redacted action copy.

When policies conflict, `BLOCK` takes precedence over `REDACT`, independent of
registration order. Reasons identify categories, detectors, and fields but do
not include matched secrets.