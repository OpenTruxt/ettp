# Sensitive Data Detection

ETTP provides deterministic detectors for defined classes of sensitive data and
configurable sensitive fields. Detection is separate from policy response:
detectors produce normalized `SensitiveMatch` values, while policies choose
`BLOCK` or `REDACT`.

Supported built-in categories include:

- Defined email, phone, and IP address patterns
- Structured credential fields such as `password` and `private_key`
- Supported API-key formats
- Payment-card-shaped numbers validated with the Luhn checksum
- User-configured nested sensitive fields

ETTP does not provide complete PII detection. It does not guarantee detection
of every credential, API key, payment-card representation, or personal datum.
Pattern detection can produce false positives and false negatives. Applications
must configure detectors for their own data and threat model.

Detectors never retain raw matched values in `SensitiveMatch` objects or policy
reasons. Test data in this repository is synthetic and must not contain real
credentials, payment cards, or personal information.