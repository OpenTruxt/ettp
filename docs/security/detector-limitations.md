# Detector Limitations

Built-in detectors recognize only documented formats. They are safeguards, not
a complete data-loss-prevention or compliance system. Encoded, obfuscated,
novel, or provider-specific values may not be detected unless a detector is
explicitly extended or a sensitive field is configured.

False-negative discoveries should become synthetic regression fixtures and
should document the missed format, the detector change, and the new boundary.