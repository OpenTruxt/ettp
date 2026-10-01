"""Deterministic sensitive-data detection primitives."""

from .detector import SensitiveDetector
from .detectors import SensitiveFieldDetector
from .match import SensitiveMatch
from .policy import SensitiveDataPolicy, SensitivePolicyResult, select_sensitive_policy
from .redaction import REDACTED_VALUE, redact, redact_action, redact_text
from .registry import DetectorRegistry
from .types import SensitiveCategory

__all__ = [
    "REDACTED_VALUE",
    "DetectorRegistry",
    "SensitiveCategory",
    "SensitiveDataPolicy",
    "SensitiveDetector",
    "SensitiveFieldDetector",
    "SensitiveMatch",
    "SensitivePolicyResult",
    "redact",
    "redact_action",
    "redact_text",
    "select_sensitive_policy",
]
