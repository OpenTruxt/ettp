"""Deterministic registry for sensitive-data detectors."""

from .detector import SensitiveDetector
from .match import SensitiveMatch


class DetectorRegistryError(ValueError):
    """Raised when detector registry invariants are violated."""


class DetectorRegistry:
    """Manage enabled detectors by stable detector ID."""

    def __init__(self) -> None:
        self._detectors: dict[str, SensitiveDetector] = {}
        self._disabled: set[str] = set()

    def register(self, detector: SensitiveDetector) -> None:
        if detector.detector_id in self._detectors:
            raise DetectorRegistryError(f"Detector is already registered: {detector.detector_id!r}")
        self._detectors[detector.detector_id] = detector

    def get(self, detector_id: str) -> SensitiveDetector:
        try:
            return self._detectors[detector_id]
        except KeyError as error:
            raise DetectorRegistryError(f"Unknown detector: {detector_id!r}") from error

    def remove(self, detector_id: str) -> SensitiveDetector:
        detector = self.get(detector_id)
        del self._detectors[detector_id]
        self._disabled.discard(detector_id)
        return detector

    def enable(self, detector_id: str) -> None:
        self.get(detector_id)
        self._disabled.discard(detector_id)

    def disable(self, detector_id: str) -> None:
        self.get(detector_id)
        self._disabled.add(detector_id)

    def list(self, *, enabled_only: bool = True) -> tuple[SensitiveDetector, ...]:
        detectors = (
            detector
            for detector_id, detector in self._detectors.items()
            if not enabled_only or detector_id not in self._disabled
        )
        return tuple(sorted(detectors, key=lambda detector: detector.detector_id))

    def detect(self, value: object, *, field: str = "") -> tuple[SensitiveMatch, ...]:
        """Run enabled detectors and return a stable, de-duplicated match set."""
        matches = [
            match for detector in self.list() for match in detector.detect(value, field=field)
        ]
        unique: dict[tuple[int, int, str, str, str], SensitiveMatch] = {}
        for match in matches:
            unique.setdefault(match.sort_key(), match)
        return tuple(match for _, match in sorted(unique.items()))
