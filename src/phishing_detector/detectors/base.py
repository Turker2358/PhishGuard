"""Common detector protocol."""

from typing import Protocol

from phishing_detector.models import DetectorModule, DetectorResult, StandardizedEmail


class Detector(Protocol):
    """A detector implementation owned by one analysis module."""

    module: DetectorModule

    async def detect(self, email: StandardizedEmail) -> DetectorResult:
        """Analyze one standardized email without mutating it."""
        ...
