"""Interfaces implemented by the three detection teams."""

from phishing_detector.detectors.base import Detector
from phishing_detector.detectors.content import ContentLLMDetector

__all__ = ["ContentLLMDetector", "Detector"]
