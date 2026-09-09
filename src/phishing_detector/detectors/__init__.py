"""Interfaces implemented by the three detection teams."""

from phishing_detector.detectors.base import Detector
from phishing_detector.detectors.content import ContentLLMDetector
from phishing_detector.detectors.pattern import PatternDetector
from phishing_detector.detectors.attachment import AttachmentDetector

__all__ = ["ContentLLMDetector", "Detector", "PatternDetector","AttachmentDetector"]
