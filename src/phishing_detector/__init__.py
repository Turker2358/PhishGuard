"""Explainable phishing email detection framework."""

from phishing_detector.aggregator import RiskAggregator
from phishing_detector.parser import EmailStandardizer

__all__ = ["EmailStandardizer", "RiskAggregator"]
__version__ = "0.1.0"
