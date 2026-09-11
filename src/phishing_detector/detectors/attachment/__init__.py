"""附件安全检测模块。"""

from phishing_detector.detectors.attachment.detector import AttachmentDetector
from phishing_detector.detectors.attachment.hash_lookup import (
    HashLookup,
    build_hash_lookup_from_env,
)

__all__ = ["AttachmentDetector", "HashLookup", "build_hash_lookup_from_env"]
