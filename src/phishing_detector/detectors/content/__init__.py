"""LLM 正文检测模块。

对外暴露检测器与构造工具，供上层组装；其余内部模块通过私有命名保持封装。
"""

from phishing_detector.detectors.content.client import (
    LLMClient,
    OpenAICompatClient,
    build_client_from_env,
)
from phishing_detector.detectors.content.llm_detector import (
    ContentLLMDetector,
    build_detector_from_env,
)

__all__ = [
    "ContentLLMDetector",
    "LLMClient",
    "OpenAICompatClient",
    "build_client_from_env",
    "build_detector_from_env",
]
