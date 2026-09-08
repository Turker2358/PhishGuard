"""LLM 结构化输出的数据模型与 JSON Schema。

邮件正文属于不可信数据，模型返回值只以严格校验后的结构化字段进入系统，
绝不执行模型返回的任意文本或代码。
"""

from pydantic import Field

from phishing_detector.models.detection import Severity
from phishing_detector.models.email import Model

# 有效性过滤规则：severity 必须是受支持的枚举值。
VALID_SEVERITIES = tuple(Severity)


class LLMSignal(Model):
    """模型识别到的一条风险信号。"""

    code: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    description: str
    evidence: str = ""


class ContentAnalysis(Model):
    """模型返回的整体正文分析结果。"""

    is_phishing: bool
    score: int = Field(ge=0, le=100)
    signals: list[LLMSignal] = Field(default_factory=list)
    reason: str = ""


# 要求模型输出的严格结构，用于约束响应格式并降低注入影响。
SCHEMA_OBJECT = {
    "type": "object",
    "properties": {
        "is_phishing": {"type": "boolean"},
        "score": {"type": "integer", "minimum": 0, "maximum": 100},
        "signals": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "code": {"type": "string"},
                    "severity": {
                        "type": "string",
                        "enum": list(VALID_SEVERITIES),
                    },
                    "confidence": {
                        "type": "number",
                        "minimum": 0,
                        "maximum": 1,
                    },
                    "description": {"type": "string"},
                    "evidence": {"type": "string"},
                },
                "required": ["code", "severity", "confidence", "description"],
            },
            "default": [],
        },
        "reason": {"type": "string"},
    },
    "required": ["is_phishing", "score"],
}


def schema_text() -> str:
    """渲染成可直接放入提示词的 JSON。"""
    from json import dumps

    return dumps(SCHEMA_OBJECT, ensure_ascii=False)
