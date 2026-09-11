"""解析并校验 LLM 返回的结构化 JSON。

从模型可能夹带的前后文本中安全提取 JSON，只接受经过 Pydantic 严格校验的
结构化字段。任何解析或校验失败都抛出 `InvalidContentResponse`，由上层按
失败处理，绝不降级为"正常"。

错误分类：
- `no_object`：输出中完全没有 JSON 对象（通常是纯文本/空输出）；
- `invalid_json`：存在花括号但无法解析出合法对象（输出被截断或夹带非 JSON）；
- `schema_recital`：顶层对象是 JSON Schema 复述而非检测结果；
- `invalid_value`：能解析出对象，但字段不满足 `ContentAnalysis` 约束（字段缺失
  或类型/取值错误）。

所有错误消息只包含字段路径与错误类型等脱敏信息，不记录密钥、完整正文或
原始模型响应。
"""

from __future__ import annotations

import json

from pydantic import ValidationError

from phishing_detector.detectors.content.schemas import (
    RESULT_FIELDS,
    SCHEMA_KEYWORDS,
    ContentAnalysis,
)


class InvalidContentResponse(ValueError):
    """LLM 返回内容无法安全解析为合格结构。

    `code` 用于机器可读的分类（`no_object`/`invalid_json`/`schema_recital`/
    `invalid_value`），`message` 是脱敏后的可展示原因。
    """

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def _strip_fences(text: str) -> str:
    """去掉可能的 Markdown 代码围栏并清理两端空白。"""
    text = text.strip()
    if text.startswith("```"):
        text = text.split("\n", 1)[-1]
        if text.endswith("```"):
            text = text[:-3]
    return text.strip()


def _extract_json(raw: str) -> dict:
    """从模型文本中稳健地提取一个 JSON 对象。

    使用 `json.JSONDecoder.raw_decode` 扫描，天然正确处理字符串内的花括号与
    转义，不再依赖手工统计花括号深度。
    """
    text = _strip_fences(raw)
    if not text:
        raise InvalidContentResponse("no_object", "LLM 输出为空或只含空白")

    # 1) 整体解析：输出就是一个合法的 JSON 对象时最快。
    try:
        value = json.loads(text)
        if isinstance(value, dict):
            return value
    except json.JSONDecodeError:
        pass

    # 2) 容错扫描：在文本中查找首个合法 JSON 对象，忽略夹带的前后说明文字。
    decoder = json.JSONDecoder()
    for i, char in enumerate(text):
        if char != "{":
            continue
        try:
            value, _ = decoder.raw_decode(text, i)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value

    # 3) 判断"找不到对象"的真实原因，区分截断与纯文本。
    if not any(c in text for c in "{}"):
        raise InvalidContentResponse("no_object", "LLM 输出中没有 JSON 对象")
    raise InvalidContentResponse(
        "invalid_json", "LLM 输出 JSON 无法解析（可能被截断或夹带非 JSON 文本）"
    )


def _looks_like_schema(value: dict) -> bool:
    """判断顶层对象是否像 JSON Schema 而非检测结果。

    合法的检测结果必然包含 `is_phishing`；若顶层同时包含 Schema 关键字（如
    type/properties/required）却缺少结果字段，基本可断定模型复述了 Schema。
    """
    has_schema_keyword = any(key in SCHEMA_KEYWORDS for key in value)
    has_result_field = any(key in RESULT_FIELDS for key in value)
    return has_schema_keyword and not has_result_field


def _validation_error_message(exc: ValidationError) -> str:
    """把首条校验错误转成脱敏消息，保留字段路径与错误类型。"""
    errors = exc.errors()
    if errors:
        first = errors[0]
        loc = ".".join(str(part) for part in first.get("loc", ())) or "(根)"
        error_type = first.get("type", "invalid")
        return f"LLM 返回字段校验失败：字段 {loc} 类型 {error_type}"
    return "LLM 返回结构不符合要求"


def parse_analysis(raw: str) -> ContentAnalysis:
    """把 LLM 原始文本解析为汇总的正文分析，失败时抛 `InvalidContentResponse`。"""
    try:
        value = _extract_json(raw)
    except InvalidContentResponse:
        raise
    if _looks_like_schema(value):
        raise InvalidContentResponse(
            "schema_recital", "LLM 复述了 JSON Schema 而非返回检测结果"
        )
    try:
        return ContentAnalysis.model_validate(value)
    except ValidationError as exc:
        raise InvalidContentResponse("invalid_value", _validation_error_message(exc)) from None
    except (TypeError, ValueError):
        raise InvalidContentResponse("invalid_value", "LLM 返回结构不符合要求") from None
