"""解析并校验 LLM 返回的结构化 JSON。

从模型可能夹带的前后文本中安全提取 JSON，只接受经过 Pydantic 严格校验的
结构化字段。任何解析或校验失败都抛出 `InvalidContentResponse`，由上层按
失败处理，绝不降级为“正常”。
"""

from __future__ import annotations

import json

from phishing_detector.detectors.content.schemas import ContentAnalysis


class InvalidContentResponse(ValueError):
    """LLM 返回内容无法安全解析为合格结构。"""


def _extract_json(raw: str) -> dict:
    text = raw.strip()
    # 去掉可能的 Markdown 代码围栏。
    if text.startswith("```"):
        text = text.split("\n", 1)[-1]
        if text.endswith("```"):
            text = text[:-3]
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        # 取首个花括号平衡块，容错模型夹带的前后解释文本。
        try:
            start = text.index("{")
        except ValueError as exc:
            raise InvalidContentResponse("LLM 输出中没有 JSON 对象") from exc
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    try:
                        value = json.loads(text[start : i + 1])
                    except json.JSONDecodeError as exc:
                        raise InvalidContentResponse("LLM 输出 JSON 格式无效") from exc
                    break
        else:
            raise InvalidContentResponse("LLM 输出 JSON 括号不完整")
    if not isinstance(value, dict):
        raise InvalidContentResponse("LLM 输出不是 JSON 对象")
    return value


def parse_analysis(raw: str) -> ContentAnalysis:
    """把 LLM 原始文本解析为汇总的正文分析，失败时抛 `InvalidContentResponse`。"""
    try:
        value = _extract_json(raw)
        return ContentAnalysis.model_validate(value)
    except InvalidContentResponse:
        raise
    except (TypeError, ValueError):
        raise InvalidContentResponse("LLM 返回结构不符合要求") from None
