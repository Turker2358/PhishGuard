"""LLM 客户端抽象与 OpenAI 兼容实现。

客户端负责把提示词发送给模型并返回结构化结果（文本内容与完成原因），不做
判定；判定与结构化校验都在上层完成。密钥只从构造参数读取，绝不写入日志或
错误信息。

结构化输出约束（`response_format`）默认关闭：不同 OpenAI 兼容服务对它的支持
不一致，在兼容性未经验证时不应假定支持。只有在确认服务支持后用
`LLM_STRUCTURED_OUTPUT` 显式开启。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Protocol

import httpx


@dataclass(frozen=True)
class Completion:
    """模型单次完成结果。

    `finish_reason` 用于区分正常完成（`stop`）与 token 截断（`length`）；
    某些网关不提供该字段时为 `None`。
    """

    content: str
    finish_reason: str | None = None


class LLMClient(Protocol):
    """LLM 能力的最小接口，便于测试替换。"""

    async def complete(
        self, *, system: str, user: str, timeout: float, max_tokens: int
    ) -> Completion:
        """发送消息并返回结构化完成结果。"""


class OpenAICompatClient:
    """OpenAI 风格 /chat/completions 兼容客户端。"""

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        base_url: str = "https://api.openai.com/v1",
        connect_timeout: float = 10.0,
        structured_output: bool = False,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.connect_timeout = connect_timeout
        self.structured_output = structured_output

    async def complete(
        self, *, system: str, user: str, timeout: float, max_tokens: int
    ) -> Completion:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
            "max_tokens": max_tokens,
        }
        # 仅在显式开启时附加结构化输出约束；默认不设置，避免兼容性未知的服务报错。
        if self.structured_output:
            payload["response_format"] = {"type": "json_object"}
        headers = {"Authorization": f"Bearer {self.api_key}"}
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=self.connect_timeout)) as client:  # noqa: E501
            response = await client.post(
                f"{self.base_url}/chat/completions",
                headers=headers,
                json=payload,
            )
            response.raise_for_status()
            data = response.json()
        choices = data.get("choices", [])
        if not choices:
            raise RuntimeError("LLM 响应缺少 choices")
        message = choices[0].get("message", {})
        content = message.get("content")
        if not isinstance(content, str) or not content:
            raise RuntimeError("LLM 响应缺少 content")
        finish_reason = choices[0].get("finish_reason")
        return Completion(content=content, finish_reason=finish_reason)


def build_client_from_env(env: dict[str, str] | None = None) -> LLMClient | None:
    """从环境（默认 os.environ）构造检测器使用的客户端。

    未配置密钥或模型时返回 `None`，由上层按"未配置"处理，避免误报"正常"。
    """
    env = env or os.environ
    api_key = (env.get("LLM_API_KEY") or "").strip()
    model = (env.get("LLM_MODEL") or "").strip()
    if not api_key or not model:
        return None
    structured_output = (env.get("LLM_STRUCTURED_OUTPUT") or "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    return OpenAICompatClient(
        api_key=api_key,
        model=model,
        base_url=env.get("LLM_API_URL") or "https://api.openai.com/v1",
        structured_output=structured_output,
    )
