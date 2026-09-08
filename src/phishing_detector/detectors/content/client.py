"""LLM 客户端抽象与 OpenAI 兼容实现。

客户端只负责把提示词发送给模型并返回原始文本，不做任何判定；判定与结构
化校验都在上层完成。密钥只从构造参数读取，绝不写入日志或错误信息。
"""

from __future__ import annotations

import os
from typing import Any, Protocol

import httpx


class LLMClient(Protocol):
    """LLM 能力的最小接口，便于测试替换。"""

    async def complete(
        self, *, system: str, user: str, timeout: float, max_tokens: int
    ) -> str:
        """发送消息并返回模型文本。"""


class OpenAICompatClient:
    """OpenAI 风格 /chat/completions 兼容客户端。"""

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        base_url: str = "https://api.openai.com/v1",
        connect_timeout: float = 10.0,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.connect_timeout = connect_timeout

    async def complete(
        self, *, system: str, user: str, timeout: float, max_tokens: int
    ) -> str:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
            "max_tokens": max_tokens,
        }
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
        content = choices[0].get("message", {}).get("content")
        if not isinstance(content, str) or not content:
            raise RuntimeError("LLM 响应缺少 content")
        return content


def build_client_from_env(env: dict[str, str] | None = None) -> LLMClient | None:
    """从环境（默认 os.environ）构造检测器使用的客户端。

    未配置密钥或模型时返回 `None`，由上层按“未配置”处理，避免误报“正常”。
    """
    env = env or os.environ
    api_key = (env.get("LLM_API_KEY") or "").strip()
    model = (env.get("LLM_MODEL") or "").strip()
    if not api_key or not model:
        return None
    return OpenAICompatClient(
        api_key=api_key,
        model=model,
        base_url=env.get("LLM_API_URL") or "https://api.openai.com/v1",
    )
