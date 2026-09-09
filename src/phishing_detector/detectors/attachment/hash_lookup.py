"""基于文件 SHA-256 的恶意样本信誉查询。

默认实现兼容 VirusTotal API v3：GET /api/v3/files/{sha256}，使用 x-apikey
请求头。若没有配置 API 地址或密钥，则只进行本地附件检测，不访问网络。
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx


@dataclass(frozen=True)
class HashLookupResult:
    """哈希查询的简化结果。"""

    status: str  # found / not_found / unavailable / error
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0


class HashLookup:
    """通过 SHA-256 查询外部恶意样本信誉。"""

    def __init__(
        self,
        *,
        api_url: str,
        api_key: str,
        timeout: float = 5.0,
    ) -> None:
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    async def lookup(self, sha256: str) -> HashLookupResult:
        if not self.api_url or not self.api_key:
            return HashLookupResult(status="unavailable")

        url = f"{self.api_url}/files/{sha256}"
        headers = {"x-apikey": self.api_key}
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url, headers=headers)
        except (httpx.TimeoutException, httpx.RequestError):
            return HashLookupResult(status="error")

        if response.status_code == 404:
            return HashLookupResult(status="not_found")
        if response.status_code != 200:
            return HashLookupResult(status="error")

        try:
            data: dict[str, Any] = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return HashLookupResult(
                status="found",
                malicious=int(stats.get("malicious", 0)),
                suspicious=int(stats.get("suspicious", 0)),
                harmless=int(stats.get("harmless", 0)),
            )
        except (KeyError, TypeError, ValueError):
            return HashLookupResult(status="error")


def build_hash_lookup_from_env(env: dict[str, str] | None = None) -> HashLookup | None:
    """从环境变量构造哈希查询器。

    HASH_LOOKUP_API_URL 为空时默认使用 VirusTotal API v3。
    """
    env = env or os.environ
    api_key = (env.get("HASH_LOOKUP_API_KEY") or "").strip()
    if not api_key:
        return None
    api_url = (env.get("HASH_LOOKUP_API_URL") or "https://www.virustotal.com/api/v3").strip()
    timeout = float(env.get("DETECTOR_TIMEOUT_SECONDS") or 5.0)
    return HashLookup(api_url=api_url, api_key=api_key, timeout=min(timeout, 10.0))
