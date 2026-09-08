"""正文 LLM 检测器。

实现 `Detector` 协议，输入已标准化的邮件，构建提示词调用 LLM，并把切面
"不泄露密钥与正文"、错误集中处理与失败兜底集中在此层。

失败处理原则（与开发文档一致）：模型调用、超时或 JSON 解析失败均返回
`status=failed`、`score=None`、`verdict=unknown`，绝不降级为"正常"。
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable

from phishing_detector.detectors.content.client import LLMClient
from phishing_detector.detectors.content.parsing import InvalidContentResponse, parse_analysis
from phishing_detector.detectors.content.prompt import Prompt, build_prompt
from phishing_detector.models import (
    DetectorModule,
    DetectorResult,
    DetectorStatus,
    RiskSignal,
    StandardizedEmail,
    Verdict,
)

logger = logging.getLogger(__name__)

MODULE = DetectorModule.CONTENT
DEFAULT_TIMEOUT = 15.0
DEFAULT_MAX_TOKENS = 600


def _verdict_from_score(score: int) -> Verdict:
    if score < 35:
        return Verdict.BENIGN
    if score < 70:
        return Verdict.SUSPICIOUS
    return Verdict.MALICIOUS


def _signals_from_analysis(signals) -> list[RiskSignal]:
    return [
        RiskSignal(
            code=signal.code,
            severity=signal.severity,
            confidence=signal.confidence,
            description=signal.description,
            evidence=signal.evidence,
        )
        for signal in signals
    ]


class ContentLLMDetector:
    """使用 LLM 分析邮件正文中的钓鱼特征。"""

    module: DetectorModule = MODULE

    def __init__(
        self,
        client: LLMClient,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        prompt_builder: Callable[..., Prompt] = build_prompt,
    ) -> None:
        self.client = client
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.prompt_builder = prompt_builder

    async def detect(self, email: StandardizedEmail) -> DetectorResult:
        parsed = email.email
        prompt = self.prompt_builder(
            subject=parsed.headers.subject,
            llm_text=parsed.body.llm_text,
        )
        try:
            raw = await asyncio.wait_for(
                self.client.complete(
                    system=prompt.system,
                    user=prompt.user,
                    timeout=self.timeout,
                    max_tokens=self.max_tokens,
                ),
                timeout=self.timeout,
            )
            analysis = parse_analysis(raw)
        except Exception as exc:  # noqa: BLE001 - 任何异常一律按失败处理
            logger.warning("content LLM detection failed: %s", _safe_error(exc))
            return DetectorResult(
                module=MODULE,
                status=DetectorStatus.FAILED,
                score=None,
                verdict=Verdict.UNKNOWN,
                errors=[_safe_error(exc)],
            )

        verdict = _verdict_from_score(analysis.score)
        signals = _signals_from_analysis(analysis.signals)
        # 模型自称"非钓鱼"却给出高可疑分，判定自相矛盾，视为结果不可信。
        suspicious_score = analysis.score >= 70
        if analysis.is_phishing != suspicious_score:
            return DetectorResult(
                module=MODULE,
                status=DetectorStatus.PARTIAL,
                score=analysis.score,
                verdict=verdict,
                signals=signals,
                errors=["模型判定结论自相矛盾，结果仅供参考"],
            )
        return DetectorResult(
            module=MODULE,
            status=DetectorStatus.SUCCESS,
            score=analysis.score,
            verdict=verdict,
            signals=signals,
        )


def _safe_error(exc: Exception) -> str:
    """把异常转换成不含密钥与完整正文的简短描述。"""
    if isinstance(exc, InvalidContentResponse):
        return str(exc)
    if isinstance(exc, asyncio.TimeoutError):
        return "LLM 检测超时"
    return f"LLM 检测失败（{type(exc).__name__}）"
