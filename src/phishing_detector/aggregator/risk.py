"""将三个检测模块的分数合并为最终结果。"""

import uuid
from collections.abc import Iterable

from phishing_detector.models import (
    AnalysisResult,
    AnalysisStatus,
    DetectorModule,
    DetectorResult,
    DetectorStatus,
    Verdict,
)

WEIGHTS = {
    DetectorModule.PATTERN: 0.40,
    DetectorModule.ATTACHMENT: 0.35,
    DetectorModule.CONTENT: 0.25,
}


class RiskAggregator:
    def aggregate(
        self,
        results: Iterable[DetectorResult],
        *,
        request_id: str | None = None,
    ) -> AnalysisResult:
        result_map: dict[DetectorModule, DetectorResult] = {}
        for result in results:
            if result.module in result_map:
                raise ValueError(f"duplicate result: {result.module}")
            result_map[result.module] = result

        warnings = self._warnings(result_map)
        usable = {
            module: result
            for module, result in result_map.items()
            if result.status != DetectorStatus.FAILED
            and result.verdict != Verdict.UNKNOWN
            and result.score is not None
        }

        if not usable:
            return AnalysisResult(
                request_id=request_id or uuid.uuid4().hex,
                status=AnalysisStatus.FAILED,
                score=None,
                verdict=Verdict.UNKNOWN,
                summary="没有检测模块返回可用结果",
                results=result_map,
                warnings=warnings,
            )

        weight_sum = sum(WEIGHTS[module] for module in usable)
        score = round(
            sum(WEIGHTS[module] * result.score for module, result in usable.items()) / weight_sum
        )

        signals = [signal for result in usable.values() for signal in result.signals]
        if any(signal.code == "KNOWN_MALICIOUS_HASH" for signal in signals):
            score = max(score, 70)

        verdict = self._verdict(score)
        complete = set(usable) == set(DetectorModule) and all(
            result.status == DetectorStatus.SUCCESS for result in usable.values()
        )
        reasons = "；".join(signal.description for signal in signals[:3])
        summary = f"综合检测结论为{self._verdict_label(verdict)}"
        if reasons:
            summary += f"：{reasons}"

        return AnalysisResult(
            request_id=request_id or uuid.uuid4().hex,
            status=AnalysisStatus.COMPLETED if complete else AnalysisStatus.PARTIAL,
            score=score,
            verdict=verdict,
            summary=summary,
            results=result_map,
            warnings=warnings,
        )

    @staticmethod
    def _verdict(score: int) -> Verdict:
        if score < 35:
            return Verdict.BENIGN
        if score < 70:
            return Verdict.SUSPICIOUS
        return Verdict.MALICIOUS

    @staticmethod
    def _verdict_label(verdict: Verdict) -> str:
        return {
            Verdict.BENIGN: "正常",
            Verdict.SUSPICIOUS: "可疑",
            Verdict.MALICIOUS: "恶意",
            Verdict.UNKNOWN: "未知",
        }[verdict]

    @staticmethod
    def _warnings(results: dict[DetectorModule, DetectorResult]) -> list[str]:
        labels = {
            DetectorModule.PATTERN: "固定模式",
            DetectorModule.ATTACHMENT: "附件",
            DetectorModule.CONTENT: "正文",
        }
        warnings = []
        for module in DetectorModule:
            result = results.get(module)
            if result is None:
                warnings.append(f"{labels[module]}检测结果缺失")
            elif result.status != DetectorStatus.SUCCESS:
                warnings.append(f"{labels[module]}检测不完整")
        return warnings
