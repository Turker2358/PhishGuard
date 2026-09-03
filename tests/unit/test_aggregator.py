from phishing_detector.aggregator import RiskAggregator
from phishing_detector.models import (
    AnalysisStatus,
    DetectorModule,
    DetectorResult,
    DetectorStatus,
    RiskSignal,
    Severity,
    Verdict,
)


def result(module: DetectorModule, score: int) -> DetectorResult:
    verdict = Verdict.BENIGN if score < 35 else Verdict.MALICIOUS
    return DetectorResult(
        module=module,
        status=DetectorStatus.SUCCESS,
        score=score,
        verdict=verdict,
    )


def test_weighted_score() -> None:
    analysis = RiskAggregator().aggregate(
        [
            result(DetectorModule.PATTERN, 80),
            result(DetectorModule.ATTACHMENT, 100),
            result(DetectorModule.CONTENT, 60),
        ],
        request_id="request-001",
    )

    assert analysis.status == AnalysisStatus.COMPLETED
    assert analysis.score == 82
    assert analysis.verdict == Verdict.MALICIOUS


def test_ignore_failed_module_and_recalculate_weight() -> None:
    failed = DetectorResult(
        module=DetectorModule.ATTACHMENT,
        status=DetectorStatus.FAILED,
        score=None,
        verdict=Verdict.UNKNOWN,
    )
    analysis = RiskAggregator().aggregate(
        [result(DetectorModule.PATTERN, 80), failed, result(DetectorModule.CONTENT, 20)]
    )

    assert analysis.status == AnalysisStatus.PARTIAL
    assert analysis.score == 57
    assert analysis.verdict == Verdict.SUSPICIOUS


def test_known_malicious_hash_is_malicious() -> None:
    attachment = result(DetectorModule.ATTACHMENT, 10)
    attachment.signals.append(
        RiskSignal(
            code="KNOWN_MALICIOUS_HASH",
            severity=Severity.CRITICAL,
            confidence=1,
            description="附件哈希命中恶意样本",
        )
    )

    analysis = RiskAggregator().aggregate([attachment])

    assert analysis.score == 70
    assert analysis.verdict == Verdict.MALICIOUS


def test_all_failed_returns_unknown() -> None:
    failed = DetectorResult(
        module=DetectorModule.PATTERN,
        status=DetectorStatus.FAILED,
        score=None,
        verdict=Verdict.UNKNOWN,
    )

    analysis = RiskAggregator().aggregate([failed])

    assert analysis.status == AnalysisStatus.FAILED
    assert analysis.score is None
    assert analysis.verdict == Verdict.UNKNOWN
