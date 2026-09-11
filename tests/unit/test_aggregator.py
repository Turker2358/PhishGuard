import pytest

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
    verdict = (
        Verdict.BENIGN if score < 35 else (Verdict.SUSPICIOUS if score < 70 else Verdict.MALICIOUS)
    )
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
    assert analysis.score == 70
    assert analysis.verdict == Verdict.MALICIOUS


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


@pytest.mark.parametrize(("score", "expected"), [(34, 14), (35, 35), (69, 35), (70, 70), (97, 70)])
def test_other_zero_scores_do_not_hide_risk(score, expected):
    analysis = RiskAggregator().aggregate(
        [
            result(DetectorModule.PATTERN, score),
            result(DetectorModule.ATTACHMENT, 0),
            result(DetectorModule.CONTENT, 0),
        ]
    )
    assert analysis.score == expected


def test_absent_attachment_is_excluded_but_analysis_is_complete():
    attachment = result(DetectorModule.ATTACHMENT, 0)
    attachment.applicable = False
    analysis = RiskAggregator().aggregate(
        [
            result(DetectorModule.PATTERN, 100),
            attachment,
            result(DetectorModule.CONTENT, 90),
        ]
    )
    assert analysis.score == 96
    assert analysis.status == AnalysisStatus.COMPLETED


def test_body_only_phishing_is_not_benign():
    analysis = RiskAggregator().aggregate(
        [
            result(DetectorModule.PATTERN, 0),
            result(DetectorModule.ATTACHMENT, 0),
            result(DetectorModule.CONTENT, 97),
        ]
    )
    assert analysis.verdict == Verdict.MALICIOUS


def test_partial_attachment_propagates_to_aggregate():
    attachment = result(DetectorModule.ATTACHMENT, 65)
    attachment.status = DetectorStatus.PARTIAL
    analysis = RiskAggregator().aggregate(
        [
            result(DetectorModule.PATTERN, 0),
            attachment,
            result(DetectorModule.CONTENT, 0),
        ]
    )
    assert analysis.status == AnalysisStatus.PARTIAL
    assert analysis.verdict == Verdict.SUSPICIOUS
    assert "附件检测不完整" in analysis.warnings
