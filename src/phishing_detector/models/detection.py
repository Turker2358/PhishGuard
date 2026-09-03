"""三个检测模块共用的结果格式。"""

from enum import StrEnum

from pydantic import Field, model_validator

from phishing_detector.models.email import Model


class DetectorModule(StrEnum):
    PATTERN = "pattern"
    ATTACHMENT = "attachment"
    CONTENT = "content"


class DetectorStatus(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


class AnalysisStatus(StrEnum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class Verdict(StrEnum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskSignal(Model):
    code: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    description: str
    evidence: str = ""


class DetectorResult(Model):
    module: DetectorModule
    status: DetectorStatus
    score: int | None = Field(default=None, ge=0, le=100)
    verdict: Verdict
    signals: list[RiskSignal] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def check_failed_result(self) -> "DetectorResult":
        if self.status == DetectorStatus.FAILED:
            if self.score is not None or self.verdict != Verdict.UNKNOWN:
                raise ValueError("failed result must use score=None and verdict=unknown")
        elif self.score is None:
            raise ValueError("successful result must contain a score")
        return self


class AnalysisResult(Model):
    request_id: str
    status: AnalysisStatus
    score: int | None = Field(default=None, ge=0, le=100)
    verdict: Verdict
    summary: str
    results: dict[DetectorModule, DetectorResult]
    warnings: list[str] = Field(default_factory=list)
