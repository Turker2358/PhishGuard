"""附件安全检测器。"""

from __future__ import annotations

from phishing_detector.detectors.attachment.file_types import (
    get_extension,
    has_double_extension,
    is_archive_or_disk_image,
    is_dangerous_extension,
    is_macro_document,
    mime_mismatch,
)
from phishing_detector.detectors.attachment.hash_lookup import HashLookup
from phishing_detector.models import (
    DetectorModule,
    DetectorResult,
    DetectorStatus,
    RiskSignal,
    Severity,
    StandardizedEmail,
    Verdict,
)

MODULE = DetectorModule.ATTACHMENT


def verdict_from_score(score: int) -> Verdict:
    if score < 35:
        return Verdict.BENIGN
    if score < 70:
        return Verdict.SUSPICIOUS
    return Verdict.MALICIOUS


class AttachmentDetector:
    """检查附件危险类型，并可通过 SHA-256 查询恶意样本信誉。"""

    module = MODULE

    def __init__(self, hash_lookup: HashLookup | None = None) -> None:
        self.hash_lookup = hash_lookup

    async def detect(self, email: StandardizedEmail) -> DetectorResult:
        attachments = email.email.attachments
        if not attachments:
            return DetectorResult(
                module=MODULE,
                status=DetectorStatus.SUCCESS,
                applicable=False,
                score=0,
                verdict=Verdict.BENIGN,
            )

        signals: list[RiskSignal] = []
        score = 0
        lookup_unavailable = False
        lookup_failed = False
        lookup_unknown = False

        for attachment in attachments:
            filename = attachment.filename
            extension = get_extension(filename)
            executable = attachment.detected_mime in {"application/x-dosexec", "application/x-elf"}
            if is_dangerous_extension(filename) or executable:
                points = 65
                score = max(score, points)
                signals.append(
                    RiskSignal(
                        code="DANGEROUS_FILE_TYPE",
                        severity=Severity.HIGH,
                        confidence=0.95,
                        description="附件扩展名或真实文件签名属于可执行或脚本类型",
                        evidence=f"{filename} ({extension}, {attachment.detected_mime})",
                    )
                )

            elif is_macro_document(filename):
                points = 45
                score = max(score, points)
                signals.append(
                    RiskSignal(
                        code="MACRO_DOCUMENT",
                        severity=Severity.HIGH,
                        confidence=0.9,
                        description="附件是可能包含宏代码的 Office 文档",
                        evidence=f"{filename} ({extension})",
                    )
                )

            elif is_archive_or_disk_image(filename):
                points = 25
                score = max(score, points)
                signals.append(
                    RiskSignal(
                        code="ARCHIVE_OR_DISK_IMAGE",
                        severity=Severity.MEDIUM,
                        confidence=0.8,
                        description="附件属于压缩包、磁盘镜像或可携带代码的归档类型",
                        evidence=f"{filename} ({extension})",
                    )
                )

            if has_double_extension(filename):
                score = max(score, 75)
                signals.append(
                    RiskSignal(
                        code="DOUBLE_EXTENSION",
                        severity=Severity.HIGH,
                        confidence=0.98,
                        description="附件使用类似文档.pdf.exe的双扩展名伪装",
                        evidence=filename,
                    )
                )

            if mime_mismatch(attachment.declared_mime, attachment.detected_mime):
                score = max(score, 55)
                signals.append(
                    RiskSignal(
                        code="MIME_MISMATCH",
                        severity=Severity.HIGH,
                        confidence=0.9,
                        description="附件声明类型与实际文件签名不一致",
                        evidence=(
                            f"{filename}: 声明={attachment.declared_mime}, "
                            f"检测={attachment.detected_mime}"
                        ),
                    )
                )

            if self.hash_lookup is None:
                lookup_unavailable = True
                continue

            lookup = await self.hash_lookup.lookup(attachment.sha256)
            if lookup.status == "found":
                if lookup.malicious > 0:
                    score = 100
                    signals.append(
                        RiskSignal(
                            code="KNOWN_MALICIOUS_HASH",
                            severity=Severity.CRITICAL,
                            confidence=1.0,
                            description="附件 SHA-256 命中恶意样本数据库",
                            evidence=f"{filename}: malicious={lookup.malicious}",
                        )
                    )
                elif lookup.suspicious > 0:
                    score = max(score, 60)
                    signals.append(
                        RiskSignal(
                            code="SUSPICIOUS_HASH",
                            severity=Severity.HIGH,
                            confidence=0.9,
                            description="附件 SHA-256 命中可疑样本数据库",
                            evidence=f"{filename}: suspicious={lookup.suspicious}",
                        )
                    )
            elif lookup.status == "unavailable":
                lookup_unavailable = True
            elif lookup.status == "error":
                lookup_failed = True
            elif lookup.status == "not_found":
                lookup_unknown = True

        errors = []
        if lookup_unavailable:
            errors.append("未配置哈希信誉查询 API，仅执行本地附件检测")
        if lookup_failed:
            errors.append("部分附件哈希信誉查询失败")
        if lookup_unknown:
            errors.append("部分附件哈希未收录，无法确定其信誉")

        return DetectorResult(
            module=MODULE,
            status=DetectorStatus.PARTIAL if errors else DetectorStatus.SUCCESS,
            score=min(score, 100),
            verdict=verdict_from_score(min(score, 100)),
            signals=signals,
            errors=errors,
        )
