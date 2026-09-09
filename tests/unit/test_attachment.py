"""附件检测模块单元测试。"""

import asyncio
import hashlib

from phishing_detector.detectors.attachment import AttachmentDetector
from phishing_detector.detectors.attachment.hash_lookup import HashLookupResult
from phishing_detector.models import (
    DetectorModule,
    DetectorStatus,
    EmailBody,
    EmailHeaders,
    ParsedAttachment,
    ParsedEmail,
    StandardizedEmail,
    Verdict,
)


def standardized_attachment(
    filename: str,
    *,
    declared_mime: str = "application/octet-stream",
    content: bytes = b"hello",
) -> StandardizedEmail:
    sha256 = hashlib.sha256(content).hexdigest()
    attachment = ParsedAttachment(
        attachment_id="att-001",
        filename=filename,
        declared_mime=declared_mime,
        detected_mime="application/octet-stream",
        size_bytes=len(content),
        sha256=sha256,
        content_ref="memory://mail/att-001",
    )
    parsed = ParsedEmail(
        email_id="mail",
        headers=EmailHeaders(subject="test"),
        body=EmailBody(),
        attachments=[attachment],
    )
    return StandardizedEmail(
        email=parsed,
        attachment_contents={"memory://mail/att-001": content},
    )


class FakeLookup:
    def __init__(self, result: HashLookupResult) -> None:
        self.result = result

    async def lookup(self, sha256: str) -> HashLookupResult:
        return self.result


def test_no_attachment_is_benign() -> None:
    email = standardized_attachment("normal.txt")
    email.email.attachments = []
    result = asyncio.run(AttachmentDetector().detect(email))
    assert result.module == DetectorModule.ATTACHMENT
    assert result.status == DetectorStatus.SUCCESS
    assert result.score == 0
    assert result.verdict == Verdict.BENIGN


def test_executable_is_high_risk() -> None:
    result = asyncio.run(AttachmentDetector().detect(standardized_attachment("invoice.exe")))
    codes = {signal.code for signal in result.signals}
    assert "DANGEROUS_FILE_TYPE" in codes
    assert result.score == 65
    assert result.verdict == Verdict.SUSPICIOUS


def test_double_extension_is_malicious() -> None:
    result = asyncio.run(AttachmentDetector().detect(standardized_attachment("invoice.pdf.exe")))
    codes = {signal.code for signal in result.signals}
    assert "DOUBLE_EXTENSION" in codes
    assert result.score == 75
    assert result.verdict == Verdict.MALICIOUS


def test_malicious_hash_is_detected() -> None:
    lookup = FakeLookup(HashLookupResult(status="found", malicious=3))
    result = asyncio.run(
        AttachmentDetector(hash_lookup=lookup).detect(standardized_attachment("invoice.pdf"))
    )
    assert result.score == 100
    assert result.verdict == Verdict.MALICIOUS
    assert any(signal.code == "KNOWN_MALICIOUS_HASH" for signal in result.signals)


def test_macro_document_is_suspicious() -> None:
    result = asyncio.run(AttachmentDetector().detect(standardized_attachment("report.docm")))
    assert result.score == 45
    assert result.verdict == Verdict.SUSPICIOUS
    assert any(signal.code == "MACRO_DOCUMENT" for signal in result.signals)


def test_pdf_exe_mime_mismatch() -> None:
    email = standardized_attachment("invoice.pdf", declared_mime="application/pdf", content=b"MZ malware")
    email.email.attachments[0].detected_mime = "application/x-dosexec"
    result = asyncio.run(AttachmentDetector().detect(email))
    assert result.score >= 55
    assert any(signal.code == "MIME_MISMATCH" for signal in result.signals)
