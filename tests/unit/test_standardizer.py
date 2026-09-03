from email.message import EmailMessage

import pytest

from phishing_detector.parser import EmailStandardizer


def example_email() -> bytes:
    message = EmailMessage()
    message["Subject"] = "您的账户需要重新验证"
    message["From"] = "某银行客服 <service@example-login.test>"
    message["Reply-To"] = "support@another-domain.test"
    message["To"] = "user@example.com"
    message["Authentication-Results"] = "mx.example; spf=fail; dkim=none; dmarc=fail"
    message.set_content("请访问 https://safe.example/path。")
    message.add_alternative(
        '<html><body><a href="http://192.0.2.1/login">bank.example.com</a></body></html>',
        subtype="html",
    )
    message.add_attachment(
        b"MZ" + b"\x00" * 8,
        maintype="application",
        subtype="pdf",
        filename="账单.pdf.exe",
    )
    return message.as_bytes()


def test_parse_email() -> None:
    standardized = EmailStandardizer().parse(example_email(), email_id="email-001")
    email = standardized.email

    assert email.headers.subject == "您的账户需要重新验证"
    assert email.headers.from_ is not None
    assert email.headers.from_.domain == "example-login.test"
    assert email.headers.reply_to[0].domain == "another-domain.test"
    assert email.headers.authentication.spf == "fail"
    assert {link.target_url for link in email.links} == {
        "https://safe.example/path",
        "http://192.0.2.1/login",
    }
    assert email.attachments[0].declared_mime == "application/pdf"
    assert email.attachments[0].detected_mime == "application/x-dosexec"
    assert standardized.get_attachment_content("memory://email-001/att-001").startswith(b"MZ")


def test_attachment_content_is_not_serialized() -> None:
    standardized = EmailStandardizer().parse(example_email())

    assert "attachment_contents" not in standardized.model_dump()


def test_reject_large_email() -> None:
    with pytest.raises(ValueError, match="邮件超过大小限制"):
        EmailStandardizer(max_email_size=10).parse(example_email())
