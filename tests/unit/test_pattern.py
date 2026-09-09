import asyncio
from email.message import EmailMessage

import pytest

from phishing_detector.aggregator import RiskAggregator
from phishing_detector.detectors import PatternDetector
from phishing_detector.models import ParsedLink, Verdict
from phishing_detector.parser import EmailStandardizer


def email(html='<a href="https://example.com">https://example.com</a>', reply=None, auth=None):
    message = EmailMessage()
    message["From"] = "sender@example.com"
    if reply:
        message["Reply-To"] = reply
    if auth:
        message["Authentication-Results"] = auth
    message.set_content("普通通知")
    message.add_alternative(html, subtype="html")
    return EmailStandardizer().parse(message.as_bytes())


def detect(message, protected=()):
    return asyncio.run(PatternDetector(protected_domains=protected).detect(message))


def codes(result):
    return {signal.code for signal in result.signals}


def test_normal_mail_and_aggregation():
    result = detect(email(reply="support@example.com", auth="mx; spf=pass; dkim=pass"))
    assert result.score == 0
    assert result.verdict == Verdict.BENIGN
    assert RiskAggregator().aggregate([result]).score == 0


def test_combined_phishing_and_no_sensitive_evidence():
    result = detect(
        email(
            '<a href="http://192.0.2.1:8080/login?token=secret">https://example.com</a>',
            reply="private@attacker.test",
            auth="mx; spf=fail; dkim=fail; dmarc=fail",
        )
    )
    assert result.score == 100
    assert result.verdict == Verdict.MALICIOUS
    assert {
        "FROM_REPLY_TO_MISMATCH",
        "SPF_FAILED",
        "DKIM_FAILED",
        "DMARC_FAILED",
        "LINK_TEXT_TARGET_MISMATCH",
        "IP_URL",
        "UNUSUAL_PORT",
    } <= codes(result)
    assert "secret" not in result.model_dump_json()
    assert "private" not in result.model_dump_json()


@pytest.mark.parametrize(
    ("target", "code"),
    [
        ("http://example.com", "HTTP_URL"),
        ("https://bit.ly/demo", "SHORT_URL"),
        ("https://[2001:db8::1]/", "IP_URL"),
        ("https://example.com:8443/", "UNUSUAL_PORT"),
        ("https://example.com@attacker.test/", "URL_USERINFO"),
        ("https://example.com:bad/", "INVALID_URL"),
        ("https://[broken/", "INVALID_URL"),
    ],
)
def test_url_rules(target, code):
    message = email()
    message.email.links = [ParsedLink(display_text="点击这里", target_url=target, source="html")]
    result = detect(message)
    assert code in codes(result)
    assert "LINK_TEXT_TARGET_MISMATCH" not in codes(result)
    assert result.verdict != Verdict.MALICIOUS


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("https://example.com.evil.test", "DISGUISED_DOMAIN"),
        ("https://examp1e.com", "SIMILAR_DOMAIN"),
        ("https://mail.example.com", None),
        ("https://EXAMPLE.COM.", None),
    ],
)
def test_protected_domain_rules(target, expected):
    result = detect(email(f'<a href="{target}">点击这里</a>'), ("example.com",))
    assert codes(result) == ({expected} if expected else set())


def test_repeated_links_do_not_increase_score():
    message = email('<a href="http://192.0.2.1">example.com</a>')
    once = detect(message)
    message.email.links *= 20
    assert detect(message).model_dump() == once.model_dump()


def test_normalized_idna_and_bare_display_domain():
    result = detect(email('<a href="https://xn--bcher-kva.de">bücher.de</a>'))
    assert result.score == 0
    assert "LINK_TEXT_TARGET_MISMATCH" in codes(
        detect(email('<a href="https://evil.test">example.com</a>'))
    )


def test_empty_and_non_web_links():
    message = email('<a href="mailto:help@example.com">联系我们</a>')
    message.email.headers.from_ = None
    assert detect(message).score == 0


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("support@bank.com", True),
        ("support@mail.example.com", False),
        ("课程通知", False),
        ("示例银行客服", True),
    ],
)
def test_display_name(name, expected):
    message = email()
    message.email.headers.from_.name = name
    detector = PatternDetector(brand_domains={"示例银行客服": ("bank.com",)})
    result = asyncio.run(detector.detect(message))
    assert ("DISPLAY_NAME_SPOOFING" in codes(result)) is expected
    assert name not in result.model_dump_json()


@pytest.mark.parametrize(
    ("shown", "target", "mismatch"),
    [
        ("example.com", "login.example.com", False),
        ("www.example.co.uk", "login.example.co.uk", False),
        ("bank.co.uk", "evil.co.uk", True),
        ("alice.github.io", "bob.github.io", True),
        ("example.com", "example.com.evil.org", True),
        ("alpha.test", "beta.test", True),
    ],
)
def test_registered_domain_comparison(shown, target, mismatch):
    result = detect(email(f'<a href="https://{target}">{shown}</a>'))
    assert ("LINK_TEXT_TARGET_MISMATCH" in codes(result)) is mismatch


def test_reply_subdomain_and_directional_allowlist():
    assert "FROM_REPLY_TO_MISMATCH" not in codes(detect(email(reply="help@mail.example.com")))
    detector = PatternDetector(allowed_domain_pairs=(("example.com", "partner.org"),))
    result = asyncio.run(
        detector.detect(
            email(
                '<a href="http://partner.org:8080">example.com</a>',
                reply="help@partner.org",
            )
        )
    )
    assert codes(result) == {"HTTP_URL", "UNUSUAL_PORT"}
    reverse = asyncio.run(
        detector.detect(
            email(
                '<a href="https://example.com">partner.org</a>',
            )
        )
    )
    assert "LINK_TEXT_TARGET_MISMATCH" in codes(reverse)


@pytest.mark.parametrize(
    ("auth", "score", "count"),
    [
        ("spf=fail", 15, 1),
        ("spf=softfail", 15, 1),
        ("spf=fail; dkim=fail", 25, 2),
        ("spf=fail; dkim=fail; dmarc=fail", 25, 3),
        ("spf=none; dkim=temperror; dmarc=pass", 0, 0),
    ],
)
def test_authentication_cap_preserves_signals(auth, score, count):
    result = detect(email(auth="mx; " + auth))
    assert result.score == score
    assert len(result.signals) == count


def test_domain_extraction_does_not_access_network(monkeypatch):
    import requests
    import tldextract

    from phishing_detector.detectors import pattern

    def forbidden(*args, **kwargs):
        pytest.fail("离线检测不应访问网络")

    monkeypatch.setattr(requests.Session, "request", forbidden)
    monkeypatch.setattr(
        pattern,
        "EXTRACT",
        tldextract.TLDExtract(
            suffix_list_urls=(),
            cache_dir=None,
            include_psl_private_domains=True,
        ),
    )
    assert pattern.same_site("mail.example.co.uk", "example.co.uk")
