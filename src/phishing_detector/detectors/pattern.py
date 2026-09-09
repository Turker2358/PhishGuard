"""离线固定模式检测，不访问邮件中的链接或查询 DNS。"""

import ipaddress
import re
from difflib import SequenceMatcher
from urllib.parse import urlsplit

import tldextract

from phishing_detector.models import (
    DetectorModule,
    DetectorResult,
    DetectorStatus,
    RiskSignal,
    Severity,
    StandardizedEmail,
    Verdict,
)

# 每种风险只计一次分，避免重复链接把分数无限抬高。
RULES = {
    "DISPLAY_NAME_SPOOFING": (35, "显示名称中的邮箱或机构与实际发件域名不符"),
    "FROM_REPLY_TO_MISMATCH": (20, "回复地址与发件人域名不同"),
    "SPF_FAILED": (15, "邮件头报告 SPF 失败"),
    "DKIM_FAILED": (15, "邮件头报告 DKIM 失败"),
    "DMARC_FAILED": (25, "邮件头报告 DMARC 失败"),
    "LINK_TEXT_TARGET_MISMATCH": (35, "链接显示域名与实际目标不同"),
    "IP_URL": (15, "链接使用 IP 地址"),
    "UNUSUAL_PORT": (10, "链接使用非默认端口"),
    "SHORT_URL": (10, "链接使用常见短链服务"),
    "HTTP_URL": (5, "链接使用明文 HTTP"),
    "URL_USERINFO": (20, "链接含用户名信息，可能混淆目标地址"),
    "DISGUISED_DOMAIN": (35, "可信域名出现在其他域名内部"),
    "SIMILAR_DOMAIN": (25, "域名拼写与受保护域名相似"),
    "INVALID_URL": (10, "链接地址或端口格式异常"),
}
SHORT_DOMAINS = {"bit.ly", "t.co", "tinyurl.com", "is.gd", "ow.ly", "s.id"}
AUTH_CODES = {"SPF_FAILED", "DKIM_FAILED", "DMARC_FAILED"}
AUTH_SCORE_CAP = 25
# 使用内置 PSL 快照，禁止下载；私有后缀避免不同 github.io 用户被视为同一站点。
EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(),
    cache_dir=None,
    include_psl_private_domains=True,
)


def registered_domain(host: str) -> str:
    host = normalize_domain(host)
    extracted = EXTRACT(host)
    return extracted.top_domain_under_public_suffix or host


def same_site(left: str, right: str) -> bool:
    return bool(left and right and registered_domain(left) == registered_domain(right))


def normalize_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError:
        return value


def display_host(text: str) -> str:
    """仅把完整 URL 或裸域名当作地址；“点击这里”不参与域名比较。"""
    text = text.strip()
    if not re.match(r"^(?:https?://|//)", text, re.I):
        if not re.fullmatch(r"[\w-]+(?:\.[\w-]+)+(?:/[^\s]*)?", text):
            return ""
        text = "//" + text
    try:
        return normalize_domain(urlsplit(text).hostname or "")
    except ValueError:
        return ""


class PatternDetector:
    module = DetectorModule.PATTERN

    def __init__(
        self,
        *,
        protected_domains: tuple[str, ...] = (),
        brand_domains: dict[str, tuple[str, ...]] | None = None,
        allowed_domain_pairs: tuple[tuple[str, str], ...] = (),
    ) -> None:
        self.protected_domains = tuple(normalize_domain(d) for d in protected_domains if d)
        self.brand_domains = {
            name.strip().casefold(): tuple(normalize_domain(d) for d in domains)
            for name, domains in (brand_domains or {}).items()
            if name.strip() and domains
        }
        # 定向允许“显示/发件域名 -> 目标/回复域名”，不豁免其他风险。
        self.allowed_domain_pairs = {
            (normalize_domain(left), normalize_domain(right))
            for left, right in allowed_domain_pairs
        }

    def _matches(self, left: str, right: str) -> bool:
        return same_site(left, right) or (left, right) in self.allowed_domain_pairs

    async def detect(self, email: StandardizedEmail) -> DetectorResult:
        signals: dict[str, RiskSignal] = {}

        def add(code: str, evidence: str = "") -> None:
            points, description = RULES[code]
            signals.setdefault(
                code,
                RiskSignal(
                    code=code,
                    severity=Severity.HIGH
                    if points >= 30
                    else (Severity.MEDIUM if points >= 15 else Severity.LOW),
                    confidence=0.7,
                    description=description,
                    evidence=evidence[:200],
                ),
            )

        headers = email.email.headers
        sender = normalize_domain(headers.from_.domain or "") if headers.from_ else ""
        domains = {sender} if sender else set()
        if sender and headers.from_:
            name = headers.from_.name.strip()
            claimed = re.findall(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", name)
            if any(not same_site(normalize_domain(domain), sender) for domain in claimed):
                add("DISPLAY_NAME_SPOOFING")
            official = self.brand_domains.get(name.casefold())
            if official and not any(same_site(sender, domain) for domain in official):
                add("DISPLAY_NAME_SPOOFING")
        for reply in headers.reply_to:
            domain = normalize_domain(reply.domain or "")
            if domain:
                domains.add(domain)
            if sender and domain and not self._matches(sender, domain):
                add("FROM_REPLY_TO_MISMATCH")

        for method in ("spf", "dkim", "dmarc"):
            # 仅读取已有结果，不宣称重新验证 SPF/DKIM/DMARC。
            if getattr(headers.authentication, method).strip().lower() in {"fail", "softfail"}:
                add(f"{method.upper()}_FAILED")

        for link in email.email.links:
            try:
                url = urlsplit(link.target_url)
                if url.scheme.lower() not in {"http", "https"} and not (
                    not url.scheme and link.target_url.startswith("//")
                ):
                    continue
                host = normalize_domain(url.hostname or "")
                if not host or any(char.isspace() for char in host):
                    raise ValueError("invalid host")
                port = url.port
            except ValueError:
                add("INVALID_URL")
                continue
            domains.add(host)
            shown = display_host(link.display_text) if link.source == "html" else ""
            if shown and not self._matches(shown, host):
                add("LINK_TEXT_TARGET_MISMATCH")
            if url.scheme.lower() == "http":
                add("HTTP_URL")
            if port is not None and port != (80 if url.scheme.lower() == "http" else 443):
                add("UNUSUAL_PORT", f"port={port}")
            if url.username is not None:
                add("URL_USERINFO")
            if host in SHORT_DOMAINS:
                add("SHORT_URL")
            try:
                ipaddress.ip_address(host)
            except ValueError:
                pass
            else:
                add("IP_URL")

        for host in sorted(domains):
            for trusted in self.protected_domains:
                if host == trusted or host.endswith("." + trusted):
                    continue
                if ("." + trusted + ".") in ("." + host + "."):
                    add("DISGUISED_DOMAIN")
                elif len(trusted) >= 6 and SequenceMatcher(None, host, trusted).ratio() >= 0.85:
                    add("SIMILAR_DOMAIN")

        auth_score = min(AUTH_SCORE_CAP, sum(RULES[c][0] for c in signals if c in AUTH_CODES))
        score = min(100, auth_score + sum(RULES[c][0] for c in signals if c not in AUTH_CODES))
        verdict = (
            Verdict.BENIGN
            if score < 35
            else (Verdict.SUSPICIOUS if score < 70 else Verdict.MALICIOUS)
        )
        return DetectorResult(
            module=self.module,
            status=DetectorStatus.SUCCESS,
            score=score,
            verdict=verdict,
            signals=list(signals.values()),
        )
