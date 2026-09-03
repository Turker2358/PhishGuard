"""把 .eml 邮件解析成三个检测模块共用的数据结构。"""

import hashlib
import re
import uuid
from datetime import UTC, datetime
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from urllib.parse import urlsplit

from phishing_detector.models import (
    AuthenticationSummary,
    EmailAddress,
    EmailBody,
    EmailHeaders,
    ParsedAttachment,
    ParsedEmail,
    ParsedLink,
    StandardizedEmail,
)

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
AUTH_PATTERN = re.compile(r"\b(spf|dkim|dmarc)=([a-zA-Z_-]+)", re.IGNORECASE)


class HTMLExtractor(HTMLParser):
    """只提取 HTML 的可见文字和链接。"""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.links: list[tuple[str, str]] = []
        self.current_href: str | None = None
        self.current_text: list[str] = []
        self.skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in {"script", "style"}:
            self.skip_depth += 1
        elif not self.skip_depth and tag == "a":
            self.current_href = dict(attrs).get("href")
            self.current_text = []

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in {"script", "style"}:
            self.skip_depth = max(0, self.skip_depth - 1)
        elif not self.skip_depth and tag == "a" and self.current_href:
            text = normalize_text(" ".join(self.current_text)) or self.current_href
            self.links.append((text, self.current_href))
            self.current_href = None
            self.current_text = []

    def handle_data(self, data: str) -> None:
        if self.skip_depth:
            return
        self.text.append(data)
        if self.current_href:
            self.current_text.append(data)


class EmailStandardizer:
    def __init__(
        self,
        *,
        max_email_size: int = 20 * 1024 * 1024,
        max_attachment_size: int = 10 * 1024 * 1024,
        max_attachment_count: int = 20,
        max_llm_chars: int = 12_000,
    ) -> None:
        self.max_email_size = max_email_size
        self.max_attachment_size = max_attachment_size
        self.max_attachment_count = max_attachment_count
        self.max_llm_chars = max_llm_chars

    def parse(self, raw_email: bytes, *, email_id: str | None = None) -> StandardizedEmail:
        if not raw_email:
            raise ValueError("邮件内容为空")
        if len(raw_email) > self.max_email_size:
            raise ValueError("邮件超过大小限制")

        message = BytesParser(policy=policy.default).parsebytes(raw_email)
        warnings: list[str] = []
        current_email_id = email_id or uuid.uuid4().hex
        headers = self._parse_headers(message, warnings)
        plain_parts: list[str] = []
        html_parts: list[str] = []
        links: list[ParsedLink] = []
        attachments: list[ParsedAttachment] = []
        attachment_contents: dict[str, bytes] = {}

        for part in message.walk():
            if part.is_multipart():
                continue

            if part.get_filename() or part.get_content_disposition() == "attachment":
                if len(attachments) >= self.max_attachment_count:
                    raise ValueError("附件数量超过限制")
                attachment, content = self._parse_attachment(
                    part, current_email_id, len(attachments) + 1
                )
                attachments.append(attachment)
                attachment_contents[attachment.content_ref] = content
                continue

            content_type = part.get_content_type().lower()
            if content_type == "text/plain":
                text = normalize_text(decode_text(part, warnings))
                plain_parts.append(text)
                links.extend(extract_plain_links(text))
            elif content_type == "text/html":
                extractor = HTMLExtractor()
                extractor.feed(decode_text(part, warnings))
                html_parts.append(normalize_text(" ".join(extractor.text)))
                links.extend(build_link(text, target, "html") for text, target in extractor.links)

        plain_text = "\n".join(filter(None, plain_parts))
        html_text = "\n".join(filter(None, html_parts))
        links = deduplicate_links(links)
        llm_text = self._llm_text(headers.subject, plain_text or html_text, links)
        truncated = len(llm_text) > self.max_llm_chars
        if truncated:
            llm_text = llm_text[: self.max_llm_chars]
            warnings.append("LLM 正文超过长度限制，已截断")

        parsed = ParsedEmail(
            email_id=current_email_id,
            headers=headers,
            body=EmailBody(
                plain_text=plain_text,
                html_text=html_text,
                llm_text=llm_text,
                truncated=truncated,
            ),
            links=links,
            attachments=attachments,
            parse_warnings=warnings,
        )
        return StandardizedEmail(email=parsed, attachment_contents=attachment_contents)

    def _parse_headers(self, message: Message, warnings: list[str]) -> EmailHeaders:
        return EmailHeaders(
            subject=normalize_text(header(message, "subject") or ""),
            from_=first_address(message, "from"),
            sender=first_address(message, "sender"),
            reply_to=addresses(message, "reply-to"),
            date=parse_date(header(message, "date"), warnings),
            message_id=header(message, "message-id"),
            authentication=parse_authentication(message),
        )

    def _parse_attachment(
        self, part: Message, email_id: str, index: int
    ) -> tuple[ParsedAttachment, bytes]:
        content = part.get_payload(decode=True)
        if not isinstance(content, bytes):
            content = b""
        if len(content) > self.max_attachment_size:
            raise ValueError("附件超过大小限制")

        attachment_id = f"att-{index:03d}"
        content_ref = f"memory://{email_id}/{attachment_id}"
        filename = normalize_text(str(part.get_filename() or f"attachment-{index}.bin"))
        return (
            ParsedAttachment(
                attachment_id=attachment_id,
                filename=filename,
                declared_mime=part.get_content_type().lower(),
                detected_mime=detect_mime(content),
                size_bytes=len(content),
                sha256=hashlib.sha256(content).hexdigest(),
                content_ref=content_ref,
            ),
            content,
        )

    @staticmethod
    def _llm_text(subject: str, body: str, links: list[ParsedLink]) -> str:
        text = f"主题：{subject or '(无主题)'}\n正文：{body or '(无正文)'}"
        if links:
            targets = "\n".join(f"- {link.target_url}" for link in links)
            text += f"\n链接：\n{targets}"
        return text


def header(message: Message, name: str) -> str | None:
    value = message.get(name)
    return str(value).strip() if value is not None else None


def addresses(message: Message, name: str) -> list[EmailAddress]:
    raw_values = [str(value) for value in message.get_all(name, [])]
    result = []
    for display_name, address in getaddresses(raw_values):
        if not address:
            continue
        domain = address.rpartition("@")[2].lower().rstrip(".") or None
        result.append(
            EmailAddress(name=normalize_text(display_name), address=address, domain=domain)
        )
    return result


def first_address(message: Message, name: str) -> EmailAddress | None:
    found = addresses(message, name)
    return found[0] if found else None


def parse_authentication(message: Message) -> AuthenticationSummary:
    value = header(message, "authentication-results") or ""
    results = {name.lower(): result.lower() for name, result in AUTH_PATTERN.findall(value)}
    return AuthenticationSummary(
        spf=results.get("spf", "unknown"),
        dkim=results.get("dkim", "unknown"),
        dmarc=results.get("dmarc", "unknown"),
    )


def parse_date(value: str | None, warnings: list[str]) -> datetime | None:
    if not value:
        return None
    try:
        result = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        warnings.append("邮件日期格式无效")
        return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=UTC)
    return result.astimezone(UTC)


def decode_text(part: Message, warnings: list[str]) -> str:
    content = part.get_payload(decode=True)
    if not isinstance(content, bytes):
        payload = part.get_payload()
        return payload if isinstance(payload, str) else ""

    for charset in (part.get_content_charset(), "utf-8", "gb18030", "latin-1"):
        if not charset:
            continue
        try:
            return content.decode(charset)
        except (LookupError, UnicodeDecodeError):
            continue
    warnings.append("正文字符集无法识别")
    return content.decode("utf-8", errors="replace")


def extract_plain_links(text: str) -> list[ParsedLink]:
    links = []
    for match in URL_PATTERN.finditer(text):
        target = match.group().rstrip(".,;:!?)]}，。；：！？）】")
        links.append(build_link(target, target, "plain"))
    return links


def build_link(display_text: str, target: str, source: str) -> ParsedLink:
    try:
        parsed = urlsplit(target)
        scheme = parsed.scheme.lower() or None
        host = parsed.hostname.lower().rstrip(".") if parsed.hostname else None
    except ValueError:
        scheme = None
        host = None
    return ParsedLink(
        display_text=normalize_text(display_text),
        target_url=target.strip(),
        scheme=scheme,
        host=host,
        source="html" if source == "html" else "plain",
    )


def deduplicate_links(links: list[ParsedLink]) -> list[ParsedLink]:
    result = []
    seen = set()
    for link in links:
        key = (link.display_text, link.target_url, link.source)
        if key not in seen:
            seen.add(key)
            result.append(link)
    return result


def detect_mime(content: bytes) -> str:
    signatures = (
        (b"%PDF-", "application/pdf"),
        (b"MZ", "application/x-dosexec"),
        (b"PK\x03\x04", "application/zip"),
        (b"\x89PNG\r\n\x1a\n", "image/png"),
        (b"\xff\xd8\xff", "image/jpeg"),
    )
    for signature, mime_type in signatures:
        if content.startswith(signature):
            return mime_type
    return "application/octet-stream"


def normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()
