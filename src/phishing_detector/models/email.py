"""邮件解析后的公共数据结构。"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class EmailAddress(Model):
    name: str = ""
    address: str
    domain: str | None = None


class AuthenticationSummary(Model):
    spf: str = "unknown"
    dkim: str = "unknown"
    dmarc: str = "unknown"


class EmailHeaders(Model):
    subject: str = ""
    from_: EmailAddress | None = Field(default=None, alias="from")
    sender: EmailAddress | None = None
    reply_to: list[EmailAddress] = Field(default_factory=list)
    date: datetime | None = None
    message_id: str | None = None
    authentication: AuthenticationSummary = Field(default_factory=AuthenticationSummary)


class EmailBody(Model):
    plain_text: str = ""
    html_text: str = ""
    llm_text: str = ""
    truncated: bool = False


class ParsedLink(Model):
    display_text: str
    target_url: str
    scheme: str | None = None
    host: str | None = None
    source: Literal["plain", "html"]


class ParsedAttachment(Model):
    attachment_id: str
    filename: str
    declared_mime: str
    detected_mime: str
    size_bytes: int = Field(ge=0)
    sha256: str
    content_ref: str


class ParsedEmail(Model):
    email_id: str
    headers: EmailHeaders
    body: EmailBody
    links: list[ParsedLink] = Field(default_factory=list)
    attachments: list[ParsedAttachment] = Field(default_factory=list)
    parse_warnings: list[str] = Field(default_factory=list)


class StandardizedEmail(Model):
    """附件字节只在程序内部保存，不会进入 JSON。"""

    email: ParsedEmail
    attachment_contents: dict[str, bytes] = Field(default_factory=dict, exclude=True, repr=False)

    def get_attachment_content(self, content_ref: str) -> bytes:
        return self.attachment_contents[content_ref]
