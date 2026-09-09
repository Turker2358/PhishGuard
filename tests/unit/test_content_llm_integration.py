"""正文 LLM 模块的端到端联通测试。

使用一个本地的 OpenAI 兼容 /chat/completions HTTP 服务器，覆盖真实网络路径：
提示词构建 -> HTTP(S) 客户端 -> 解析/校验 -> 检测器结果。这样在无外部密钥时
也能验证整条链路。

服务器按请求次序轮转返回预先编排的响应，用于模拟：
- 模型复述 Schema（正常邮件复测场景）；
- 正确的检测结果；
- token 截断（finish_reason=length）。
"""

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from phishing_detector.detectors.content.client import OpenAICompatClient
from phishing_detector.detectors.content.llm_detector import ContentLLMDetector
from phishing_detector.models import (
    DetectorResult,
    DetectorStatus,
    EmailBody,
    EmailHeaders,
    ParsedEmail,
    StandardizedEmail,
    Verdict,
)


class OpenAICompatHandler(BaseHTTPRequestHandler):
    responses: list[dict] = []
    requests: list[dict] = []
    index = 0

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        OpenAICompatHandler.requests.append(
            {"path": self.path, "payload": json.loads(body.decode("utf-8"))}
        )
        choice = OpenAICompatHandler.responses[OpenAICompatHandler.index % len(OpenAICompatHandler.responses)]  # noqa: E501
        OpenAICompatHandler.index += 1
        payload = json.dumps({"choices": [choice]}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args) -> None:  # noqa: D401
        pass


@pytest.fixture()
def llm_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), OpenAICompatHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    OpenAICompatHandler.requests = []
    OpenAICompatHandler.index = 0
    yield server.server_address[1]
    server.shutdown()
    thread.join()


SCHEMA_RECITAL = {
    "message": {"content": '{"type": "object", "properties": {}, "required": []}'},
    "finish_reason": "stop",
}
GOOD = {
    "message": {
        "content": '{"is_phishing": true, "score": 88, "signals": [], "reason": "重申验证"}'
    },
    "finish_reason": "stop",
}
TRUNCATED = {
    "message": {"content": '{"is_phishing": tr'},
    "finish_reason": "length",
}


def _email() -> StandardizedEmail:
    parsed = ParsedEmail(
        email_id="e2e-001",
        headers=EmailHeaders(subject="账户验证"),
        body=EmailBody(plain_text="请点击链接验证", llm_text="请点击链接验证"),
    )
    return StandardizedEmail(email=parsed)


def _detector(port: int) -> ContentLLMDetector:
    client = OpenAICompatClient(
        api_key="sk-test", model="gpt-test", base_url=f"http://127.0.0.1:{port}/v1"
    )
    return ContentLLMDetector(client)


def _run(detector: ContentLLMDetector) -> "DetectorResult":
    return asyncio.run(detector.detect(_email()))


def test_real_http_good_detection(llm_server) -> None:
    OpenAICompatHandler.responses = [GOOD]
    result = _run(_detector(llm_server))

    assert result.status == DetectorStatus.SUCCESS
    assert result.score == 88
    assert result.verdict == Verdict.MALICIOUS
    # 确保请求确实走到本地服务器，且携带了提示词。
    assert OpenAICompatHandler.requests
    assert OpenAICompatHandler.requests[0]["path"].endswith("/chat/completions")


def test_real_http_schema_recital_is_failed(llm_server) -> None:
    OpenAICompatHandler.responses = [SCHEMA_RECITAL]
    result = _run(_detector(llm_server))

    # Schema 复述不得被当作检测结果。
    assert result.status == DetectorStatus.FAILED
    assert result.verdict == Verdict.UNKNOWN
    assert result.score is None
    assert "复述" in result.errors[0] or "Schema" in result.errors[0]


def test_real_http_truncation_is_failed(llm_server) -> None:
    OpenAICompatHandler.responses = [TRUNCATED]
    result = _run(_detector(llm_server))

    assert result.status == DetectorStatus.FAILED
    assert result.verdict == Verdict.UNKNOWN
    assert "截断" in result.errors[0]


def test_real_http_structured_output_flag(llm_server) -> None:
    OpenAICompatHandler.responses = [GOOD]
    client = OpenAICompatClient(
        api_key="sk-test",
        model="gpt-test",
        base_url=f"http://127.0.0.1:{llm_server}/v1",
        structured_output=True,
    )
    result = _run(ContentLLMDetector(client))

    assert result.status == DetectorStatus.SUCCESS
    assert OpenAICompatHandler.requests[0]["payload"]["response_format"] == {
        "type": "json_object"
    }
