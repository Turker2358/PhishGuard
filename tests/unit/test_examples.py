import asyncio
import subprocess
import sys
from pathlib import Path

import pytest

from phishing_detector.detectors import PatternDetector
from phishing_detector.parser import EmailStandardizer

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "examples" / "emails"


@pytest.mark.parametrize(
    ("name", "score"),
    [
        ("01_fake_account.eml", 100),
        ("02_disguised_domain.eml", 70),
        ("03_typo_domain.eml", 65),
        ("04_body_only.eml", 0),
        ("05_normal.eml", 0),
    ],
)
def test_sample_scores(name, score):
    email = EmailStandardizer().parse((SAMPLES / name).read_bytes())
    result = asyncio.run(PatternDetector(protected_domains=("example.com",)).detect(email))
    assert result.score == score


def test_cli_runs_and_reports_missing_modules():
    result = subprocess.run(
        [sys.executable, "-m", "phishing_detector", str(SAMPLES / "01_fake_account.eml")],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert result.returncode == 0
    assert '"score": 100' in result.stdout
    assert '"status": "partial"' in result.stdout
    # 不带 --llm 时不运行正文 LLM 检测，因此缺少正文模块结果（附件与固定模式正常执行）。
    assert "正文检测结果缺失" in result.stdout


def test_cli_missing_file():
    result = subprocess.run(
        [sys.executable, "-m", "phishing_detector", str(SAMPLES / "missing.eml")],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert result.returncode == 2
    assert "无法读取或解析邮件" in result.stderr
