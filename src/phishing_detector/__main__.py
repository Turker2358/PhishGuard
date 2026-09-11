"""运行 python -m phishing_detector example.eml。"""

import argparse
import asyncio
from pathlib import Path

from phishing_detector.aggregator import RiskAggregator
from phishing_detector.detectors import AttachmentDetector, PatternDetector
from phishing_detector.detectors.attachment import build_hash_lookup_from_env
from phishing_detector.detectors.content import build_detector_from_env
from phishing_detector.parser import EmailStandardizer


def main() -> None:
    parser = argparse.ArgumentParser(description="检测 .eml 邮件，默认仅运行离线固定模式检测")
    parser.add_argument("files", nargs="+", type=Path, help="一个或多个 .eml 文件")
    parser.add_argument("--protect", action="append", default=[], help="受保护域名，可重复指定")
    parser.add_argument("--llm", action="store_true", help="将正文发送给已配置的 LLM 进行检测")
    args = parser.parse_args()
    llm_detector = build_detector_from_env() if args.llm else None
    if args.llm and llm_detector is None:
        parser.error("启用 LLM 需要设置 LLM_MODEL 和 LLM_API_KEY 环境变量")

    hash_lookup = build_hash_lookup_from_env()

    async def run() -> None:
        detector = PatternDetector(protected_domains=tuple(args.protect))
        attachment_detector = AttachmentDetector(hash_lookup=hash_lookup)
        for path in args.files:
            try:
                with path.open("rb") as stream:
                    raw = stream.read(20 * 1024 * 1024 + 1)
                standardized = EmailStandardizer().parse(raw)
            except (OSError, ValueError):
                parser.error(f"无法读取或解析邮件：{path}")
            results = [
                await detector.detect(standardized),
                await attachment_detector.detect(standardized),
            ]
            if llm_detector is not None:
                results.append(await llm_detector.detect(standardized))
            report = RiskAggregator().aggregate(results)
            print(f"=== {path.name} ===")
            print(report.model_dump_json(indent=2))

    asyncio.run(run())


if __name__ == "__main__":
    main()
