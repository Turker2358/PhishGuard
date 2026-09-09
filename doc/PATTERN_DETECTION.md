# 固定模式检测说明

实现位置：`src/phishing_detector/detectors/pattern.py`。输入为标准化邮件
`StandardizedEmail`，输出为 `module="pattern"` 的 `DetectorResult`，可直接交给聚合层。
全部规则离线执行，不访问链接、不查询 DNS，也不调用 LLM。

## 调用方式

```python
import asyncio
from pathlib import Path
from phishing_detector.parser import EmailStandardizer
from phishing_detector.detectors import PatternDetector

mail = EmailStandardizer().parse(Path("example.eml").read_bytes())
detector = PatternDetector(
    protected_domains=("example.com",),
    brand_domains={"示例银行客服": ("example.com",)},
    allowed_domain_pairs=(("example.com", "partner.org"),),
)
result = asyncio.run(detector.detect(mail))
print(result.model_dump_json(indent=2))
```

三个配置都可以省略。已有异步函数中使用 `await detector.detect(mail)`。

## 规则和分数

| 风险码 | 条件 | 分数 |
| --- | --- | ---: |
| `DISPLAY_NAME_SPOOFING` | 显示名称里的邮箱域名或配置机构与实际发件域名不符 | 35 |
| `FROM_REPLY_TO_MISMATCH` | 发件人与回复地址不属于同一注册域名 | 20 |
| `SPF_FAILED` | 邮件头报告 SPF fail / softfail | 15 |
| `DKIM_FAILED` | 邮件头报告 DKIM fail / softfail | 15 |
| `DMARC_FAILED` | 邮件头报告 DMARC fail / softfail | 25 |
| `LINK_TEXT_TARGET_MISMATCH` | 显示链接与实际目标不属于同一注册域名 | 35 |
| `IP_URL` | HTTP(S) 链接主机为 IPv4 或 IPv6 | 15 |
| `UNUSUAL_PORT` | 端口不是 HTTP 80 或 HTTPS 443 | 10 |
| `SHORT_URL` | 使用内置常见短链域名 | 10 |
| `HTTP_URL` | 使用明文 HTTP | 5 |
| `URL_USERINFO` | URL 含用户名部分，例如 example.com@evil.org | 20 |
| `DISGUISED_DOMAIN` | 受保护域名出现在其他主机名内部 | 35 |
| `SIMILAR_DOMAIN` | 与受保护域名的字符串相似度至少为 0.85 | 25 |
| `INVALID_URL` | Web 链接主机或端口无法正常解析 | 10 |

同一风险码只计分一次；三个认证风险合计最多 25 分，其余风险相加，总分最高 100。
0～34 为正常，35～69 为可疑，70～100 为恶意。这里的“正常”只表示未达到本模块
的风险阈值，不表示邮件经过身份认证或完全安全。

## 本次三项改进

### 显示名称伪造

从 `headers.from.name` 提取邮箱形式的文字，与真实发件人的域名比较。例如：

- 显示 `support@bank.com`，实际 `attacker@evil.org`：加 35 分；
- 显示 `support@mail.example.com`，实际 `notice@example.com`：不加分；
- 显示 `示例银行客服`：只有配置 `brand_domains` 后才检查机构身份。

机构名称采用去除首尾空格、忽略大小写后的完整匹配，可以为同一名称配置多个官方
域名。普通人名、未配置机构名不作猜测。显示邮箱的用户名不同但域名相同不触发。

### 注册域名和定向允许列表

使用 `tldextract` 内置 Public Suffix List 快照，不把域名简单截成最后两段。
例如 `mail.example.co.uk` 和 `example.co.uk` 视为同一站点，而 `bank.co.uk`
和 `evil.co.uk` 不同。启用私有后缀识别，因此 `alice.github.io` 与
`bob.github.io` 不会被合并为同一站点。未知后缀保留完整主机名进行比较。

域名比较会统一大小写、末尾点和 IDNA。IP 地址按完整地址比较。
这项比较用于发件人与回复地址、显示名称里的邮箱和显示链接与实际目标。

`allowed_domain_pairs=(("example.com", "partner.org"),)` 只允许从前者到后者：

- From example.com → Reply-To partner.org：不触发地址不一致；
- 显示 example.com → 链接 partner.org：不触发链接不一致；
- 反方向、未配置的子域名对不会自动放行；
- 仅豁免这两种不一致规则，HTTP、异常端口、显示名称伪造等仍会检测。

配置值填主机名，不填完整 URL。保护域名与机构域名的用途不同，需分别配置。
注册域名一致不意味着站点一定可信；被入侵或委托给第三方的子域名仍可能有风险。
快照不会在线更新，后续可随依赖升级更新。配置依据见
[tldextract 官方说明](https://github.com/john-kurkowski/tldextract)。

### 认证计分修正

原先 SPF、DKIM、DMARC 同时失败累加为 55 分，现在最多计 25 分，保留全部风险项。
例如三个认证失败 + 伪造显示链接，模块得分为 `25 + 35 = 60`，而非 90。
缺失、pass、none 或错误状态不当作认证失败；现有实现兼容 fail / softfail 字符串。

认证数据仍来自原始邮件头，当前标准化对象没有可信接收服务器来源字段，不能判断
认证头是否被伪造。检测器没有重新验证 SPF、DKIM 或 DMARC；分数上限只缓解关联
证据重复计分，不解决认证头真实性问题。

## 测试与边界

运行 `.venv/bin/pytest tests/unit/test_pattern.py` 验证规则。测试覆盖正常邮件、组合
钓鱼特征、重复链接、损坏 URL、IPv6、IDNA、显示名称伪造、多级公共后缀、私有后缀、
允许列表方向性及认证上限；另验证域名提取不会发起网络请求。

信号只输出规则描述和必要端口，不输出完整邮箱、链接参数或正文。相似度与置信度
属于课程项目的经验设置，未做统计校准。未实现 Unicode 视觉混淆、HTML 表单或
重定向参数分析；短链只识别内置域名，不展开目标。
