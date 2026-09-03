# 钓鱼邮件检测系统开发指导文档

> 版本：v1.2

## 1. 项目目标

系统接收一封 `.eml` 邮件，从固定模式、附件和正文三个方面进行检测，最后输出 0～100 的风险分数，以及“正常、可疑、恶意”三级结论。

开发时优先保证：

- 功能能够运行和演示；
- 三个检测模块通过统一接口集成；
- 结果包含简单、明确的判断理由；
- 不执行附件、不访问邮件中的链接、不泄露邮件内容。

## 2. 系统流程

```text
.eml 邮件
    │
    ▼
邮件解析与标准化
    │
    ├── 固定模式检测
    ├── 附件安全检测
    └── 正文 LLM 检测
             │
             ▼
        风险聚合层
             │
             ▼
      分数、结论和原因
```

推荐使用 Python 3.12 及以上版本。项目采用 Pydantic 定义公共数据结构，pytest 编写测试，Ruff 检查基本代码规范。

## 3. 项目结构

```text
src/phishing_detector/
├── models/                 # 公共数据结构
├── parser/                 # 邮件解析与标准化
├── detectors/              # 三个检测模块的公共接口
└── aggregator/             # 风险分数聚合
tests/
├── unit/                   # 单元测试
└── fixtures/               # 脱敏测试邮件
doc/
└── DEVELOPMENT_GUIDE.md    # 本文档
```

## 4. 邮件标准化格式

解析层只负责提取信息，不负责判断邮件是否恶意。所有检测模块使用同一个 `ParsedEmail` 对象。

```json
{
  "email_id": "email-001",
  "headers": {
    "subject": "您的账户需要重新验证",
    "from": {
      "name": "某银行客服",
      "address": "service@example-login.test",
      "domain": "example-login.test"
    },
    "sender": null,
    "reply_to": [
      {
        "name": "",
        "address": "support@another-domain.test",
        "domain": "another-domain.test"
      }
    ],
    "date": "2026-09-03T08:30:00Z",
    "message_id": "<abc123@example-login.test>",
    "authentication": {
      "spf": "fail",
      "dkim": "none",
      "dmarc": "fail"
    }
  },
  "body": {
    "plain_text": "您的账户即将停用，请立即验证……",
    "html_text": "您的账户即将停用，请立即验证……",
    "llm_text": "主题：您的账户需要重新验证\n正文：您的账户即将停用……",
    "truncated": false
  },
  "links": [
    {
      "display_text": "https://bank.example.com",
      "target_url": "http://192.0.2.1/login",
      "scheme": "http",
      "host": "192.0.2.1",
      "source": "html"
    }
  ],
  "attachments": [
    {
      "attachment_id": "att-001",
      "filename": "账单.pdf.exe",
      "declared_mime": "application/pdf",
      "detected_mime": "application/x-dosexec",
      "size_bytes": 16384,
      "sha256": "64 位 SHA-256 摘要",
      "content_ref": "memory://email-001/att-001"
    }
  ],
  "parse_warnings": []
}
```

标准化要求：

- 正文统一解码为 Unicode；
- HTML 只提取可见文本和链接，不执行脚本；
- 域名转为小写；
- `declared_mime` 保存邮件声明的类型，`detected_mime` 保存根据文件头识别的类型；
- 附件内容不放入 JSON，只通过 `content_ref` 在程序内部读取；
- 设置邮件大小、附件数量和单个附件大小限制；
- 无法解析的字段记录到 `parse_warnings`。

三个模块使用的主要字段：

| 模块 | 输入字段 |
| --- | --- |
| 固定模式检测 | `headers`、`links` |
| 附件安全检测 | `attachments`、附件内部引用 |
| 正文内容检测 | `headers.subject`、`body.llm_text` |

## 5. 检测结果格式

三个检测器统一返回：

```json
{
  "module": "pattern",
  "status": "success",
  "score": 78,
  "verdict": "malicious",
  "signals": [
    {
      "code": "LINK_TEXT_TARGET_MISMATCH",
      "severity": "high",
      "confidence": 0.95,
      "description": "链接显示地址与实际地址不一致",
      "evidence": "显示 bank.example.com，实际为 192.0.2.1"
    }
  ],
  "errors": []
}
```

- `module`：`pattern`、`attachment` 或 `content`；
- `status`：`success`、`partial` 或 `failed`；
- `score`：0～100，检测失败时为 `null`；
- `verdict`：`benign`、`suspicious`、`malicious` 或 `unknown`；
- `signals`：命中的风险项；
- `errors`：可展示的错误信息，不写密钥或完整邮件正文。

## 6. 各模块基本要求

### 6.1 固定模式检测

至少实现：

- `From` 与 `Reply-To` 域名不一致；
- SPF、DKIM、DMARC 失败；
- 链接显示地址与实际跳转地址不一致；
- IP 地址链接、异常端口、短链接等可疑 URL；
- 双重或相似域名等简单伪造特征。

单个规则只能作为风险证据，不应仅凭“使用 HTTP”直接判定邮件恶意。

### 6.2 附件安全检测

至少实现：

- 计算附件 SHA-256；
- 通过哈希查询接口检查已知恶意附件；
- 比较扩展名、MIME 声明和真实文件类型；
- 检测可执行文件、脚本和双扩展名。

禁止执行附件。第三方平台默认只查询哈希，不上传附件原文。

### 6.3 正文 LLM 检测

至少识别：

- 索取账号、密码或验证码；
- 异常付款、转账或退款；
- 使用紧迫、威胁或中奖话术；
- 冒充机构并诱导点击链接或下载附件。

LLM 应返回结构化 JSON。邮件正文属于不可信数据，正文中的指令不能改变模型的检测任务。模型调用失败时返回 `unknown`，不能返回“安全”。

## 7. 聚合规则

初始权重：

```text
总分 = 固定模式分 × 0.40 + 附件分 × 0.35 + 正文分 × 0.25
```

| 分数 | 结论 |
| --- | --- |
| 0～34 | 正常 |
| 35～69 | 可疑 |
| 70～100 | 恶意 |

补充规则：

- 命中已知恶意附件哈希时，直接判定为恶意；
- 某个模块失败时，使用其他可用模块重新计算权重，并提示“检测不完整”；
- 所有模块都失败时，结论为 `unknown`，不能判定为正常；
- 权重和阈值后续根据测试结果调整。

## 8. 开发与 Git 规范

- `main` 保存可运行版本；
- 新功能使用独立分支，例如 `feature/pattern`；
- 一个提交只完成一个主要修改；
- 公共接口改动必须同步修改测试和本文档；
- API 密钥写入 `.env`，不得提交到 Git。

提交信息示例：

```text
feat(pattern): add link mismatch detection
fix(attachment): handle empty attachment
test(content): add malicious body cases
```

## 9. 测试要求

每个模块至少准备：

- 一封正常邮件；
- 一封明显钓鱼邮件；
- 一封边界或格式异常邮件；
- 一个外部服务失败场景。

测试样本必须脱敏。不要在仓库中保存真实恶意程序，可以用无害字节模拟危险文件头。

提交代码前运行：

```bash
ruff check .
pytest
```

## 10. 功能完成标准

一项功能完成时应满足：

- 能正常运行并符合任务要求；
- 输出符合公共数据格式；
- 包含正常和异常测试；
- 不泄露密钥、完整正文或附件内容；
- 测试和代码检查通过。
