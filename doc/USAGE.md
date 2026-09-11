# 示例邮件与检测使用方法

## 安装

在项目根目录使用 Python 3.12 或以上版本运行：

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
```

## 离线演示

检测全部示例：

```bash
.venv/bin/python -m phishing_detector examples/emails/*.eml --protect example.com
```

检测单个文件或自己导出的 `.eml` 邮件：

```bash
.venv/bin/python -m phishing_detector examples/emails/01_fake_account.eml --protect example.com
```

`--protect` 指定需要识别冒充的域名，可重复传入。默认运行固定模式和附件检测，
不访问邮件链接。未配置哈希密钥时附件仅做本地检测；配置后只向服务查询哈希。

示例是无害模拟内容，不包含真实凭据、收款账户或可执行附件。不要访问样本链接；
拼写域名 `examp1e.com` 仅作为离线字符串使用，并不保证该域名未被注册。

| 文件 | 场景 | 固定模式预期分数 | 结论 |
| --- | --- | ---: | --- |
| `01_fake_account.eml` | 显示邮箱冒充、回复地址异常、认证失败、IP 伪造链接 | 100 | 恶意 |
| `02_disguised_domain.eml` | example.com.evil.test 伪装成 example.com | 70 | 恶意 |
| `03_typo_domain.eml` | examp1e.com 拼写冒充与 HTTP 链接 | 65 | 可疑 |
| `04_body_only.eml` | 无异常链接，仅靠正文催促转账、索取验证码 | 0 | 固定模式未发现风险 |
| `05_normal.eml` | 正常课程通知及合法子域名 | 0 | 正常对照 |

上表要求传入 `--protect example.com`。正文型恶意邮件得 0 分展示了规则检测的
局限，需要结合正文检测。样本内的认证失败头也是模拟数据，不代表真正验证过。

## 如何看结果

每封邮件输出文件名和 JSON 报告：

- `score`、`verdict`：当前可用模块的综合分数和结论；
- `results.pattern.signals`：命中的固定模式规则和原因；
- `status`、`warnings`：检测是否完整，缺少哪些模块。

无附件时该模块返回 `applicable=false`，不参与权重计算；不启用正文时，示例总分
等于固定模式分数，整体为 `partial` 并提示缺少正文。恶意判定不是程序错误。
综合分数保留最高模块的风险等级下限：有模块达到 70 分时总分至少 70，否则有
模块达到 35 分时总分至少 35。这个保守策略可能放大单模块误报。
程序成功输出报告返回 0，文件读取或参数错误返回 2。

## 可选正文 LLM 检测

环境中设置 `LLM_MODEL` 和 `LLM_API_KEY`，兼容服务还可设置 `LLM_API_URL`
（基础地址，应包含服务要求的版本路径，例如 `/v1`）。程序不会自动加载 `.env`；
可以在本机编辑 `.env` 后，在终端加载这个自己维护的文件：

```bash
set -a
source .env
set +a
.venv/bin/python -m phishing_detector examples/emails/04_body_only.eml --llm
```

`--llm` 会把邮件主题及标准化正文发送给配置的服务，可能产生 API 费用。
LLM 分数不固定；未配置模型或密钥时报参数错误，调用失败则报告模块失败。
启用 LLM 且各模块完成检测时返回 `completed`。有附件而哈希查询未配置、失败或
未收录时，附件和整体均为 `partial`，已有本地风险结果仍参与评分。

2026-09-12 同步远端后，5 封示例的真实 LLM 调用均成功返回；分数随模型响应变化。
出现调用失败时应查看模块状态，不应把回退分数当成正文检测成功。
