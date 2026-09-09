# 钓鱼邮件检测系统

本项目是一个本科课程设计，通过固定模式、附件安全和大语言模型正文分析三种方式检测钓鱼邮件，并输出风险分数、检测结论和可解释的风险原因。

正文 LLM 检测模块位于 `src/phishing_detector/detectors/content/`，输入邮件主题与正文文本，在提示词中对不可信正文做定界并显式防提示注入，要求模型返回结构化 JSON，解析失败或调用失败时一律返回 `unknown`。模型与密钥等配置见 `.env.example`（`LLM_MODEL`、`LLM_API_KEY`、`LLM_API_URL`）。

附件安全检测模块位于 `src/phishing_detector/detectors/attachment/`，输入邮件附件信息，检测危险文件类型、双扩展名和 MIME 类型伪装，并根据附件 SHA-256 查询是否命中已知恶意样本，最终输出附件风险分数、检测结论和风险原因。哈希查询相关配置见 `.env.example`（`HASH_LOOKUP_API_URL`、`HASH_LOOKUP_API_KEY`）。
