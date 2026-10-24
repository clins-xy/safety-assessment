# 接口说明

基础路径 `/api`；JSON 请求/响应。业务时间统一使用北京时间（UTC+08:00）`YYYY/MM/DD/HH.mm`，例如 `2026/10/23/10.11`，精度为分钟。空时间仍为 `null`；同一分钟多条记录通过 ID 排序。`sessions.expires_at` 是用于登录有效期判断的 Unix 数字时间戳，不转为文本、不修改字段类型。错误格式 `{"detail":"说明"}`；422 参数错误可能返回数组。需登录的接口使用同源 HttpOnly Cookie，无需前端读取 token。Cookie 有效期 8 小时。

## 系统与认证

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/system/status` | 是否初始化及数据库类型，公开 |
| POST | `/system/init` | 本机首次创建管理员；`username`、`password`（至少 8 位） |
| POST | `/system/login` | `username`、`password`；返回用户信息并设置 Cookie |
| POST | `/system/logout` | 删除会话 |
| GET | `/system/me` | 当前用户 |
| POST | `/system/users` | 管理员创建账户：`username`、`password`、`role: user/admin` |
| GET/PUT | `/system/config` | 管理员读取/全量更新运行配置 |
| GET | `/system/logs` | 管理员最近 200 条操作审计 |
| GET | `/examples` | 内置正反案例目录、预期信号数量 |
| GET | `/system/llm/config` | 管理员读取脱敏的大模型配置，不返回 API Key |
| PUT | `/system/llm/config` | 管理员设置 OpenAI 兼容服务、模型、超时、提示词和 API Key |
| GET | `/system/llm/health` | 登录用户查看配置状态；未实测时 `reachable=null`，不发起模型请求 |
| POST | `/system/llm/test` | 管理员实际发送无业务代码的探测请求，返回 `reachable` 和脱敏提示；可能产生调用费用 |

`PUT /system/config` 的字段：`default_timeout`（5–3600 秒）、`max_concurrency`（1–16）、`retention_days`（1–3650，仅策略）、`docker_image`、`allow_git`、`max_files`（1–20000）、`max_file_bytes`（1024–4194304）。

LLM 配置字段：`enabled`、`provider=openai_compatible`、`base_url`、`api_key`、`model`、`timeout_seconds`（5–300）、`max_code_chars`（1000–50000）、`system_prompt`。空 `api_key` 表示保持已保存的 Key；响应只返回 `api_key_configured`。

非空 `SAFETY_LLM_*` 环境变量覆盖数据库配置，修改后需重启；配置响应 `environment_overrides` 列出覆盖的字段名，不含密钥值。启用但没有 Key 返回 422。Base URL 必须是无凭据、查询参数和片段的 HTTP(S) 地址。

## 项目

管理员可访问所有项目；普通用户仅可操作自己创建的项目。

`POST /projects` 请求：

```json
{
  "project_name": "用户服务评估",
  "source_type": "local",
  "source_path": "E:\\learn\\safety-assessment\\src\\safety_assessment\\examples\\unsafe",
  "task_content": "检查 SQL 与 Shell 注入风险",
  "environment_type": "static"
}
```

`source_type` 可为 `local` / `git` / `inline`；`environment_type` 可为 `static` / `docker`。`task_content` 是审计说明，不是执行命令或模型提示词。POST 成功返回完整项目对象，HTTP 201。

### 一步导入并评估

`POST /projects/import`（登录后可用，`multipart/form-data`，成功 HTTP 202）：

- `files`：可重复的上传字段，接受多个 `.py` 文件或 `.zip`，文件夹上传以相对路径作为 filename；无需传入服务器目录。
- 或 `code` + 可选 `filename=submitted.py`：直接粘贴源码。不可同时传 `files` 和 `code`。
- 可选 `project_name`、`task_content`：空名称按文件、文件夹或 ZIP 名称自动生成。

返回 `project_id`、`project_name`、`file_count`、`skipped_count`、`bytes`、`started`、`message`。项目和所有源码原子保存，后台自动分析并生成报告；使用已有全局 LLM 配置，不要求每次上传改配置。模型失败仍保存静态结果和报告。并发已满时 HTTP 202、`started=false`，源码保留，稍后调用项目 `/start`。

最多 200 个源码文件、单源码 1 MiB、上传合计及解压源码合计各 20 MiB、ZIP 条目 10000；整个 multipart 请求上限 21 MiB。只接受 UTF-8 Python 源码，依赖和非源码文件跳过。非法路径、符号链接、重名冲突、语法错误返回 422；超大请求返回 413；未登录返回 401。沿用现有表，不新增或修改字段。

### 已有项目提交

创建一个 `source_type=inline` 的项目后，前端「提交代码」页或以下接口可以直接分析代码：

`POST /projects/{id}/submissions`

```json
{"filename":"review.py","language":"python","code":"import os\ndef run(value):\n    os.system(value)"}
```

该请求先验证 Python 语法及 UTF-8 字节数（最多 1 MiB，文件名必须以 `.py` 结尾），保存 `code_submissions`，立即运行静态 AST 规则；若管理员启用模型，则通过 OpenAI Chat Completions 兼容协议异步请求复核。分析记录、模型状态和漏洞在同一事务中写入现有表。接口不会执行提交代码；模型失败不影响源码和静态结果保存。重复分析保留历史，替换该提交的漏洞；模型文件名、行号越界时不采纳结果。

提交后可调用 `/projects/{id}/start`，从已保存源码生成完整报告；该阶段复用提交时的 LLM 结果，不重复发送源码。未提交源码的 inline 项目无法完成评估。本地目录和 Git 项目不调用模型。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/projects` | 当前用户可见项目，按 ID 降序 |
| GET | `/projects/{id}` | 项目详情、漏洞数、候选路径数、报告数 |
| POST | `/projects/{id}/start` | 仅 `created` 状态能启动；并发或状态冲突返回 409 |
| POST | `/projects/{id}/stop` | 等待取消生效，保留已保存数据 |
| DELETE | `/projects/{id}` | 运行中返回 409；先停止再删除 |
| GET | `/projects/{id}/stages` | 五阶段状态 |
| GET | `/projects/{id}/workers` | 六类角色任务及结果、错误、时间 |
| GET | `/projects/{id}/vulnerabilities` | 漏洞数组；可选 `risk_level`、`verify_status` 筛选 |
| GET | `/projects/{id}/vulnerabilities/{vuln_id}` | 完整漏洞证据详情 |
| GET | `/projects/{id}/attack-paths` | 候选路径及 `items` 漏洞关联与利用顺序 |
| GET | `/projects/{id}/report` | Markdown、HTML、文件路径；未生成返回 404 |
| GET | `/projects/{id}/report/download?format=md` | 下载 Markdown；`format=html` 下载 HTML |
| GET | `/projects/{id}/logs` | 运行日志 |
| GET | `/projects/{id}/messages` | 角色消息 |
| GET | `/projects/{id}/resources` | CPU、RSS MiB、token=0、记录时间 |
| GET | `/projects/{id}/submissions` | 项目的代码提交历史，不返回源码正文 |
| GET | `/projects/{id}/submissions/{submission_id}` | 读取已入库的完整源码，校验项目所有者权限 |
| GET | `/projects/{id}/submission-analyses` | 分析历史、静态 JSON、LLM 关联 ID、`llm_status`、`llm_summary`、`llm_result_json` |
| POST | `/projects/{id}/submissions/{submission_id}/analyze` | 对已保存代码重新分析；运行中和已生成报告的项目返回 409 |

阶段、角色、日志、消息、资源接口支持 `after`（记录 ID，默认 0）、`limit`（默认 500，最大 2000）用于增量读取。漏洞验证状态为 `pending` / `static_confirmed` / `needs_review`；静态核验不是动态漏洞验证。

项目状态：`created`、`running`、`completed`、`failed`、`stopped`。阶段名：`environment_scan`、`code_analysis`、`vulnerability_verify`、`report_generate`、`done`。角色/阶段状态：`idle`、`running`、`success`、`failed`；被停止的当前阶段记为 `failed` 并保存停止原因，未开始阶段保留 `idle`。

漏洞详情含 `vuln_code`、`vuln_title`、`risk_level`、`file_path`、`line_number`、`rule_id`、`impact_text`、`condition_text`、`evidence_text`、`reproduce_steps_text`、`verify_code_text`、`remediation_text`、`verify_status`。`verify_code_text` 在本版记录不执行目标代码的静态核验方法，不伪造 exploit 验证代码。

## 实时订阅

`WS /api/projects/{id}/stream` 使用登录 Cookie 和项目权限校验；不接收查询参数 token。连接后发送当前项目状态，每 10 秒空闲发送 heartbeat。队列上限 256，极慢客户端可能丢弃旧事件，HTTP 查询是状态真相来源。

```json
{
  "type": "vulnerability_found",
  "timestamp": "2026/10/21/20.00",
  "data": {"project_id": 1, "vuln_id": 1, "vuln_title": "外部输入拼接 SQL", "risk_level": "high"}
}
```

| 类型 | `data` 核心字段 |
| --- | --- |
| `project_status` | `project_id`, `project_status` |
| `stage_status` | `project_id`, `stage_name`, `stage_status` |
| `worker_status` | `worker_task_id`, `worker_role`, `task_status` |
| `chat_message` | `worker_role`, `message_text` |
| `runtime_log` | `log_level`, `log_content` |
| `resource_usage` | `cpu_usage`, `memory_usage`, `token_count` |
| `vulnerability_found` | `vuln_id`, `vuln_title`, `risk_level` |
| `report_ready` | `project_id`, `report_id` |
| `heartbeat` | `project_id` |

首次状态帧和心跳可能没有 `timestamp`。前端通过事件触发 HTTP 快照刷新，并对运行项目每 3 秒轮询作为回退。
