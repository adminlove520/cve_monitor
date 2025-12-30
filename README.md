# CVE威胁情报推送系统

## 📋 项目简介

该项目用于监控多个安全平台的最新威胁情报信息，并通过多种渠道（钉钉、飞书、Telegram等）进行实时推送。

系统融合了以下多个数据源的威胁情报信息：
- OSCS1024漏洞库
- 安天威胁情报
- Tenable平台
- 微软安全中心
- CVE平台
- 奇安信CERT
- 微步（ThreatBook）

## ✨ 功能特性

- **🔄 多平台监控**：同时监控多个漏洞平台的最新CVE信息
- **📢 多渠道推送**：支持钉钉、飞书、Telegram Bot、Discard等多种推送渠道
- **📋 日报生成**：自动生成每日漏洞日报，支持Markdown和HTML格式
- **📆 周报功能**：每周五15:00北京时区自动生成周报并推送，包含本周所有日报
- **🌐 Web界面**：生成静态HTML页面，分为周报和日报两个板块，可部署到GitHub Pages
- **📡 RSS支持**：生成WordPress兼容的RSS feed，每日生成当天威胁情报RSS，每周五生成包含本周所有漏洞的每周威胁情报汇总RSS
- **🔍 去重处理**：使用SQLite数据库存储已推送的漏洞信息，避免重复推送
- **🛡️ 健壮性优化**：增强了异常处理、资源管理、中断处理等功能
- **⚙️ 灵活配置**：通过YAML配置文件可以灵活定制推送渠道和系统参数
- **📈 GitHub API优化**：支持GitHub token认证，解决速率限制问题

## 📦 安装依赖

```bash
pip install -r requirements.txt
```

## ⚙️ 配置说明

### 配置文件

在`config.yaml`文件中配置推送渠道和相关参数：

```yaml
all_config:
 dingding:
   - enable: 1  # 1启用, 0禁用
   - webhook: https://oapi.dingtalk.com/robot/send?access_token=
   - secretKey: 
   - app_name: dingding
 feishu:
   - enable: 0  # 1启用, 0禁用
   - webhook: xxx
   - app_name: feishu
 tgbot:
   - enable: 0  # 1启用, 0禁用
   - token: 123
   - group_id: 123
   - app_name: tgbot
 discard:
   - enable: 0  # 1启用, 0禁用
   - webhook: https://discord.com/api/webhooks/
   - app_name: discard
   - send_normal_msg: ON  # 是否推送每日消息
   - send_daily_report: ON  # 是否推送日报
 translate:
   - enable: 1
   - provider: google
   - api_key: ""  # 如果使用googletrans库则不需要填写
   - source_lang: auto
   - target_lang: zh-cn
 datasources:
   - oscs1024: 1  # 1启用, 0禁用
   - antiycloud: 1
   - tenable: 1
   - microsoft: 1
   - okcve: 1
   - qianxin: 1
   - threatbook: 1
 run_config:
   - enable_night_sleep: 1  # 启用夜间休眠
   - night_sleep_start: 0  # 休眠开始时间（小时）
   - night_sleep_end: 7  # 休眠结束时间（小时）
   - check_interval: 7200  # 检查间隔，单位：秒，默认2小时
   - max_run_time: 3540  # 最大运行时间，单位：秒，默认59分钟
   - exception_retry_interval: 60  # 异常重试间隔，单位：秒，默认1分钟
   - github_token: ""  # GitHub API令牌，用于解决速率限制问题
```

### 环境变量

系统支持通过环境变量覆盖配置文件中的设置，环境变量优先级高于配置文件。以下是支持的环境变量：

| 环境变量 | 描述 | 默认值 |
|---------|------|--------|
| `DINGDING_WEBHOOK` | 钉钉机器人webhook | 配置文件中的值 |
| `DINGDING_SECRET` | 钉钉机器人密钥 | 配置文件中的值 |
| `TELEGRAM_TOKEN` | Telegram Bot令牌 | 配置文件中的值 |
| `TELEGRAM_GROUP_ID` | Telegram群组ID | 配置文件中的值 |
| `FEISHU_WEBHOOK` | 飞书机器人webhook | 配置文件中的值 |
| `DISCARD_WEBHOOK` | Discard webhook | 配置文件中的值 |
| `DISCARD_SEND_NORMAL_MSG` | 是否推送每日消息 | ON |
| `DISCARD_SEND_DAILY_REPORT` | 是否推送日报 | ON |
| `GITHUB_TOKEN` | GitHub API令牌 | 配置文件中的值 |
| `NIGHT_SLEEP_SWITCH` | 是否开启夜间休眠 | ON |
| `DAILY_REPORT_SWITCH` | 是否生成日报 | ON |
| `NO_PUSH_SWITCH` | 是否关闭推送功能 | OFF |
| `DATASOURCE_OSCS1024` | 是否启用OSCS1024数据源 | 1 |
| `DATASOURCE_ANTIYCLOUD` | 是否启用安天数据源 | 1 |
| `DATASOURCE_TENABLE` | 是否启用Tenable数据源 | 1 |
| `DATASOURCE_MICROSOFT` | 是否启用微软数据源 | 1 |
| `DATASOURCE_OKCVE` | 是否启用CVE平台数据源 | 1 |
| `DATASOURCE_QIANXIN` | 是否启用奇安信CERT数据源 | 1 |
| `DATASOURCE_THREATBOOK` | 是否启用微步数据源 | 1 |
| `WEEKLY_REPORT_SWITCH` | 是否生成周报 | ON |

## 🚀 使用方法

### 直接运行

```bash
python CVE_monitor.py
```
- 持续运行模式，适合在服务器上长期运行
- 定期检查漏洞更新并推送
- 自动生成日报（如果启用）

### 单次执行模式

```bash
python CVE_monitor.py --once
```
- 只执行一次，适合GitHub Action运行
- 执行完后自动退出

### 生成日报模式

```bash
python CVE_monitor.py --daily-report
```
或
```bash
python CVE_monitor.py --once --daily-report
```
- 生成当日的漏洞日报（Markdown和HTML格式）
- 生成当天威胁情报的RSS
- 不推送日报，仅存储到archive目录
- 更新index.html首页

### 生成周报模式

```bash
python CVE_monitor.py --weekly-report
```
或
```bash
python CVE_monitor.py --once --weekly-report
```
- 生成包含本周所有日报的周报（Markdown和HTML格式）
- 生成包含所有漏洞的RSS（每周威胁情报汇总）
- 推送给Discard（如果配置了）
- 更新index.html首页

### 关闭推送模式

```bash
python CVE_monitor.py --no-push
```
- 关闭推送功能，只收集数据
- 可与其他模式组合使用，如：
  ```bash
  python CVE_monitor.py --once --daily-report --no-push
  ```

## 📁 目录结构

```
.
├── CVE_monitor.py       # 主程序
├── config.yaml          # 配置文件
├── data.db              # SQLite数据库
├── requirements.txt     # 依赖列表
├── log/                 # 日志目录
│   ├── run.log          # 运行日志
│   └── err.log          # 错误日志
├── archive/             # 日报存档
│   └── YYYY-MM-DD/      # 按日期存档
├── static/              # 静态文件
│   └── template.html    # HTML模板
└── index.html           # 根目录索引页面
└── RSS/                 # RSS目录
    └── cve_rss.xml      # WordPress兼容RSS feed，包含每日和每周威胁情报汇总
```

## 📊 日志说明

系统日志存放在`log`目录下：
- `run.log`：运行日志，记录程序运行状态
- `err.log`：错误日志，记录程序异常信息

日志文件会按天进行切割，并保留最近7天的日志记录。

## 🔄 GitHub Actions

项目包含两个GitHub Actions工作流配置，用于自动生成日报和周报：

### 日报工作流（CVE-Monitor.yml）
- **定时运行**：北京时间9点（UTC时间1点）自动运行
- **手动触发**：支持通过GitHub UI手动触发运行
- **功能**：
  - 生成每日漏洞日报（Markdown和HTML格式）
  - 生成当天威胁情报的RSS
  - 更新index.html首页
  - 自动提交更新到仓库
- **环境变量控制**：
  - `DAILY_REPORT_SWITCH`：设置为 `ON` 启用日报生成，`OFF` 禁用
  - `NIGHT_SLEEP_SWITCH`：设置为 `ON` 开启夜间休眠，`OFF` 禁用
  - `NO_PUSH_SWITCH`：设置为 `ON` 关闭推送功能，`OFF` 启用

### 周报工作流（CVE-Monitor-Weekly.yml）
- **定时运行**：每周五15:00北京时区（UTC时间7点）自动运行
- **手动触发**：支持通过GitHub UI手动触发运行
- **功能**：
  - 生成包含本周所有日报的周报（Markdown和HTML格式）
  - 生成包含所有漏洞的RSS（每周威胁情报汇总）
  - 更新index.html首页
  - 自动提交更新到仓库
- **环境变量控制**：
  - `WEEKLY_REPORT_SWITCH`：设置为 `ON` 启用周报生成，`OFF` 禁用
  - `NO_PUSH_SWITCH`：设置为 `ON` 关闭推送功能，`OFF` 启用

### GitHub Actions部署说明

1. **启用GitHub Actions**：
   - 在GitHub仓库的"Actions"标签页中启用工作流
   - 无需额外配置，工作流会自动使用默认设置运行

2. **手动触发工作流**：
   - 进入GitHub仓库的"Actions"标签页
   - 选择要运行的工作流（CVE-Monitor或CVE-Monitor-Weekly）
   - 点击"Run workflow"按钮
   - 根据需要调整输入参数，然后点击"Run workflow"

3. **配置环境变量**：
   - 在GitHub仓库的"Settings" → "Secrets and variables" → "Actions"中配置环境变量
   - 环境变量优先级高于配置文件，可用于覆盖配置

4. **工作流输出**：
   - 工作流运行结果会显示在GitHub Actions页面
   - 生成的日报和周报会自动提交到仓库
   - 可在仓库的"Commits"页面查看自动提交的更新

两个工作流均支持：
- 自动提交更新到仓库
- 灵活的配置选项
- 支持环境变量覆盖配置
- 详细的运行日志
- 自动删除旧的工作流运行记录（保留最近7天）

## 📝 注意事项

1. 确保配置文件中至少启用了一个推送渠道
2. 程序设计为长时间运行，支持优雅退出（Ctrl+C）
3. 如需修改抓取频率，请在配置文件的`run_config`部分调整`check_interval`参数
4. 建议配置GitHub token以提高API请求速率限制

### 环境变量配置建议

- **必须配置**：推送相关的敏感信息（webhook和secretkey），通过GitHub Secrets配置
- **默认配置**：其他环境变量基本不需要配置，使用默认值即可
- **非敏感配置**：建议在`config.yaml`中配置，而非环境变量
- **灵活调整**：
  - 临时调整：通过手动触发工作流时的输入参数
  - 长期固定配置：通过GitHub Variables配置
- **例外情况**：只有当需要修改默认行为时（如禁用数据源、调整推送行为等），才需要配置其他环境变量

### 敏感信息配置

所有推送相关的敏感信息（如DISCARD_WEBHOOK、DINGDING_WEBHOOK等）必须通过GitHub Secrets配置，避免将敏感信息硬编码到配置文件中。

### 自动运行建议

- 每日模式：默认每天北京时间9点自动运行，生成当日威胁情报
- 周报模式：默认每周五15:00北京时区自动运行，生成每周威胁情报汇总
- 无需手动配置，工作流会自动使用默认设置运行
- 可通过GitHub Actions手动触发，灵活调整运行时机

## 🤝 贡献

欢迎提交Issue和Pull Request，共同改进项目！

## 📄 许可证

MIT License