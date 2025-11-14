GitHub Monitor - 代码仓库监控系统

一个基于 Cloudflare Workers 的 GitHub 代码仓库监控系统，能够实时监控指定仓库的代码更新，并通过 Telegram 发送通知。

https://img.shields.io/badge/Version-1.0.0-blue.svg
https://img.shields.io/badge/Platform-Cloudflare_Workers-orange.svg
https://img.shields.io/badge/License-MIT-green.svg

✨ 功能特性

功能 描述 状态
🔔 实时监控 自动检测 GitHub 仓库的代码提交 ✅
📱 Telegram 通知 通过 Telegram Bot 发送更新通知 ✅
⚡ 高性能 基于 Cloudflare Workers 边缘计算 ✅
🔒 安全认证 管理员密码保护 ✅
📊 多仓库支持 同时监控多个 GitHub 仓库和分支 ✅
⏰ 定时检查 支持 Cron 定时任务自动检查 ✅
🛡️ API 优化 支持 GitHub Token 提高 API 限制 ✅

🚀 快速开始

1. 创建 Cloudflare Worker

1. 登录 Cloudflare Dashboard
2. 进入 Workers & Pages 页面
3. 点击 "Create application"
4. 选择 "Create Worker"
5. 给 Worker 命名并点击 "Deploy"

2. 配置 KV 命名空间

```bash
# 创建 KV 命名空间
名称: github-monitor-storage
用途: 存储监控数据、配置信息和会话
```

操作步骤：

1. 在 Workers & Pages 页面，选择 "KV"
2. 点击 "Create namespace"
3. 输入名称（例如：github-monitor-storage）
4. 记录下命名空间 ID

3. 绑定 KV 到 Worker

1. 进入你创建的 Worker
2. 点击 "Settings" 标签页
3. 点击 "Variables" 部分
4. 在 "KV Namespace Bindings" 点击 "Add binding"
5. 设置：
   · Variable name: STORAGE
   · KV namespace: 选择刚才创建的命名空间

4. 配置 Cron 触发器

表达式 说明 推荐场景
*/30 * * * * 每30分钟检查一次 高频更新仓库
0 * * * * 每小时检查一次 常规监控
0 */6 * * * 每6小时检查一次 低频更新仓库

配置步骤：

1. 在 Worker 的 "Settings" 标签页
2. 点击 "Triggers" 部分
3. 在 "Cron Triggers" 点击 "Add trigger"
4. 设置定时任务表达式

5. 上传代码

将提供的 worker.js 代码复制粘贴到 Worker 编辑器中，然后点击 "Save and Deploy"。

⚙️ 详细配置

初始访问

部署完成后，访问你的 Worker URL：

```
https://your-worker-name.your-subdomain.workers.dev/
```

默认登录信息：

· 🔐 用户名: admin
· 🔑 密码: admin123

⚠️ 安全提示: 首次登录后请立即修改默认密码！

GitHub Token 配置

推荐配置 GitHub Token 以提高 API 限制：

1. 访问 GitHub Settings → Developer settings → Personal access tokens
2. 点击 "Generate new token"
3. 输入 token 名称（例如：GitHub Monitor）
4. 选择有效期（推荐：90天）
5. 无需选择任何权限（空权限即可访问公开仓库）
6. 生成 token 并复制
7. 在系统设置的 "GitHub API 配置" 中粘贴 token

Telegram 通知配置

创建 Telegram Bot：

1. 在 Telegram 中搜索 @BotFather
2. 发送 /newbot 创建新机器人
3. 设置机器人名称和用户名
4. 获取 Bot Token

获取 Chat ID：

1. 向你的机器人发送任意消息
2. 访问以下 URL（替换为你的 Bot Token）：
   ```
   https://api.telegram.org/bot<YourBOTToken>/getUpdates
   ```
3. 在响应中找到 chat.id 字段
4. 在系统设置的 "Telegram 通知配置" 中填写 Token 和 Chat ID

📖 使用方法

添加监控仓库

在 "添加监控仓库" 表单中填写以下信息：

字段 说明 示例
仓库所有者 GitHub 用户名或组织名 microsoft
仓库名称 仓库名称 vscode
分支名称 要监控的分支（可选） main

手动检查更新

· 点击 "立即检查" 按钮手动触发仓库检查
· 系统会自动保存每个仓库的最后提交记录

查看系统状态

在 "系统信息" 面板中查看：

· 📊 监控仓库数量
· ⏰ 最后检查时间
· 🔔 通知状态
· ✅ 上次定时任务执行情况

🔌 API 参考

端点 方法 描述 认证要求
/ GET 管理面板 是
/login GET 登录页面 否
/login POST 登录处理 否
/logout GET 退出登录 是
/check-updates GET 手动检查更新 是
/health GET 健康检查 否

⚠️ 配置说明

GitHub API 限制

配置 限制 建议
无 Token 60 请求/小时 个人使用
有 Token 5000 请求/小时 多仓库监控

💡 优化提示: 系统会自动在请求间添加延迟以避免触发限制

🔒 安全特性

· 🔐 管理员密码使用 SHA-256 加密存储
· ⏳ 会话 Cookie 24小时过期
· 🛡️ HTTPOnly Cookie 防止 XSS 攻击
· 🔒 CSRF 保护

📨 通知格式

Telegram 通知包含以下信息：

```
🔄 代码更新通知

📦 仓库: microsoft/vscode
🌿 分支: main
👤 作者: john-doe
💬 提交: 修复登录页面样式问题
⏰ 时间: 2024-01-15 14:30:25

🔗 查看提交: https://github.com/microsoft/vscode/commit/abc123...
```

🐛 故障排除

常见问题

问题 症状 解决方案
GitHub API 限制 429 错误码 配置 GitHub Token 或减少检查频率
Telegram 通知失败 消息未发送 检查 Bot Token 和 Chat ID 配置
仓库检查失败 404 错误 确认仓库存在且分支名称正确
登录问题 会话过期 清除浏览器缓存或重新登录

📋 日志查看

在 Cloudflare Dashboard 的 Worker 日志中查看详细执行日志：

1. 进入 Worker 详情页
2. 点击 "Logs" 标签页
3. 查看实时日志或历史记录

🛠️ 开发说明

技术架构

```
GitHub Monitor
├── 📁 前端界面 (HTML/CSS/JS)
├── 🔧 业务逻辑 (JavaScript)
├── 💾 数据存储 (Cloudflare KV)
├── ⏰ 定时任务 (Cron Triggers)
└── 📱 通知服务 (Telegram Bot API)
```

核心特性

· 🏗️ 使用原生 Cloudflare Workers API
· 💽 KV 存储持久化数据
· 🧩 模块化代码结构
· 📱 响应式管理界面
· 🔄 错误处理和重试机制

📄 许可证

本项目采用 MIT License - 详见 LICENSE 文件。

💬 支持与帮助

如遇问题，请按以下步骤排查：

1. 🔍 检查日志: 查看 Cloudflare Worker 日志
2. 🌐 API 状态: 确认 GitHub API 和 Telegram API 状态
3. ⚙️ 配置验证: 重新检查 Bot Token 和 Chat ID
4. 🔗 网络连接: 确认网络连接正常

---

<div align="center">

如果这个项目对你有帮助，请给个 ⭐️ Star 支持一下！

</div>