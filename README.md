GitHub Monitor

一个基于 Cloudflare Workers 的 GitHub 代码仓库监控系统，可实时监控多个 GitHub 仓库的提交更新，并通过 Telegram 发送通知。

✨ 功能特性

· 🔔 实时监控 - 自动检测 GitHub 仓库的新提交
· 🤖 Telegram 通知 - 通过 Telegram Bot 发送实时更新通知
· 🔐 安全认证 - 管理员密码保护的管理面板
· ⚡ 高性能 - 基于 Cloudflare Workers 边缘计算
· 🕒 定时检查 - 自动定时检查仓库更新
· 🎨 美观界面 - 现代化的响应式管理面板
· 🔧 多仓库支持 - 同时监控多个 GitHub 仓库和分支

🚀 快速开始

前置要求

· Cloudflare 账户
· Cloudflare Workers 权限
· KV 命名空间配置
· （可选）Telegram Bot Token 和 Chat ID
· （可选）GitHub Personal Access Token

部署步骤

1. 克隆或创建项目
   ```bash
   # 创建新的 Workers 项目
   npx wrangler generate github-monitor
   cd github-monitor
   ```
2. 配置 KV 命名空间
   ```bash
   # 创建 KV 命名空间
   npx wrangler kv:namespace create "STORAGE"
   npx wrangler kv:namespace create "STORAGE" --preview
   ```
3. 更新 wrangler.toml 配置
   ```toml
   name = "github-monitor"
   compatibility_date = "2024-01-01"
   
   [[kv_namespaces]]
   binding = "STORAGE"
   id = "你的KV命名空间ID"
   preview_id = "你的预览KV命名空间ID"
   
   [triggers]
   crons = ["*/30 * * * *"]  # 每30分钟执行一次检查
   ```
4. 部署到 Cloudflare
   ```bash
   npx wrangler deploy
   ```

🔧 配置说明

初始访问

1. 部署完成后访问你的 Workers 域名
2. 使用默认密码 admin123 登录
3. 建议立即在"安全设置"中修改密码

GitHub API 配置

推荐配置 GitHub Token 以提高 API 限制：

1. 访问 GitHub Settings → Developer settings → Personal access tokens
2. 生成新的 token（无需选择任何权限）
3. 在系统设置的 "GitHub API 配置" 中填入 token

Telegram 通知配置

1. 通过 @BotFather 创建 Telegram 机器人
2. 获取 Bot Token
3. 向你的机器人发送任意消息
4. 访问 https://api.telegram.org/bot<YourBOTToken>/getUpdates 获取 Chat ID
5. 在系统设置中配置 Token 和 Chat ID

📡 API 端点

主要端点

· GET / - 管理面板
· GET /login - 登录页面
· POST /login - 处理登录
· GET /logout - 退出登录
· GET /check-updates - 手动触发检查更新
· GET /health - 健康检查

健康检查

```bash
curl https://your-worker.workers.dev/health
```

响应示例：

```json
{
  "status": "ok",
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

🗂️ 数据存储

系统使用 Cloudflare KV 存储以下数据：

· 管理员密码 - SHA-256 加密存储
· 监控仓库列表 - JSON 格式存储仓库配置
· 上次提交记录 - 每个仓库分支的最后提交 SHA
· 系统设置 - Telegram 和 GitHub 配置

🔒 安全特性

· 密码加密 - 使用 SHA-256 哈希存储密码
· 会话管理 - 24小时会话过期
· HTTPOnly Cookies - 安全的会话存储
· 输入验证 - 所有输入都经过验证和清理

⚙️ 定时任务

系统配置了定时触发器，默认每30分钟自动检查一次仓库更新。你可以在 wrangler.toml 中修改 cron 表达式：

```toml
[triggers]
crons = ["*/30 * * * *"]  # 每30分钟
# crons = ["*/10 * * * *"]  # 每10分钟
# crons = ["0 * * * *"]     # 每小时
```

🎯 使用指南

添加监控仓库

1. 登录管理面板
2. 在"添加监控仓库"表单中填入：
   · 仓库所有者：GitHub 用户名或组织名
   · 仓库名称：仓库名称
   · 分支名称：（可选）默认为 main
3. 点击"添加仓库"

手动检查更新

· 点击"立即检查"按钮手动触发更新检查
· 系统会立即检查所有监控仓库并发送通知

测试配置

· 测试 Telegram：在系统设置中点击"测试通知"
· 测试 GitHub：配置 GitHub Token 后点击"测试GitHub"

🐛 故障排除

常见问题

1. GitHub API 限制
   · 原因：未认证请求频率限制
   · 解决：配置 GitHub Personal Access Token
2. Telegram 通知失败
   · 检查 Bot Token 和 Chat ID 是否正确
   · 确保已向机器人发送过消息
3. 仓库无法添加
   · 确认仓库存在且可公开访问
   · 检查分支名称是否正确

日志查看

在 Cloudflare Workers 仪表板中查看实时日志，监控系统运行状态。

📝 开发说明

项目结构

```
worker.js
├── 路由处理
│   ├── 仪表板 (/)
│   ├── 登录 (/login)
│   ├── 登出 (/logout)
│   └── API端点 (/check-updates, /health)
├── 认证系统
│   ├── 密码验证
│   ├── 会话管理
│   └── 权限检查
├── 仓库监控
│   ├── GitHub API 集成
│   ├── 提交比较
│   └── 变更检测
├── 通知系统
│   ├── Telegram Bot 集成
│   └── 消息格式化
└── 数据存储
    ├── KV 存储操作
    └── 配置管理
```

本地开发

```bash
# 安装依赖（如果需要）
npm install

# 本地开发
npx wrangler dev

# 部署到生产环境
npx wrangler deploy
```

📄 许可证

MIT License

🤝 贡献

欢迎提交 Issue 和 Pull Request！

📞 支持

如有问题，请通过以下方式联系：

· 创建 GitHub Issue
· 查看 Cloudflare Workers 文档

---

注意：首次部署后请立即修改默认密码 admin123 以确保系统安全。