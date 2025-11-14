GitHub Monitor - 代码仓库监控系统

一个基于 Cloudflare Workers 的 GitHub 代码仓库监控系统，能够实时监控指定仓库的代码更新，并通过 Telegram 发送通知。

功能特性

· 🔔 实时监控 - 自动检测 GitHub 仓库的代码提交
· 📱 Telegram 通知 - 通过 Telegram Bot 发送更新通知
· ⚡ 高性能 - 基于 Cloudflare Workers 边缘计算
· 🔒 安全认证 - 管理员密码保护
· 📊 多仓库支持 - 同时监控多个 GitHub 仓库和分支
· ⏰ 定时检查 - 支持 Cron 定时任务自动检查
· 🛡️ API 优化 - 支持 GitHub Token 提高 API 限制

部署步骤

1. 创建 Cloudflare Worker

1. 登录 Cloudflare Dashboard
2. 进入 Workers & Pages 页面
3. 点击 "Create application"
4. 选择 "Create Worker"
5. 给 Worker 命名并点击 "Deploy"

2. 配置 KV 命名空间

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

1. 在 Worker 的 "Settings" 标签页
2. 点击 "Triggers" 部分
3. 在 "Cron Triggers" 点击 "Add trigger"
4. 设置定时任务表达式，例如：
   · */30 * * * * - 每30分钟检查一次
   · 0 * * * * - 每小时检查一次
   · 0 */6 * * * - 每6小时检查一次

5. 上传代码

将提供的 worker.js 代码复制粘贴到 Worker 编辑器中，然后点击 "Save and Deploy"。

初始配置

1. 访问管理面板

部署完成后，访问你的 Worker URL（格式：`https://your-worker-name.your-subdomain.workers.dev/`）

2. 登录系统

· 默认密码: admin123
· 首次登录后建议立即修改密码

3. 配置 GitHub Token（推荐）

1. 访问 GitHub Settings → Developer settings → Personal access tokens
2. 点击 "Generate new token"
3. 输入 token 名称（例如：GitHub Monitor）
4. 无需选择任何权限（空权限即可）
5. 生成 token 并复制
6. 在系统设置的 "GitHub API 配置" 中粘贴 token

4. 配置 Telegram 通知

1. 在 Telegram 中搜索 @BotFather
2. 发送 /newbot 创建新机器人
3. 设置机器人名称和用户名
4. 获取 Bot Token
5. 向你的机器人发送任意消息
6. 访问 https://api.telegram.org/bot<YourBOTToken>/getUpdates 获取 Chat ID
7. 在系统设置的 "Telegram 通知配置" 中填写 Token 和 Chat ID

使用方法

添加监控仓库

1. 在 "添加监控仓库" 表单中填写：
   · 仓库所有者: GitHub 用户名或组织名
   · 仓库名称: 仓库名称
   · 分支名称: 要监控的分支（可选，默认为 main）
2. 点击 "添加仓库"

手动检查更新

· 点击 "立即检查" 按钮手动触发仓库检查
· 系统会自动保存每个仓库的最后提交记录

查看系统状态

· 在 "系统信息" 卡片中查看：
  · 监控仓库数量
  · 最后检查时间
  · 通知状态
  · 上次定时任务执行情况

API 端点

· GET / - 管理面板
· GET /login - 登录页面
· POST /login - 登录处理
· GET /logout - 退出登录
· GET /check-updates - 手动检查更新（API）
· GET /health - 健康检查

配置说明

GitHub API 限制

· 无 Token: 60 请求/小时
· 有 Token: 5000 请求/小时
· 系统会自动在请求间添加延迟以避免触发限制

安全特性

· 管理员密码使用 SHA-256 加密存储
· 会话 Cookie 24小时过期
· HTTPOnly Cookie 防止 XSS 攻击

通知格式

Telegram 通知包含：

· 仓库名称和链接
· 分支信息
· 最新提交信息（作者、消息、时间）
· 相关链接

故障排除

常见问题

1. GitHub API 限制
   · 配置 GitHub Token 提高限制
   · 减少检查频率
2. Telegram 通知发送失败
   · 检查 Bot Token 和 Chat ID 是否正确
   · 确认机器人已启动并向其发送过消息
3. 仓库检查失败
   · 确认仓库存在且可访问
   · 检查分支名称是否正确
   · 查看系统日志获取详细错误信息

日志查看

在 Cloudflare Dashboard 的 Worker 日志中查看详细执行日志。

开发说明

系统使用原生 Cloudflare Workers API，主要特性：

· 使用 KV 存储持久化数据
· 模块化代码结构
· 响应式管理界面
· 错误处理和重试机制

许可证

MIT License

支持

如遇问题，请检查：

1. Cloudflare Worker 日志
2. GitHub API 状态
3. Telegram Bot 配置
4. 网络连接状态