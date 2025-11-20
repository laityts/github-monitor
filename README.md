<div align="center">

# 🚀 GitHub Monitor for Cloudflare Workers

![Cloudflare Workers](https://img.shields.io/badge/Cloudflare-Workers-F38020?style=for-the-badge&logo=cloudflare)
![GitHub API](https://img.shields.io/badge/GitHub-API-181717?style=for-the-badge&logo=github)
![Telegram Bot](https://img.shields.io/badge/Telegram-Bot-26A5E4?style=for-the-badge&logo=telegram)

**一个运行在 Cloudflare Workers 上的无服务器 GitHub 仓库监控系统**  
无需服务器，零成本运行，通过 Telegram 实时接收代码更新通知

[功能特性](#-功能特性) • [快速部署](#-快速部署) • [配置指南](#-配置指南) • [API 文档](#-api-接口)

</div>

## 📋 目录
- [✨ 功能特性](#-功能特性)
- [🚀 快速部署](#-快速部署)
- [⚙️ 配置指南](#-配置指南)
- [📡 API 接口](#-api-接口)
- [❓ 常见问题](#-常见问题)
- [📄 许可证](#-许可证)

## ✨ 功能特性

### 🔍 监控能力
- **👀 多维监控** - 支持无限数量 GitHub 仓库，可指定监控特定分支
- **📊 智能检测** - 自动识别新提交并过滤无关变更

### 🖥️ 可视化界面
- **🎨 内置仪表盘** - 无需额外部署，直接访问 Worker 域名即可管理
- **📱 响应式设计** - 完美适配桌面端和移动端
- **📈 状态概览** - 实时显示检查时间、API 状态和运行日志

### 🔔 通知系统
- **💬 Telegram 推送** - 实时发送提交详情（Commit Hash、作者、留言、链接）
- **⏰ 定时报告** - 可选开启 Cron 定时任务执行汇总报告

### 🛡️ 安全可靠
- **🔐 身份验证** - 基于会话管理和 SHA-256 密码加密
- **💾 数据持久化** - 使用 Cloudflare KV 进行稳定数据存储

### ⚡ 性能优化
- **🔑 GitHub Token 支持** - 显著提升 API 调用频率限制
- **🌐 边缘计算** - 利用 Cloudflare 全球网络实现快速响应

## 🚀 快速部署

### 方式 A：网页控制台部署（推荐新手）

<details>
<summary><b>📝 点击展开详细部署步骤</b></summary>

#### 1. 创建 Worker
1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com)
2. 进入 **Workers & Pages** → **Create Application** → **Create Worker**
3. 命名为 `github-monitor`，点击 **Deploy**

#### 2. 导入代码
1. 点击 **Edit code**
2. 将 `worker.js` 的内容完全复制并覆盖编辑器中的现有代码
3. 点击右上角的 **Save and deploy**

#### 3. 创建并绑定 KV（关键步骤！）
1. 回到 Worker 的配置页面，点击左侧菜单的 **KV**
2. 点击 **Create a Namespace**，命名为 `GITHUB_MONITOR_KV`，点击 **Add**
3. 进入 Worker 的 **Settings** → **Variables**
4. 向下滚动到 **KV Namespace Bindings**，点击 **Add binding**
   - **Variable name**: `STORAGE`（必须完全一致，注意大写）
   - **KV Namespace**: 选择刚才创建的 `GITHUB_MONITOR_KV`
5. 点击 **Save and deploy**

#### 4. 设置定时任务
1. 进入 **Triggers** 选项卡
2. 在 **Cron Triggers** 部分点击 **Add Cron Trigger**
3. 设置频率（例如每 30 分钟：`*/30 * * * *`）
4. 点击 **Add Trigger**

</details>

### 方式 B：Wrangler CLI 部署（开发者推荐）

<details>
<summary><b>🛠️ 点击展开命令行部署指南</b></summary>

#### 1. 环境准备
```bash
# 安装 Wrangler CLI
npm install -g wrangler

# 登录 Cloudflare
wrangler login
```

2. 项目配置

```bash
# 创建并配置 wrangler.toml
cat > wrangler.toml << EOF
name = "github-monitor"
main = "src/index.js"
compatibility_date = "2023-01-01"

[[kv_namespaces]]
binding = "STORAGE"
id = "your-kv-namespace-id-here"

[triggers]
crons = ["*/30 * * * *"]
EOF
```

3. 创建 KV 命名空间

```bash
# 创建 KV 命名空间并获取 ID
npx wrangler kv:namespace create "GITHUB_MONITOR_KV"

# 将返回的 ID 替换到 wrangler.toml 中
```

4. 部署应用

```bash
# 部署到 Cloudflare Workers
npx wrangler deploy
```

</details>

⚙️ 配置指南

1. 首次登录与初始化

部署成功后，访问您的 Worker 域名：

```
https://github-monitor.your-name.workers.dev
```

· 🔐 默认密码: admin123
· ⚠️ 安全提示: 首次登录后，请立即在 系统设置 → 安全设置 中修改密码

2. 必要配置参数

在仪表盘的 系统设置 中填入以下信息：

| 参数 | 说明 | 获取方式 |
|------|------|----------|
| `Telegram Bot Token` | 机器人密钥 | 在 Telegram 联系 [@BotFather](https://t.me/BotFather) 发送 `/newbot` 创建 |
| `Telegram Chat ID` | 接收消息的 ID | 向您的机器人发送任意消息，然后访问 `https://api.telegram.org/bot<TOKEN>/getUpdates` 查看 |
| `GitHub Token` | (可选但推荐) API 令牌 | 在 [GitHub Developer Settings](https://github.com/settings/tokens) 生成 Classic Token |

<details>
<summary><b>ℹ️ 为什么需要 GitHub Token？</b></summary>

· 未认证请求: 每小时 60 次 API 调用限制
· 使用 Token 后: 每小时 5000 次 API 调用限制
· 适用场景: 频繁监控或大量仓库时必需

</details>

## 📡 API 接口
除了 Web 界面，系统还提供以下 REST API 端点：

| 端点 | 方法 | 描述 | 响应示例 |
|------|------|------|----------|
| `/` | `GET` | 返回 Web 管理面板 | `HTML 页面` |
| `/check-updates` | `GET` | 手动触发更新检查 | `{"success":true, "message":"检查完成", "checkedCount":5}` |
| `/health` | `GET` | 健康检查接口 | `{"status":"ok", "timestamp":"..."}` |

❓ 常见问题

<details>
<summary><b>Q: 登录后显示 "Internal Server Error"？</b></summary>

A: 99% 的情况是因为没有正确绑定 KV Storage：

· 检查 Settings → Variables 中是否绑定了 KV
· 确认变量名必须是 STORAGE（全大写）
· 重新部署 Worker 应用

</details>

<details>
<summary><b>Q: 定时任务没有发送通知？</b></summary>

A: 请按以下步骤排查：

1. ✅ Cloudflare 后台是否添加了 Cron Trigger
2. ✅ Telegram Bot Token 和 Chat ID 是否正确配置
3. ✅ 是否开启了"定时任务通知"开关
4. ✅ 检查 Worker 日志是否有错误信息

</details>

<details>
<summary><b>Q: 如何重置管理员密码？</b></summary>

A: 如果忘记密码，可以通过以下方式重置：

1. 进入 Cloudflare 后台的 KV 界面
2. 找到 GITHUB_MONITOR_KV 命名空间
3. 删除键名为 admin_password_hash 的条目
4. 重新访问网页，密码将重置为 admin123

</details>

📄 许可证

本项目基于 MIT 许可证 开源。

---

<div align="center">

如果这个项目对您有帮助，请给个 ⭐️ 星标支持！

由 Cloudflare Workers 提供支持 🌐

</div>