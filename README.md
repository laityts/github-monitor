# GitHub Monitor – Cloudflare Workers 版

一个轻量、零依赖的 **GitHub 仓库更新监控系统**，部署在 **Cloudflare Workers** 上，实时检测代码提交并通过 **Telegram** 推送通知。

> **Dashboard + Cron 自动检查**，无需 `wrangler.toml`，仅需 **KV 存储** 与 **Cron 触发器**。

---

## 功能特性

| 功能 | 描述 |
|------|------|
| **实时监控** | 检测任意 GitHub 仓库（支持自定义分支）的最新提交 |
| **Telegram 通知** | 新提交立即推送，HTML 富文本，支持链接跳转 |
| **Web 管理面板** | 登录后可视化添加/删除仓库、修改密码、配置 Token |
| **定时任务 (Cron)** | 支持 Cloudflare Workers Cron，自动周期检查 |
| **API 频率优化** | 支持 GitHub Token，突破 60 次/小时限制 |
| **安全认证** | 管理员密码（SHA-256 哈希），24 小时 Cookie 登录 |
| **默认密码** | 首次部署：`admin123`（请立即修改） |
| **零外部依赖** | 纯原生 Worker API，无需 Node.js 模块 |

---

## 部署步骤

### 1. 创建 Cloudflare Worker

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com)
2. 进入 **Workers & Pages** → **Create application** → **Worker**
3. 填写名称（如 `github-monitor`），点击 **Deploy**

### 2. 绑定 KV 命名空间

1. 在 Worker 编辑页，点击 **Settings** → **Variables** → **KV Namespace Bindings**
2. 点击 **Add binding**
   - **Variable name**: `STORAGE`
   - **KV namespace**: 点击 **Create namespace**，命名如 `GITHUB_MONITOR_KV`
3. 保存

> 所有数据（密码、仓库列表、提交记录、配置）都存储在此 KV 中。

### 3. 粘贴完整代码

将下方完整代码 **全部复制**，粘贴到 Worker 编辑器中，覆盖默认内容：

### 4. 设置 Cron 触发器（定时任务）

1. 在 Worker 页面点击 **Settings** → **Triggers**
2. 点击 **Add Cron Trigger**
3. 添加以下表达式（示例：**每 10 分钟**检查一次）：

```cron
*/10 * * * *
```

> 可选频率：
> - `*/5 * * * *` → 每 5 分钟
> - `0 * * * *` → 每小时
> - `0 0 * * *` → 每天凌晨

4. 保存

> Cron 执行日志会自动发送到 Telegram（若已配置）

---

## 使用说明

### 首次访问

部署完成后，访问你的 Worker 域名：

```
https://github-monitor.your-worker.workers.dev
```

### 默认登录信息

| 项目 | 值 |
|------|----|
| **用户名** | 无（仅密码） |
| **默认密码** | `admin123` |

> **强烈建议登录后立即修改密码！**

---

## 管理面板功能

### 添加仓库

```
所有者：microsoft
仓库名：vscode
分支：main（可选）
```

### 手动检查更新

点击 **“立即检查”** 按钮

### 清空所有仓库

点击 **“清空全部”**，谨慎操作！

### 设置 Telegram 通知

1. 与 [@BotFather](https://t.me/BotFather) 创建 Bot → 获取 **Bot Token**
2. 向 Bot 发送任意消息
3. 访问以下链接获取 **Chat ID**：
   ```
   https://api.telegram.org/bot<你的TOKEN>/getUpdates
   ```
4. 填写 **Bot Token** 和 **Chat ID**
5. 点击 **“测试通知”** 验证

### 设置 GitHub Token（推荐）

1. GitHub → Settings → Developer settings → Personal access tokens → **Generate new token (classic)**
2. **无需勾选任何权限**
3. 复制 Token，粘贴到 **GitHub Token** 输入框
4. 点击 **“测试GitHub”**

> 提高 API 限制：**5000 次/小时**（未认证仅 60 次）

### 修改密码

在 **安全设置** 标签页修改管理员密码

---

## 定时任务报告（Cron）

每次 Cron 执行会：

1. 检查所有仓库
2. 发现更新 → 发送 Telegram 通知
3. 保存执行日志
4. **发送完整报告到 Telegram**（包含成功/失败、耗时、统计）

示例报告：

```
GitHub Monitor 定时任务报告

执行时间: 2025-04-05 14:30:00
执行时长: 1234ms
执行状态: 执行成功

检查结果:
   • 已检查仓库: 3
   • 发现更新: 1
   • 错误数量: 0
总结: 检查完成

系统状态: 正常运行
通知渠道: Telegram
```

---

## 安全说明

- 密码使用 **SHA-256** 哈希存储
- Cookie 使用 `HttpOnly` + `SameSite=Strict`
- 登录有效期 **24 小时**
- 所有输入均服务端验证
- 无 SQL、无文件系统

---

## 故障排查

| 问题 | 解决方案 |
|------|----------|
| **登录失败** | 检查密码是否为 `admin123`，或已修改后忘记 |
| **无通知** | 检查 Telegram 配置，点击“测试通知” |
| **API 403 限制** | 配置 GitHub Token |
| **Cron 不执行** | 检查 Triggers 是否保存，查看 Workers Logs |
| **仓库检测不到更新** | 确认分支名正确，检查 GitHub 是否有新提交 |

---

## 开源协议

**MIT License** - 可自由使用、修改、商用

---