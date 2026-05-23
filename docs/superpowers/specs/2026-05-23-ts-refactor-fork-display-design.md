# GitHub Monitor — TypeScript 重构 + Fork 展示

- **日期**：2026-05-23
- **分支**：`feat/ui-refactor-fork-display`
- **作者**：laityts（驱动）+ Claude（执笔）
- **状态**：设计已批准，待 writing-plans

## 1. 目标

1. 将单文件 `worker.js`（约 2308 行）完整重构为 TypeScript，按职责拆分模块。
2. 现代化 UI（浅色 + 深色可切换，极简风格），保留所有现有功能。
3. **新功能**：在每条监控记录上展示「我的 fork」状态（链接、落后/领先、最新 commit、同步上游按钮、Fork 此仓库按钮）。
4. 强化认证（PBKDF2、签名 session、强制首次改密、登录失败限流、「记住我」）。
5. 重新设计 KV 键命名 + 启动时自动迁移（一次性、幂等）。

## 2. 关键决策汇总

| 主题 | 决策 |
|------|------|
| Fork 关系 | 上游 → 我的 fork（自动检测） |
| 用户名来源 | GitHub Token 自动获取（`/user`），缓存在 `settings:github.username` |
| Fork 检测策略 | 同名校验 → 全量扫描兜底，结果带 1 小时缓存 |
| Fork 展示功能 | 链接 / 落后领先 / 最新 commit / 同步上游 / Fork 按钮 |
| 架构 | 单 Worker + Hono + JSX SSR + 模块化 TS |
| 视觉风格 | 极简浅色 + 深色可切换，跟随系统偏好 + cookie 记忆 |
| KV 存储 | 重新设计键名 + 启动时**一次性**自动迁移 |
| 认证 | PBKDF2 + HMAC 签名 session + 强制首次改密 + 失败 5 次锁定 10 分钟 + 「记住我」 |
| 测试 | Vitest（纯 Node 环境）。本地 Android 内核 `mmap_rnd_bits=24` 阻止 workerd 启动，故放弃 vitest-pool-workers 集成测试，仅保留单元测试。 |
| 发布 | 直接覆盖现有 Worker；rollback 通过 `wrangler rollback` 或 git revert |
| 交付节奏 | 单 PR + 阶段原子提交 |

## 3. 项目结构

```
github-monitor/
├── src/
│   ├── index.ts                 # Hono app 入口、fetch/scheduled 导出
│   ├── env.ts                   # Env 类型、绑定声明
│   ├── lib/
│   │   ├── crypto.ts            # PBKDF2 / HMAC / 随机 token
│   │   ├── time.ts              # 时区/格式化
│   │   └── result.ts            # Result<T,E> 工具
│   ├── storage/
│   │   ├── keys.ts              # 新键名常量
│   │   ├── migration.ts         # 旧键 → 新键迁移
│   │   ├── settings.ts
│   │   ├── repos.ts
│   │   ├── sessions.ts
│   │   └── cron-log.ts
│   ├── auth/
│   │   ├── password.ts          # PBKDF2 hash/verify
│   │   ├── session.ts           # 签名 session
│   │   ├── middleware.ts
│   │   └── rate-limit.ts
│   ├── services/
│   │   ├── github.ts            # GitHubClient
│   │   ├── fork-detector.ts
│   │   ├── telegram.ts          # 包含 buildMessage 纯函数
│   │   ├── checker.ts           # 主循环
│   │   └── cron.ts              # 定时任务编排
│   ├── routes/
│   │   ├── auth.ts
│   │   ├── dashboard.ts
│   │   ├── repos.ts
│   │   ├── settings.ts
│   │   ├── fork.ts
│   │   └── system.ts            # /check-updates /health
│   └── views/
│       ├── layout.tsx
│       ├── theme.ts             # 浅色/深色 CSS 变量
│       ├── login.tsx
│       ├── dashboard.tsx
│       └── components/
│           ├── repo-card.tsx
│           ├── settings-panel.tsx
│           ├── status-banner.tsx
│           └── change-password-form.tsx
├── test/
│   └── unit/
│       ├── crypto.test.ts
│       ├── session.test.ts
│       ├── rate-limit.test.ts
│       ├── fork-detector.test.ts
│       ├── message-builder.test.ts
│       └── migration-unit.test.ts
├── wrangler.toml
├── tsconfig.json
├── vitest.config.ts
├── package.json
└── README.md
```

### 入口骨架

```ts
// src/index.ts
import { Hono } from 'hono'
import type { Env } from './env'
import { runMigrations } from './storage/migration'
import { authMiddleware } from './auth/middleware'
import { runCron } from './services/cron'
import * as r from './routes'

const app = new Hono<{ Bindings: Env }>()

app.use('*', async (c, next) => {
  await runMigrations(c.env)
  return next()
})

app.route('/login', r.auth.login)
app.route('/logout', r.auth.logout)
app.use('/*', authMiddleware)
app.route('/', r.dashboard)
app.route('/repos', r.repos)
app.route('/settings', r.settings)
app.route('/fork', r.fork)
app.route('/', r.system)

export default {
  fetch: app.fetch,
  scheduled: (event: ScheduledEvent, env: Env, ctx: ExecutionContext) =>
    ctx.waitUntil((async () => {
      await runMigrations(env)   // 兜底：首次 cron 早于任何 HTTP 请求时也能迁移
      await runCron(env)
    })()),
}
```

## 4. KV 存储设计

### 新键

| 新键 | 旧键 | 类型 | 说明 |
|------|------|------|------|
| `auth:password-hash` | `admin_password_hash` | `string` | `$pbkdf2$iter=100000$salt$hash` |
| `auth:must-change-password` | （新）| `'1' \| null` | 默认密码标志 |
| `auth:session:<token>` | （新）| JSON `{createdAt,expiresAt,rememberMe}` | KV TTL = cookie maxAge |
| `auth:login-attempts:<ip>` | （新）| JSON `{count,lockedUntil}` | TTL 10 分钟 |
| `auth:hmac-secret` | （新）| `string` | 256-bit base64 |
| `settings:telegram` | `telegram_bot_token` + `telegram_chat_id` | JSON `{botToken,chatId}` | 合并 |
| `settings:github` | `github_token` | JSON `{token,username,usernameFetchedAt}` | 含缓存用户名 |
| `settings:notifications` | `cron_notification_enabled` | JSON `{cronEnabled}` | 预留扩展 |
| `repos:list` | `monitored_repositories` | JSON `Array<RepoEntry>` | |
| `repos:state:<owner>:<repo>:<branch>` | `last_commit_<owner>:<repo>:<branch>` | JSON `{lastSha,lastCheckedAt}` | 对象化 |
| `system:last-check-time` | `last_check_time` | `string` | ISO |
| `system:last-cron-log` | `last_cron_log` | JSON | 同现状 |
| `fork:cache:<o>:<r>` | （新）| JSON `{forkFullName\|null,parentVerified,fetchedAt}` | TTL 1 小时 |
| `fork:user-forks-list` | （新）| JSON `Array<{full_name,parent,default_branch,updated_at}>` | TTL 1 小时 |
| `migration:version` | （新）| `string` | 已执行的迁移版本 |

### RepoEntry 类型

```ts
type RepoEntry = {
  owner: string
  repo: string
  branch: string
  addedAt: string  // ISO
}
```

Fork 信息不存在 RepoEntry 内，通过 `fork:cache:*` 即时查询/缓存。

### 一次性迁移

```ts
const MIGRATION_VERSION = '1'

export async function runMigrations(env: Env) {
  const current = await env.STORAGE.get('migration:version')
  if (current === MIGRATION_VERSION) return

  await migrateAuth(env)            // admin_password_hash → auth:password-hash
                                    //   + 写入 auth:must-change-password 如果哈希匹配 admin123
  await migrateSettings(env)         // telegram_* → settings:telegram, github_token → settings:github
  await migrateNotificationToggle(env) // cron_notification_enabled → settings:notifications
  await migrateRepoList(env)         // monitored_repositories → repos:list（addedAt 用 now）
  await migrateLastCommits(env)      // last_commit_* → repos:state:*（list 出所有键）
  await migrateCronArtifacts(env)    // last_check_time, last_cron_log → system:*
  await ensureHmacSecret(env)        // 不存在则生成

  // 一次性：删除所有已迁移的旧键
  await deleteLegacyKeys(env)

  await env.STORAGE.put('migration:version', MIGRATION_VERSION)
}
```

**性质**：
- **幂等**：每个 `migrate*` 函数都用「读新键，如果已存在则跳过；否则读旧键，写入新键」的模式。即使 `migration:version` 未写入（任何步骤中途失败），下次运行重做所有 `migrate*` 不会破坏已迁移的数据。
- **不丢数据**：每个 `migrate*` 内部「先 put 新键 → 再 delete 旧键」。put 成功 / delete 失败的情况下，下次运行从新键读到值会跳过 put，再次尝试 delete（幂等）。
- **可观察**：`console.log` 打印每步进度，wrangler tail 可见。
- **触发点**：
  - `fetch` 中间件每次请求触发（成本：1 次 KV get）
  - `scheduled` 入口同样触发，兜底新部署后首次 cron 早于 HTTP 请求的场景

## 5. 认证

### 密码哈希（`auth/password.ts`）

PBKDF2-SHA256，100k 迭代，16 字节随机 salt。格式：

```
$pbkdf2$iter=100000$<base64-salt>$<base64-hash>
```

`verifyPassword` 使用常量时间比较。

### Session（`auth/session.ts`）

- 登录成功 → 32 字节随机 token（base64url）
- 写 KV `auth:session:<token>`，TTL：
  - 「记住我」勾选：7 天（604800 秒）
  - 未勾选：1 天（86400 秒，安全上限）
- 计算 `hmac = HMAC-SHA256(hmacSecret, token)`，cookie = `<token>.<hmac>`
- Cookie 属性：`HttpOnly; Secure; SameSite=Strict; Path=/`
  - 勾选「记住我」：`Max-Age=604800`
  - 未勾选：不设 `Max-Age`（浏览器关闭即删）
- 校验：解析 → HMAC 验证 → KV 查询 → expiresAt 检查

### 登录失败限流（`auth/rate-limit.ts`）

- 按 `CF-Connecting-IP` 计数
- 5 次连续失败 → 锁定 10 分钟
- 成功登录后清零
- 锁定期内即使密码正确也拒绝

### 强制首次改密

- 迁移时如检测旧哈希等于 `admin123` 的 SHA-256 → 写 `auth:must-change-password = '1'`
- 新部署 `initAdminPassword` 同样设置
- 中间件：登录后该标志为 `1` → 所有路由（除 `/settings/password`、`/logout`）302 → `/settings/password?forced=1`
- 改密成功后删除该标志

### 登录流程

```
POST /login (password, remember_me?)
  ├─► rate-limit check (IP)         ─失败──► 429 + 锁定提示
  ├─► verifyPassword                ─失败──► 计数+1，返回 401（含剩余次数）
  ├─► createSession(rememberMe) → KV put
  ├─► Set-Cookie (signed)
  └─► 302 → /
         └─► authMiddleware
               ├─► must-change-password? ──是──► 302 /settings/password?forced=1
               └─► 渲染 dashboard
```

### CSRF & 其他

- 所有改状态的路由都用 POST + Referer/Origin 同源检查（Hono 中间件）
- 表单 password 字段用 `autocomplete="new-password"`
- session token 不出现在 URL 或日志中

## 6. GitHub 客户端 & Fork 检测

### `GitHubClient`（`services/github.ts`）

```ts
export class GitHubClient {
  constructor(private token?: string) {}
  
  // 现有
  getLatestCommit(owner, repo, branch)
  getCommitsBetween(owner, repo, branch, sinceSha)
  
  // 新增
  getAuthenticatedUser()                            // GET /user
  getRepo(owner, repo)                              // GET /repos/{o}/{r}
  listUserRepos(username, { type: 'forks' })        // GET /users/{u}/repos?type=forks (分页)
  compareCommits(owner, repo, base, head)           // GET /repos/{o}/{r}/compare/{base}...{head}
  syncFork(owner, repo, branch)                     // POST /repos/{o}/{r}/merge-upstream
  createFork(owner, repo)                           // POST /repos/{o}/{r}/forks
}
```

错误包装为 `GitHubError`，含 `status`、`message`、`isRateLimit`、`needsAuth`。

### `resolveUsername(env, gh)`

- 读 `settings:github.username` + `usernameFetchedAt`
- 超过 24 小时或不存在 → 调 `/user` 刷新 → 写回 KV

### Fork 检测策略（`services/fork-detector.ts`）

```ts
export type ForkInfo =
  | { exists: true
      fullName: string
      defaultBranch: string
      latestCommitSha: string
      latestCommitAt: string
      ahead: number
      behind: number
      canSync: boolean }
  | { exists: false }
  | { error: string }
```

**流程**：

```
detectFork(env, gh, me, upstreamOwner, upstreamRepo, upstreamBranch)
  1. 读 fork:cache:<upstreamOwner>:<upstreamRepo>
     ├─ 新鲜 (<1h) → 使用缓存的 forkFullName
     └─ 否则继续
  
  2. 阶段 1（同名猜测）：
     GET /repos/{me}/{upstreamRepo}
     ├─ 200 + parent.full_name === "{upstreamOwner}/{upstreamRepo}" → ✅
     └─ 404 / parent 不匹配 → 阶段 2
  
  3. 阶段 2（全量扫描兜底）：
     读 fork:user-forks-list（TTL 1h）
     ├─ 未缓存 → GET /users/{me}/repos?type=forks（分页所有页）→ 存 KV
     └─ 在列表中找 parent.full_name 匹配 → 找到 / 不存在
  
  4. 写回 fork:cache
  
  5. 若找到 fork，补全展示数据：
     - GET /repos/{me}/{forkRepo}/branches/{upstreamBranch}
     - GET /repos/{upstreamOwner}/{upstreamRepo}/compare/{upstreamBranch}...{me}:{upstreamBranch}
     - canSync = behind > 0 && token 存在
```

**失败降级**：任何步骤失败 → 返回 `{ error }` → UI 显示「检测失败：<原因>」+ 重试按钮。

## 7. UI 设计

### 主题系统（`views/theme.ts`）

```css
:root[data-theme="light"] {
  --bg: #ffffff; --bg-soft: #f8fafc; --surface: #ffffff;
  --border: #e2e8f0; --text: #0f172a; --text-muted: #64748b;
  --primary: #0f172a; --accent: #2563eb;
  --success: #16a34a; --danger: #dc2626; --warning: #d97706;
}
:root[data-theme="dark"] {
  --bg: #0b1220; --bg-soft: #111827; --surface: #1e293b;
  --border: #334155; --text: #f1f5f9; --text-muted: #94a3b8;
  --primary: #f1f5f9; --accent: #38bdf8;
  --success: #4ade80; --danger: #f87171; --warning: #fbbf24;
}
```

**加载顺序**：内联 `<script>` 在 `<head>` 顶端运行 → 读 cookie `theme` → 无 cookie 则 `prefers-color-scheme` → 设 `data-theme`，避免 FOUC。

### 全局结构

```
┌─────────────────────────────────────────────────────────┐
│ 顶部条：📦 GitHub Monitor    👤 @laityts  🌓 主题  ⎋ 登出 │
├─────────────────────────────────────────────────────────┤
│ 状态横幅（success / error / info）                       │
├─────────────────────────────────────────────────────────┤
│ 主内容区                                                 │
├─────────────────────────────────────────────────────────┤
│ 页脚：上次检查 · Cron 状态 · 版本                        │
└─────────────────────────────────────────────────────────┘
```

### Dashboard 区块

1. 顶部统计卡片：监控仓库数 / 上次检查 / Cron 通知开关 / GitHub 用户
2. 添加仓库表单（合并的 `owner/repo` 输入 + 分支）
3. 仓库卡片列表（重点）
4. 设置抽屉/折叠区：Telegram / GitHub Token / 通知开关 / 修改密码 / 清空仓库
5. 底部操作：手动检查 / 测试 Telegram / 测试 GitHub

### 仓库卡片（`views/components/repo-card.tsx`）

三种状态：

**状态 1（有 fork）**：

```
┌─────────────────────────────────────────────────────────────┐
│ vercel/next.js  ﹝main﹞                       [删除] [⋯]    │
│ 上次提交 9b8d2c · 2 小时前 · Vercel Bot                      │
├ 🍴 我的 Fork ──────────────────────────────────────────────┤
│ ✓ laityts/next.js                                          │
│   落后 12 · 领先 0                          [同步上游] [↗]  │
│   最新：a3f0e1 · 3 天前                                     │
└─────────────────────────────────────────────────────────────┘
```

**状态 2（无 fork）**：

```
├ 🍴 我的 Fork ──────────────────────────────────────────────┤
│   你还没有 fork 这个仓库                  [Fork 此仓库 →]   │
```

**状态 3（检测失败）**：

```
├ 🍴 我的 Fork ──────────────────────────────────────────────┤
│ ⚠ 检测失败：GitHub API 限流                    [重试]      │
```

### 交互

- `[同步上游]`：POST `/fork/sync`（form + CSRF），成功后整页刷新
- `[Fork 此仓库 →]`：POST `/fork/create`，2 秒等待 + 重新检测
- `[重试]`：POST `/fork/refresh`，强制重新拉取
- `[🌓 主题]`：JS 切换 `data-theme` + 写 cookie
- `[删除]`：confirm() 后 POST `/repos/delete`

## 8. Telegram & Cron

### TelegramClient（`services/telegram.ts`）

```ts
export class TelegramClient {
  constructor(private botToken: string, private chatId: string) {}
  send(text: string, opts?: { parse_mode?: 'HTML' }): Promise<void>
}
```

错误抛 `TelegramError`（含 `description`），由上层决定记录/降级。

### 消息构建（同文件下的纯函数，便于单测）

- `buildCommitNotification(repo, commits, isCompleteHistory, forkInfo?)` —— 等价当前实现 + 可选 fork 段（fork 落后则附「💡 你的 fork 落后 N commit」）
- `buildCronLogMessage(log)` —— 等价
- `buildErrorMessage(repo, error)` —— 等价

### Cron 编排（`services/cron.ts`）

```ts
export async function runCron(env: Env): Promise<CronLog> {
  const start = Date.now()
  let result, error
  try { result = await runCheck(env) }
  catch (e) { error = e; result = { success: false, error: e.message } }
  const log: CronLog = { /* timestamps, duration, success, result, error */ }
  await saveCronLog(env, log)
  await maybeSendCronLog(env, log)
  return log
}
```

### checkAllRepos（`services/checker.ts`）

行为等价当前 worker.js，但：
- 重写为 TS，使用 `GitHubClient` 和 `TelegramClient`
- API 限流降级保持（有 token 500ms 间隔，无 token 2000ms）
- **新增**：检查完毕后 `ctx.waitUntil` 异步刷新所有仓库的 fork 缓存
- 单条仓库 Telegram 失败不阻塞其他

### Cron 通知开关行为

保持现状不变。明确现状：
- `cronEnabled = true`（默认）：每次 cron 执行都发一条「定时任务报告」到 Telegram。
- `cronEnabled = false`：跳过定时任务报告。**仓库更新通知（commit 推送）与错误通知不受此开关影响，始终发送**（前提是 Telegram 已配置）。

## 9. 测试

### Vitest 配置（`vitest.config.ts`）

```ts
import { defineConfig } from 'vitest/config'
export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
  },
})
```

> 本地开发环境（Android 内核 `mmap_rnd_bits=24`）下 `workerd` 二进制无法启动 tcmalloc，
> 因此放弃 `@cloudflare/vitest-pool-workers` 与配套集成测试，仅保留纯 Node 单元测试。
> 端到端覆盖通过 Phase 11 中手工浏览器验收完成。

### 单元测试

| 模块 | 关键测试 |
|------|----------|
| `lib/crypto.ts` | `hashPassword` + `verifyPassword` 配对、错误密码拒绝、constant-time 比较 |
| `auth/session.ts` | 生成 token、HMAC 校验、过期 session、伪造 cookie 拒绝、记住我 vs 短期 |
| `auth/rate-limit.ts` | 5 次失败锁定、10 分钟解锁、成功清零 |
| `services/telegram.ts` (build*) | commit 列表、>10 截断、HTML escape、fork-behind 提示 |
| `services/fork-detector.ts` | 同名命中、404 兜底全量、parent 不匹配跳兜底、缓存读写、缓存过期重取、ahead/behind 计算 |
| `storage/migration.ts` | 旧→新键正确性、`migration:version` 幂等、合并字段（telegram 拆分键）、缺失旧键不报错（在 `migration-unit.test.ts` 中以手写 KV mock 进行） |

### 集成测试

不再编写。原计划中的 `auth-flow.test.ts` 与 `migration.test.ts` 因本地无法运行 `workerd` 而取消；
对应覆盖通过 Phase 11 浏览器手工验收完成。

### GitHub / Telegram mock

`vi.stubGlobal('fetch', ...)` 拦截。`services/github.ts` 不依赖全局状态，便于注入。

### TDD

每个新功能/bugfix 先写失败测试 → 实现 → 通过。

### Scripts（`package.json`）

```json
{
  "scripts": {
    "dev": "wrangler dev",
    "test": "vitest run",
    "test:watch": "vitest",
    "typecheck": "tsc --noEmit",
    "deploy": "wrangler deploy"
  }
}
```

## 10. 部署 & 运维

### 构建

- Wrangler 内置 esbuild，无需独立构建步骤
- `wrangler.toml` 改：`main = "src/index.ts"`
- `tsconfig.json`：`target: ES2022`、`jsx: react-jsx`、`jsxImportSource: hono/jsx`、`strict: true`、`noUncheckedIndexedAccess: true`、`exactOptionalPropertyTypes: true`、`types: ["@cloudflare/workers-types"]`

### 发布流程

```
1. 完成所有阶段提交
2. npm install
3. npm run typecheck && npm run test  → 必须全绿
4. wrangler deploy
5. 浏览器访问线上：
   a. 看 wrangler tail 确认 migration 执行
   b. 登录 → 应被强制改密
   c. 改密后检查仓库列表完整
   d. 至少 1 个 repo 的 fork 检测正常
   e. /check-updates → 200
   f. 等下次 cron 或手动触发
6. 若失败：wrangler rollback 或 git revert
```

### 回滚预案

迁移是**一次性**的：执行后旧键已被删除，单纯回滚旧 worker.js 将无法读取数据。

应急方案：
- **首选**：在前端发版前在 Cloudflare KV 后台手动备份当前所有键（CSV 导出）
- **次选**：发布后用 `wrangler rollback` 回到旧版 + 配合 KV 数据恢复脚本（如果备份了）

### README 更新

- 增加「本地开发」章节：`npm install` / `npm run dev` / `npm run test`
- Token 权限说明：未来 fork sync 与 fork create 需要 `repo` 或 `public_repo`
- 部署方式 A（网页粘贴）改为：通过 `wrangler deploy` 上传 dist 或 CI 构建产物上传

## 11. 实现节奏（阶段原子提交）

单 PR，按以下顺序提交：

1. **chore: 添加 TS 工具链与 Hono 脚手架**（`package.json`、`tsconfig.json`、`vitest.config.ts`、`src/index.ts` 空 Hono app、`wrangler.toml` 改 main）
2. **feat(storage): 重新设计 KV 键并实现迁移**（`storage/keys.ts`、`storage/migration.ts`，单元测试在 Phase 3 内，与 crypto 一起补）
3. **feat(lib): 加密原语**（`lib/crypto.ts`、`crypto.test.ts`）
4. **feat(auth): PBKDF2 密码 + 签名 session + 限流 + 强制改密**（`auth/*`、`session.test.ts`、`rate-limit.test.ts`）
5. **feat(services): GitHubClient 与 TelegramClient + 消息构建**（`services/github.ts`、`services/telegram.ts`、`message-builder.test.ts`）
6. **feat(services): checker + cron**（`services/checker.ts`、`services/cron.ts`）
7. **feat(views): 主题系统与基础 layout**（`views/theme.ts`、`views/layout.tsx`、`views/login.tsx`）
8. **feat(views): dashboard 与 repo-card（不含 fork 子块）**（`views/dashboard.tsx`、`views/components/*`）
9. **feat(routes): 接入所有路由**（`routes/*`）
10. **feat(fork): fork-detector + UI 子块 + sync/create/refresh 路由**（`services/fork-detector.ts`、`fork-detector.test.ts`、`routes/fork.ts`、`views/components/repo-card.tsx` 补 fork 段）
11. **docs: 更新 README**
12. **chore: 删除旧 worker.js**

每个提交都要求：`npm run typecheck && npm run test` 通过。

## 12. 风险 & 缓解

| 风险 | 缓解 |
|------|------|
| KV 迁移出错丢数据 | 每个 migrate* 函数先 put 再 delete；`migration-unit.test.ts` 用手写 KV mock 覆盖；发布前 Cloudflare 后台导出 KV 备份 |
| 用户已修改默认密码但本设计仍写入 `must-change-password` | 迁移时只在哈希 == SHA-256(`admin123`) 时设置标志 |
| Fork 全量扫描慢（fork 多） | 1 小时 KV 缓存；首次访问 dashboard 时异步刷新；超时降级到「检测中…」+ 重试 |
| Hono JSX 渲染性能 | 服务端 SSR 单次渲染开销极小（毫秒级），不构成瓶颈 |
| Token 权限不足（无 `repo`） | UI 在尝试 sync/fork 时显示明确错误，并提示去设置页升级 token |
| 强制改密导致用户被锁在外 | 流程内总是允许 `/settings/password` 与 `/logout`，不会形成死锁 |
| 重写遗漏现有功能 | 实现节奏第 1-9 阶段完成时，对照旧 worker.js 功能清单做一次 diff 检查 |

## 13. 验收清单

- [ ] 浏览器访问 `/` 渲染 dashboard，未登录时跳 `/login`
- [ ] 用默认密码 `admin123` 登录后被强制跳改密页（前提：线上当前仍使用默认密码）
- [ ] 改密后 cookie 仍有效，回到 dashboard
- [ ] 「记住我」勾选时 cookie 有 `Max-Age`，不勾选时无
- [ ] 5 次错密码后锁定，显示剩余时间
- [ ] 仓库列表完整迁移，原有监控正常工作
- [ ] 每条仓库卡片正确显示 fork 三种状态之一
- [ ] 点击「同步上游」成功调用 GitHub API
- [ ] 点击「Fork 此仓库」成功创建 fork
- [ ] 主题切换正常，cookie 持久
- [ ] `/check-updates` 与 cron 触发都正常运行
- [ ] Telegram 通知格式无回归
- [ ] 全部测试通过：`npm run test` 全绿
- [ ] `npm run typecheck` 无错误
