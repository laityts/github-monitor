# GitHub Monitor — TypeScript 重构 + Fork 展示 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 将单文件 `worker.js` 重构为模块化 TypeScript（Hono + JSX SSR），保留所有原功能，并新增「我的 Fork」展示与同步功能。

**Architecture:** 单 Cloudflare Worker 部署，Hono 作为路由 + 中间件 + JSX 渲染框架。代码按 `lib/storage/auth/services/routes/views` 分层。KV 数据通过启动时一次性自动迁移到新键名空间。

**Tech Stack:** TypeScript · Hono · `@cloudflare/workers-types` · Vitest + `@cloudflare/vitest-pool-workers` · Wrangler（内置 esbuild）

**Spec:** [`docs/superpowers/specs/2026-05-23-ts-refactor-fork-display-design.md`](../specs/2026-05-23-ts-refactor-fork-display-design.md)

**前置条件**：
- Node.js ≥ 20 已安装
- 当前在 `feat/ui-refactor-fork-display` 分支
- `worker.js` + `wrangler.toml` 不要在 Phase 11 之前删除（迁移测试会引用旧键名常量）

**全局约定**：
- 每个 Phase 结束都跑：`npm run typecheck && npm run test` 必须全绿
- 每个 commit 信息以约定式提交格式（feat/chore/docs/test/refactor）
- 所有提交都附 `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`

---

## Phase 1: TS 工具链与 Hono 脚手架

**Files:**
- Create: `package.json`
- Create: `tsconfig.json`
- Create: `vitest.config.ts`
- Create: `src/index.ts`
- Create: `src/env.ts`
- Modify: `wrangler.toml`
- Create: `.gitignore`（如不存在）

### Step 1.1 创建 package.json

- [ ] **Step 1.1.1: 写入 `package.json`**

```json
{
  "name": "github-monitor",
  "version": "2.0.0",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "wrangler dev",
    "test": "vitest run",
    "test:watch": "vitest",
    "typecheck": "tsc --noEmit",
    "deploy": "wrangler deploy"
  },
  "dependencies": {
    "hono": "^4.6.0"
  },
  "devDependencies": {
    "@cloudflare/vitest-pool-workers": "^0.5.0",
    "@cloudflare/workers-types": "^4.20250121.0",
    "typescript": "^5.5.0",
    "vitest": "~2.1.0",
    "wrangler": "^3.95.0"
  }
}
```

- [ ] **Step 1.1.2: 执行 `npm install`**

```bash
npm install
```

Expected: 安装成功，生成 `node_modules/` 与 `package-lock.json`。

### Step 1.2 创建 tsconfig.json

- [ ] **Step 1.2.1: 写入 `tsconfig.json`**

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ES2022",
    "moduleResolution": "Bundler",
    "lib": ["ES2022"],
    "types": ["@cloudflare/workers-types", "@cloudflare/vitest-pool-workers"],
    "jsx": "react-jsx",
    "jsxImportSource": "hono/jsx",
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "noFallthroughCasesInSwitch": true,
    "noImplicitOverride": true,
    "esModuleInterop": true,
    "forceConsistentCasingInFileNames": true,
    "skipLibCheck": true,
    "resolveJsonModule": true,
    "isolatedModules": true,
    "verbatimModuleSyntax": false,
    "noEmit": true
  },
  "include": ["src/**/*", "test/**/*"]
}
```

### Step 1.3 修改 wrangler.toml

- [ ] **Step 1.3.1: 用以下内容替换 `wrangler.toml`**

```toml
name = "github-monitor"
main = "src/index.ts"
compatibility_date = "2025-11-21"
keep_vars = true

[[kv_namespaces]]
binding = "STORAGE"
id = "23647058d05b415e918016865bfc408d"
```

### Step 1.4 创建 src/env.ts

- [ ] **Step 1.4.1: 写入 `src/env.ts`**

```ts
export type Env = {
  STORAGE: KVNamespace
}

export type Variables = {
  // 中间件向后续 handler 注入的上下文
  username?: string
}
```

### Step 1.5 创建空 Hono app 入口

- [ ] **Step 1.5.1: 写入 `src/index.ts`**

```ts
import { Hono } from 'hono'
import type { Env, Variables } from './env'

const app = new Hono<{ Bindings: Env; Variables: Variables }>()

app.get('/health', (c) =>
  c.json({ status: 'ok', timestamp: new Date().toISOString() })
)

export default {
  fetch: app.fetch,
  scheduled: async (_event: ScheduledEvent, _env: Env, _ctx: ExecutionContext) => {
    // 后续阶段补全
  },
}
```

### Step 1.6 创建 vitest.config.ts

- [ ] **Step 1.6.1: 写入 `vitest.config.ts`**

```ts
import { defineWorkersConfig } from '@cloudflare/vitest-pool-workers/config'

export default defineWorkersConfig({
  test: {
    poolOptions: {
      workers: {
        wrangler: { configPath: './wrangler.toml' },
        miniflare: {
          kvNamespaces: ['STORAGE'],
        },
      },
    },
  },
})
```

### Step 1.7 创建 .gitignore（如不存在则新建，否则追加缺失项）

- [ ] **Step 1.7.1: 写入或追加 `.gitignore`**

```
node_modules/
.wrangler/
.superpowers/
dist/
*.log
.dev.vars
```

### Step 1.8 校验 + 提交

- [ ] **Step 1.8.1: 跑 typecheck**

```bash
npm run typecheck
```

Expected: 无错误。

- [ ] **Step 1.8.2: 启动测试（应当通过 0 个测试）**

```bash
npm run test
```

Expected: `No test files found` 或 `0 tests passed`。允许通过。

- [ ] **Step 1.8.3: 提交**

```bash
git add package.json package-lock.json tsconfig.json vitest.config.ts wrangler.toml src/index.ts src/env.ts .gitignore
git commit -m "$(cat <<'EOF'
chore: 添加 TS 工具链与 Hono 脚手架

引入 Hono / Vitest / Workers types。新建 src/index.ts 作为入口、
src/env.ts 定义 Env / Variables 类型。wrangler.toml 切到 src/index.ts。

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Phase 2: KV 存储 — 键定义、模块、迁移

**Files:**
- Create: `src/storage/keys.ts`
- Create: `src/storage/settings.ts`
- Create: `src/storage/repos.ts`
- Create: `src/storage/sessions.ts`
- Create: `src/storage/cron-log.ts`
- Create: `src/storage/migration.ts`
- Create: `test/integration/migration.test.ts`

### Step 2.1 写键名常量

- [ ] **Step 2.1.1: 写入 `src/storage/keys.ts`**

```ts
export const KV = {
  // auth
  PASSWORD_HASH: 'auth:password-hash',
  MUST_CHANGE_PASSWORD: 'auth:must-change-password',
  HMAC_SECRET: 'auth:hmac-secret',
  sessionKey: (token: string) => `auth:session:${token}`,
  loginAttemptsKey: (ip: string) => `auth:login-attempts:${ip}`,

  // settings
  SETTINGS_TELEGRAM: 'settings:telegram',
  SETTINGS_GITHUB: 'settings:github',
  SETTINGS_NOTIFICATIONS: 'settings:notifications',

  // repos
  REPOS_LIST: 'repos:list',
  repoStateKey: (owner: string, repo: string, branch: string) =>
    `repos:state:${owner}:${repo}:${branch}`,

  // system
  SYSTEM_LAST_CHECK_TIME: 'system:last-check-time',
  SYSTEM_LAST_CRON_LOG: 'system:last-cron-log',

  // fork
  forkCacheKey: (owner: string, repo: string) => `fork:cache:${owner}:${repo}`,
  FORK_USER_FORKS_LIST: 'fork:user-forks-list',

  // migration
  MIGRATION_VERSION: 'migration:version',
} as const

// 旧键（仅供迁移使用）
export const LEGACY = {
  PASSWORD_HASH: 'admin_password_hash',
  REPO_LIST: 'monitored_repositories',
  LAST_COMMIT_PREFIX: 'last_commit_',
  TG_BOT_TOKEN: 'telegram_bot_token',
  TG_CHAT_ID: 'telegram_chat_id',
  GITHUB_TOKEN: 'github_token',
  LAST_CHECK_TIME: 'last_check_time',
  LAST_CRON_LOG: 'last_cron_log',
  CRON_NOTIFICATION_ENABLED: 'cron_notification_enabled',
} as const

export const MIGRATION_VERSION = '1'
```

### Step 2.2 写存储模块

- [ ] **Step 2.2.1: 写入 `src/storage/settings.ts`**

```ts
import type { Env } from '../env'
import { KV } from './keys'

export type TelegramSettings = { botToken: string; chatId: string }
export type GithubSettings = {
  token: string
  username: string
  usernameFetchedAt: string  // ISO
}
export type NotificationSettings = { cronEnabled: boolean }

export async function getTelegram(env: Env): Promise<TelegramSettings | null> {
  const raw = await env.STORAGE.get(KV.SETTINGS_TELEGRAM, 'json')
  return (raw as TelegramSettings | null) ?? null
}

export async function setTelegram(env: Env, value: TelegramSettings): Promise<void> {
  await env.STORAGE.put(KV.SETTINGS_TELEGRAM, JSON.stringify(value))
}

export async function getGithub(env: Env): Promise<GithubSettings | null> {
  const raw = await env.STORAGE.get(KV.SETTINGS_GITHUB, 'json')
  return (raw as GithubSettings | null) ?? null
}

export async function setGithub(env: Env, value: GithubSettings): Promise<void> {
  await env.STORAGE.put(KV.SETTINGS_GITHUB, JSON.stringify(value))
}

export async function getNotifications(env: Env): Promise<NotificationSettings> {
  const raw = await env.STORAGE.get(KV.SETTINGS_NOTIFICATIONS, 'json')
  return (raw as NotificationSettings | null) ?? { cronEnabled: true }
}

export async function setNotifications(env: Env, value: NotificationSettings): Promise<void> {
  await env.STORAGE.put(KV.SETTINGS_NOTIFICATIONS, JSON.stringify(value))
}
```

- [ ] **Step 2.2.2: 写入 `src/storage/repos.ts`**

```ts
import type { Env } from '../env'
import { KV } from './keys'

export type RepoEntry = {
  owner: string
  repo: string
  branch: string
  addedAt: string  // ISO
}

export type RepoState = {
  lastSha: string
  lastCheckedAt: string  // ISO
}

export async function getRepoList(env: Env): Promise<RepoEntry[]> {
  const raw = await env.STORAGE.get(KV.REPOS_LIST, 'json')
  return (raw as RepoEntry[] | null) ?? []
}

export async function setRepoList(env: Env, list: RepoEntry[]): Promise<void> {
  await env.STORAGE.put(KV.REPOS_LIST, JSON.stringify(list))
}

export async function getRepoState(
  env: Env, owner: string, repo: string, branch: string,
): Promise<RepoState | null> {
  const raw = await env.STORAGE.get(KV.repoStateKey(owner, repo, branch), 'json')
  return (raw as RepoState | null) ?? null
}

export async function setRepoState(
  env: Env, owner: string, repo: string, branch: string, state: RepoState,
): Promise<void> {
  await env.STORAGE.put(KV.repoStateKey(owner, repo, branch), JSON.stringify(state))
}

export async function deleteRepoState(
  env: Env, owner: string, repo: string, branch: string,
): Promise<void> {
  await env.STORAGE.delete(KV.repoStateKey(owner, repo, branch))
}
```

- [ ] **Step 2.2.3: 写入 `src/storage/sessions.ts`**

```ts
import type { Env } from '../env'
import { KV } from './keys'

export type SessionData = {
  createdAt: string
  expiresAt: string
  rememberMe: boolean
}

export async function getSession(env: Env, token: string): Promise<SessionData | null> {
  const raw = await env.STORAGE.get(KV.sessionKey(token), 'json')
  return (raw as SessionData | null) ?? null
}

export async function putSession(
  env: Env, token: string, data: SessionData, ttlSeconds: number,
): Promise<void> {
  await env.STORAGE.put(KV.sessionKey(token), JSON.stringify(data), {
    expirationTtl: ttlSeconds,
  })
}

export async function deleteSession(env: Env, token: string): Promise<void> {
  await env.STORAGE.delete(KV.sessionKey(token))
}
```

- [ ] **Step 2.2.4: 写入 `src/storage/cron-log.ts`**

```ts
import type { Env } from '../env'
import { KV } from './keys'

export type CronLog = {
  timestamp: string
  startTime: string         // 本地化字符串
  endTime: string
  duration: string          // "1234ms"
  success: boolean
  result: {
    success: boolean
    message?: string
    checkedCount?: number
    updatedCount?: number
    errorCount?: number
    error?: string
  }
  error: string | null
}

export async function getLastCronLog(env: Env): Promise<CronLog | null> {
  const raw = await env.STORAGE.get(KV.SYSTEM_LAST_CRON_LOG, 'json')
  return (raw as CronLog | null) ?? null
}

export async function setLastCronLog(env: Env, log: CronLog): Promise<void> {
  await env.STORAGE.put(KV.SYSTEM_LAST_CRON_LOG, JSON.stringify(log))
}

export async function getLastCheckTime(env: Env): Promise<string> {
  return (await env.STORAGE.get(KV.SYSTEM_LAST_CHECK_TIME)) ?? '从未检查'
}

export async function setLastCheckTime(env: Env, value: string): Promise<void> {
  await env.STORAGE.put(KV.SYSTEM_LAST_CHECK_TIME, value)
}
```

### Step 2.3 写迁移测试（先写测试）

- [ ] **Step 2.3.1: 写入 `test/integration/migration.test.ts`**

```ts
import { env } from 'cloudflare:test'
import { describe, expect, it, beforeEach } from 'vitest'
import { runMigrations } from '../../src/storage/migration'
import { KV, LEGACY, MIGRATION_VERSION } from '../../src/storage/keys'

async function clearAll() {
  const list = await env.STORAGE.list()
  for (const k of list.keys) await env.STORAGE.delete(k.name)
}

describe('storage/migration', () => {
  beforeEach(async () => { await clearAll() })

  it('迁移密码、Telegram、GitHub、通知开关', async () => {
    // admin123 的 SHA-256
    const adminSha = 'b4b9b935a6db4d3d27d76b25ec0e2a45e6e1e8e6f7c8c8e7d8c8e7d8c8e7d8c8'
    // 用真实的 admin123 哈希
    const data = new TextEncoder().encode('admin123')
    const hash = await crypto.subtle.digest('SHA-256', data)
    const hashHex = Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, '0')).join('')

    await env.STORAGE.put(LEGACY.PASSWORD_HASH, hashHex)
    await env.STORAGE.put(LEGACY.TG_BOT_TOKEN, 'BOT123')
    await env.STORAGE.put(LEGACY.TG_CHAT_ID, 'CHAT456')
    await env.STORAGE.put(LEGACY.GITHUB_TOKEN, 'ghp_test')
    await env.STORAGE.put(LEGACY.CRON_NOTIFICATION_ENABLED, 'false')

    await runMigrations(env)

    expect(await env.STORAGE.get(KV.PASSWORD_HASH)).toBe(hashHex)
    expect(await env.STORAGE.get(KV.MUST_CHANGE_PASSWORD)).toBe('1')
    expect(await env.STORAGE.get(KV.SETTINGS_TELEGRAM, 'json')).toEqual({
      botToken: 'BOT123', chatId: 'CHAT456',
    })
    const gh = await env.STORAGE.get(KV.SETTINGS_GITHUB, 'json') as any
    expect(gh.token).toBe('ghp_test')
    expect(await env.STORAGE.get(KV.SETTINGS_NOTIFICATIONS, 'json')).toEqual({
      cronEnabled: false,
    })
    expect(await env.STORAGE.get(KV.MIGRATION_VERSION)).toBe(MIGRATION_VERSION)

    // 旧键应被删除
    expect(await env.STORAGE.get(LEGACY.PASSWORD_HASH)).toBeNull()
    expect(await env.STORAGE.get(LEGACY.TG_BOT_TOKEN)).toBeNull()
    expect(await env.STORAGE.get(LEGACY.GITHUB_TOKEN)).toBeNull()
  })

  it('用非默认密码哈希时不写 must-change-password', async () => {
    await env.STORAGE.put(LEGACY.PASSWORD_HASH, 'not-admin123-hash')
    await runMigrations(env)
    expect(await env.STORAGE.get(KV.MUST_CHANGE_PASSWORD)).toBeNull()
  })

  it('迁移仓库列表 + 最后提交 SHA', async () => {
    await env.STORAGE.put(
      LEGACY.REPO_LIST,
      JSON.stringify([{ owner: 'vercel', repo: 'next.js', branch: 'main' }]),
    )
    await env.STORAGE.put(`${LEGACY.LAST_COMMIT_PREFIX}vercel:next.js:main`, 'abc123')

    await runMigrations(env)

    const list = await env.STORAGE.get(KV.REPOS_LIST, 'json') as any[]
    expect(list).toHaveLength(1)
    expect(list[0].owner).toBe('vercel')
    expect(list[0].repo).toBe('next.js')
    expect(list[0].branch).toBe('main')
    expect(typeof list[0].addedAt).toBe('string')

    const state = await env.STORAGE.get(
      KV.repoStateKey('vercel', 'next.js', 'main'), 'json',
    ) as any
    expect(state.lastSha).toBe('abc123')
    expect(typeof state.lastCheckedAt).toBe('string')

    expect(await env.STORAGE.get(LEGACY.REPO_LIST)).toBeNull()
    expect(await env.STORAGE.get(`${LEGACY.LAST_COMMIT_PREFIX}vercel:next.js:main`)).toBeNull()
  })

  it('第二次调用是 no-op（migration:version 已存在）', async () => {
    await runMigrations(env)
    await env.STORAGE.put(KV.PASSWORD_HASH, 'manually-set')
    await runMigrations(env)
    expect(await env.STORAGE.get(KV.PASSWORD_HASH)).toBe('manually-set')
  })

  it('生成 hmac-secret 如不存在', async () => {
    await runMigrations(env)
    const secret = await env.STORAGE.get(KV.HMAC_SECRET)
    expect(secret).toBeTruthy()
    expect(secret!.length).toBeGreaterThan(20)
  })

  it('保留已存在的 hmac-secret', async () => {
    await env.STORAGE.put(KV.HMAC_SECRET, 'existing-secret')
    await runMigrations(env)
    expect(await env.STORAGE.get(KV.HMAC_SECRET)).toBe('existing-secret')
  })

  it('缺失旧键不报错', async () => {
    await expect(runMigrations(env)).resolves.toBeUndefined()
    expect(await env.STORAGE.get(KV.MIGRATION_VERSION)).toBe(MIGRATION_VERSION)
  })
})
```

- [ ] **Step 2.3.2: 跑测试，确认所有用例 FAIL**

```bash
npm run test -- migration
```

Expected: 报告找不到 `runMigrations` —— 因为还未实现。

### Step 2.4 实现迁移

- [ ] **Step 2.4.1: 写入 `src/storage/migration.ts`**

```ts
import type { Env } from '../env'
import { KV, LEGACY, MIGRATION_VERSION } from './keys'

export async function runMigrations(env: Env): Promise<void> {
  const current = await env.STORAGE.get(KV.MIGRATION_VERSION)
  if (current === MIGRATION_VERSION) return

  console.log('🔄 开始 KV 迁移到版本', MIGRATION_VERSION)
  await migrateAuth(env)
  await migrateTelegram(env)
  await migrateGithub(env)
  await migrateNotifications(env)
  await migrateRepoList(env)
  await migrateLastCommits(env)
  await migrateCronArtifacts(env)
  await ensureHmacSecret(env)

  await env.STORAGE.put(KV.MIGRATION_VERSION, MIGRATION_VERSION)
  console.log('✅ KV 迁移完成')
}

async function migrateAuth(env: Env): Promise<void> {
  const existing = await env.STORAGE.get(KV.PASSWORD_HASH)
  if (existing) return
  const legacy = await env.STORAGE.get(LEGACY.PASSWORD_HASH)
  if (!legacy) return

  await env.STORAGE.put(KV.PASSWORD_HASH, legacy)

  // 检测是否为默认密码 admin123 的 SHA-256
  const adminSha = await sha256Hex('admin123')
  if (legacy === adminSha) {
    await env.STORAGE.put(KV.MUST_CHANGE_PASSWORD, '1')
  }

  await env.STORAGE.delete(LEGACY.PASSWORD_HASH)
  console.log('  ✓ auth:password-hash')
}

async function migrateTelegram(env: Env): Promise<void> {
  const existing = await env.STORAGE.get(KV.SETTINGS_TELEGRAM)
  if (existing) return
  const botToken = await env.STORAGE.get(LEGACY.TG_BOT_TOKEN)
  const chatId = await env.STORAGE.get(LEGACY.TG_CHAT_ID)
  if (!botToken && !chatId) return

  await env.STORAGE.put(
    KV.SETTINGS_TELEGRAM,
    JSON.stringify({ botToken: botToken ?? '', chatId: chatId ?? '' }),
  )
  if (botToken) await env.STORAGE.delete(LEGACY.TG_BOT_TOKEN)
  if (chatId) await env.STORAGE.delete(LEGACY.TG_CHAT_ID)
  console.log('  ✓ settings:telegram')
}

async function migrateGithub(env: Env): Promise<void> {
  const existing = await env.STORAGE.get(KV.SETTINGS_GITHUB)
  if (existing) return
  const token = await env.STORAGE.get(LEGACY.GITHUB_TOKEN)
  if (!token) return

  await env.STORAGE.put(
    KV.SETTINGS_GITHUB,
    JSON.stringify({
      token,
      username: '',
      usernameFetchedAt: '',
    }),
  )
  await env.STORAGE.delete(LEGACY.GITHUB_TOKEN)
  console.log('  ✓ settings:github')
}

async function migrateNotifications(env: Env): Promise<void> {
  const existing = await env.STORAGE.get(KV.SETTINGS_NOTIFICATIONS)
  if (existing) return
  const raw = await env.STORAGE.get(LEGACY.CRON_NOTIFICATION_ENABLED)
  // 默认为 true（与旧实现一致）
  const cronEnabled = raw === null ? true : raw === 'true'

  await env.STORAGE.put(
    KV.SETTINGS_NOTIFICATIONS,
    JSON.stringify({ cronEnabled }),
  )
  if (raw !== null) await env.STORAGE.delete(LEGACY.CRON_NOTIFICATION_ENABLED)
  console.log('  ✓ settings:notifications')
}

async function migrateRepoList(env: Env): Promise<void> {
  const existing = await env.STORAGE.get(KV.REPOS_LIST)
  if (existing) return
  const legacy = await env.STORAGE.get(LEGACY.REPO_LIST, 'json') as
    | Array<{ owner: string; repo: string; branch: string }>
    | null
  if (!legacy) return

  const now = new Date().toISOString()
  const upgraded = legacy.map((r) => ({ ...r, addedAt: now }))
  await env.STORAGE.put(KV.REPOS_LIST, JSON.stringify(upgraded))
  await env.STORAGE.delete(LEGACY.REPO_LIST)
  console.log(`  ✓ repos:list (${upgraded.length} 条)`)
}

async function migrateLastCommits(env: Env): Promise<void> {
  const now = new Date().toISOString()
  let cursor: string | undefined
  let migrated = 0
  do {
    const page = await env.STORAGE.list({
      prefix: LEGACY.LAST_COMMIT_PREFIX,
      ...(cursor ? { cursor } : {}),
    })
    for (const k of page.keys) {
      const rest = k.name.slice(LEGACY.LAST_COMMIT_PREFIX.length)
      const parts = rest.split(':')
      if (parts.length < 3) continue
      const [owner, repo, ...branchParts] = parts
      const branch = branchParts.join(':')
      const newKey = KV.repoStateKey(owner!, repo!, branch)
      if (await env.STORAGE.get(newKey)) {
        await env.STORAGE.delete(k.name)
        continue
      }
      const sha = await env.STORAGE.get(k.name)
      if (sha) {
        await env.STORAGE.put(
          newKey,
          JSON.stringify({ lastSha: sha, lastCheckedAt: now }),
        )
      }
      await env.STORAGE.delete(k.name)
      migrated++
    }
    cursor = page.list_complete ? undefined : page.cursor
  } while (cursor)
  if (migrated > 0) console.log(`  ✓ repos:state:* (${migrated} 条)`)
}

async function migrateCronArtifacts(env: Env): Promise<void> {
  const ct = await env.STORAGE.get(LEGACY.LAST_CHECK_TIME)
  if (ct && !(await env.STORAGE.get(KV.SYSTEM_LAST_CHECK_TIME))) {
    await env.STORAGE.put(KV.SYSTEM_LAST_CHECK_TIME, ct)
    await env.STORAGE.delete(LEGACY.LAST_CHECK_TIME)
  }
  const cl = await env.STORAGE.get(LEGACY.LAST_CRON_LOG)
  if (cl && !(await env.STORAGE.get(KV.SYSTEM_LAST_CRON_LOG))) {
    await env.STORAGE.put(KV.SYSTEM_LAST_CRON_LOG, cl)
    await env.STORAGE.delete(LEGACY.LAST_CRON_LOG)
  }
  if (ct || cl) console.log('  ✓ system:* artifacts')
}

async function ensureHmacSecret(env: Env): Promise<void> {
  const existing = await env.STORAGE.get(KV.HMAC_SECRET)
  if (existing) return
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  const secret = btoa(String.fromCharCode(...bytes))
  await env.STORAGE.put(KV.HMAC_SECRET, secret)
  console.log('  ✓ auth:hmac-secret (generated)')
}

async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input)
  const hash = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}
```

- [ ] **Step 2.4.2: 跑测试，确认全部通过**

```bash
npm run test -- migration
```

Expected: 7 个测试全部 PASS。

### Step 2.5 校验 + 提交

- [ ] **Step 2.5.1: typecheck**

```bash
npm run typecheck
```

Expected: 无错误。

- [ ] **Step 2.5.2: 全量测试**

```bash
npm run test
```

Expected: 全绿。

- [ ] **Step 2.5.3: 提交**

```bash
git add src/storage test/integration/migration.test.ts
git commit -m "$(cat <<'EOF'
feat(storage): 重新设计 KV 键并实现自动迁移

新键采用 namespace:detail 风格（auth/settings/repos/system/fork）。
runMigrations 在 fetch 中间件与 scheduled 入口均会触发，幂等，
不丢数据，通过 migration:version 跳过已完成版本。

包含 7 项集成测试覆盖：密码迁移、默认密码标志、Telegram/GitHub 合并、
通知开关、仓库列表 + addedAt、last_commit_* 扁平化为 repos:state:*、
HMAC secret 生成与保留、二次启动幂等、缺失旧键不报错。

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Phase 3: lib/crypto + auth 基础（password、session、rate-limit）

**Files:**
- Create: `src/lib/crypto.ts`
- Create: `src/auth/password.ts`
- Create: `src/auth/session.ts`
- Create: `src/auth/rate-limit.ts`
- Create: `test/unit/crypto.test.ts`
- Create: `test/unit/session.test.ts`
- Create: `test/unit/rate-limit.test.ts`

### Step 3.1 lib/crypto.ts

- [ ] **Step 3.1.1: 写测试 `test/unit/crypto.test.ts`**

```ts
import { describe, expect, it } from 'vitest'
import { b64encode, b64decode, hmacSha256, randomBase64Url, sha256Hex, timingSafeEqual } from '../../src/lib/crypto'

describe('lib/crypto', () => {
  it('b64encode/decode 互逆', () => {
    const bytes = new Uint8Array([1, 2, 3, 250])
    expect(b64decode(b64encode(bytes))).toEqual(bytes)
  })

  it('sha256Hex 输出 64 位十六进制', async () => {
    const hex = await sha256Hex('admin123')
    expect(hex).toMatch(/^[0-9a-f]{64}$/)
  })

  it('hmacSha256 同输入产生相同输出，不同输入不同', async () => {
    const a = await hmacSha256('secret', 'data')
    const b = await hmacSha256('secret', 'data')
    const c = await hmacSha256('secret', 'data2')
    expect(a).toBe(b)
    expect(a).not.toBe(c)
  })

  it('randomBase64Url 产生 URL 安全字符串', () => {
    const s = randomBase64Url(32)
    expect(s).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(s.length).toBeGreaterThan(30)
  })

  it('timingSafeEqual', () => {
    expect(timingSafeEqual('abc', 'abc')).toBe(true)
    expect(timingSafeEqual('abc', 'abd')).toBe(false)
    expect(timingSafeEqual('abc', 'abcd')).toBe(false)
  })
})
```

- [ ] **Step 3.1.2: 跑测试，确认 FAIL**

```bash
npm run test -- crypto
```

Expected: `Cannot find module './src/lib/crypto'`。

- [ ] **Step 3.1.3: 实现 `src/lib/crypto.ts`**

```ts
export function b64encode(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s)
}

export function b64decode(b64: string): Uint8Array {
  const s = atob(b64)
  const out = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i)
  return out
}

export function b64urlEncode(bytes: Uint8Array): string {
  return b64encode(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function b64urlDecode(s: string): Uint8Array {
  const padded = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)
  return b64decode(padded)
}

export function randomBase64Url(bytes: number): string {
  return b64urlEncode(crypto.getRandomValues(new Uint8Array(bytes)))
}

export async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input)
  const hash = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, '0')).join('')
}

export async function hmacSha256(secret: string, data: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign'],
  )
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data))
  return b64urlEncode(new Uint8Array(sig))
}

export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i)
  return diff === 0
}
```

- [ ] **Step 3.1.4: 跑测试，全部 PASS**

```bash
npm run test -- crypto
```

Expected: 5 个测试 PASS。

### Step 3.2 auth/password.ts

- [ ] **Step 3.2.1: 写测试，新增到 `test/unit/crypto.test.ts` 末尾**

> 注意：把 password 测试放在 `crypto.test.ts` 是为了减少文件数；如团队约定一个模块一个测试文件，可拆为 `password.test.ts`。

```ts
// 追加到 test/unit/crypto.test.ts 文件末尾
import { hashPassword, verifyPassword } from '../../src/auth/password'

describe('auth/password', () => {
  it('hash + verify 配对成功', async () => {
    const h = await hashPassword('s3cret!')
    expect(h).toMatch(/^\$pbkdf2\$iter=\d+\$[^$]+\$[^$]+$/)
    expect(await verifyPassword('s3cret!', h)).toBe(true)
  })

  it('错误密码拒绝', async () => {
    const h = await hashPassword('s3cret!')
    expect(await verifyPassword('wrong', h)).toBe(false)
  })

  it('每次 hash 产生不同 salt / 不同结果', async () => {
    const h1 = await hashPassword('same')
    const h2 = await hashPassword('same')
    expect(h1).not.toBe(h2)
    expect(await verifyPassword('same', h1)).toBe(true)
    expect(await verifyPassword('same', h2)).toBe(true)
  })

  it('损坏格式返回 false', async () => {
    expect(await verifyPassword('x', 'not-a-pbkdf2-string')).toBe(false)
  })
})
```

- [ ] **Step 3.2.2: 跑测试，FAIL**

```bash
npm run test -- crypto
```

Expected: `Cannot find module './src/auth/password'`。

- [ ] **Step 3.2.3: 实现 `src/auth/password.ts`**

```ts
import { b64decode, b64encode, timingSafeEqual } from '../lib/crypto'

const ITERATIONS = 100_000

export async function hashPassword(plain: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const bits = await deriveBits(plain, salt, ITERATIONS)
  return `$pbkdf2$iter=${ITERATIONS}$${b64encode(salt)}$${b64encode(new Uint8Array(bits))}`
}

export async function verifyPassword(plain: string, stored: string): Promise<boolean> {
  const m = stored.match(/^\$pbkdf2\$iter=(\d+)\$([^$]+)\$([^$]+)$/)
  if (!m) return false
  const iter = parseInt(m[1]!, 10)
  if (!Number.isFinite(iter) || iter < 1) return false
  let salt: Uint8Array, expected: Uint8Array
  try { salt = b64decode(m[2]!); expected = b64decode(m[3]!) }
  catch { return false }
  const bits = await deriveBits(plain, salt, iter)
  const actual = new Uint8Array(bits)
  return timingSafeEqual(b64encode(actual), b64encode(expected))
}

async function deriveBits(plain: string, salt: Uint8Array, iterations: number): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(plain), 'PBKDF2', false, ['deriveBits'],
  )
  return crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    key, 256,
  )
}
```

- [ ] **Step 3.2.4: 测试 PASS**

```bash
npm run test -- crypto
```

Expected: 9 个测试 PASS。

### Step 3.3 auth/session.ts

- [ ] **Step 3.3.1: 写测试 `test/unit/session.test.ts`**

```ts
import { env } from 'cloudflare:test'
import { describe, expect, it, beforeEach } from 'vitest'
import { createSession, verifySessionCookie, deleteSessionCookie, buildSessionCookie } from '../../src/auth/session'
import { KV } from '../../src/storage/keys'

beforeEach(async () => {
  const list = await env.STORAGE.list()
  for (const k of list.keys) await env.STORAGE.delete(k.name)
  await env.STORAGE.put(KV.HMAC_SECRET, 'test-secret')
})

describe('auth/session', () => {
  it('创建 session → 写 KV → cookie 含签名', async () => {
    const { cookieValue, token } = await createSession(env, { rememberMe: true })
    expect(cookieValue).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)
    expect(token.length).toBeGreaterThan(20)
    const stored = await env.STORAGE.get(KV.sessionKey(token), 'json')
    expect(stored).toBeTruthy()
  })

  it('verifySessionCookie 接受正确签名', async () => {
    const { cookieValue } = await createSession(env, { rememberMe: false })
    const result = await verifySessionCookie(env, cookieValue)
    expect(result.valid).toBe(true)
  })

  it('verifySessionCookie 拒绝伪造签名', async () => {
    const { token } = await createSession(env, { rememberMe: false })
    const result = await verifySessionCookie(env, `${token}.tampered_hmac`)
    expect(result.valid).toBe(false)
  })

  it('verifySessionCookie 拒绝过期 session（KV 已删除）', async () => {
    const { cookieValue, token } = await createSession(env, { rememberMe: false })
    await env.STORAGE.delete(KV.sessionKey(token))
    const result = await verifySessionCookie(env, cookieValue)
    expect(result.valid).toBe(false)
  })

  it('buildSessionCookie rememberMe=true 设 Max-Age', () => {
    const c = buildSessionCookie('abc.def', { rememberMe: true })
    expect(c).toContain('Max-Age=604800')
    expect(c).toContain('HttpOnly')
    expect(c).toContain('Secure')
    expect(c).toContain('SameSite=Strict')
  })

  it('buildSessionCookie rememberMe=false 不设 Max-Age', () => {
    const c = buildSessionCookie('abc.def', { rememberMe: false })
    expect(c).not.toContain('Max-Age=')
  })

  it('deleteSessionCookie 返回过期 cookie 字符串', () => {
    const c = deleteSessionCookie()
    expect(c).toContain('Max-Age=0')
  })
})
```

- [ ] **Step 3.3.2: 跑测试，FAIL**

```bash
npm run test -- session
```

Expected: `Cannot find module './src/auth/session'`。

- [ ] **Step 3.3.3: 实现 `src/auth/session.ts`**

```ts
import type { Env } from '../env'
import { hmacSha256, randomBase64Url, timingSafeEqual } from '../lib/crypto'
import { KV } from '../storage/keys'
import { getSession, putSession, deleteSession } from '../storage/sessions'

const REMEMBER_ME_TTL = 60 * 60 * 24 * 7  // 7 days
const SHORT_TTL = 60 * 60 * 24            // 1 day

export type CreateSessionResult = {
  token: string
  cookieValue: string
  ttlSeconds: number
}

async function getSecret(env: Env): Promise<string> {
  const s = await env.STORAGE.get(KV.HMAC_SECRET)
  if (!s) throw new Error('HMAC secret not initialized')
  return s
}

export async function createSession(
  env: Env, opts: { rememberMe: boolean },
): Promise<CreateSessionResult> {
  const token = randomBase64Url(32)
  const ttl = opts.rememberMe ? REMEMBER_ME_TTL : SHORT_TTL
  const now = Date.now()
  await putSession(env, token, {
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + ttl * 1000).toISOString(),
    rememberMe: opts.rememberMe,
  }, ttl)
  const sig = await hmacSha256(await getSecret(env), token)
  return { token, cookieValue: `${token}.${sig}`, ttlSeconds: ttl }
}

export type VerifyResult =
  | { valid: true; token: string }
  | { valid: false }

export async function verifySessionCookie(env: Env, cookieValue: string): Promise<VerifyResult> {
  const parts = cookieValue.split('.')
  if (parts.length !== 2) return { valid: false }
  const [token, sig] = parts as [string, string]

  const secret = await getSecret(env)
  const expectedSig = await hmacSha256(secret, token)
  if (!timingSafeEqual(sig, expectedSig)) return { valid: false }

  const data = await getSession(env, token)
  if (!data) return { valid: false }
  if (Date.parse(data.expiresAt) < Date.now()) return { valid: false }
  return { valid: true, token }
}

export async function destroySession(env: Env, token: string): Promise<void> {
  await deleteSession(env, token)
}

export function buildSessionCookie(
  cookieValue: string, opts: { rememberMe: boolean },
): string {
  const base = `session=${cookieValue}; HttpOnly; Secure; SameSite=Strict; Path=/`
  return opts.rememberMe ? `${base}; Max-Age=${REMEMBER_ME_TTL}` : base
}

export function deleteSessionCookie(): string {
  return 'session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0'
}

export function parseSessionCookie(cookieHeader: string | null | undefined): string | null {
  if (!cookieHeader) return null
  for (const part of cookieHeader.split(';')) {
    const [k, ...rest] = part.trim().split('=')
    if (k === 'session') return rest.join('=')
  }
  return null
}
```

- [ ] **Step 3.3.4: 测试 PASS**

```bash
npm run test -- session
```

Expected: 7 个测试 PASS。

### Step 3.4 auth/rate-limit.ts

- [ ] **Step 3.4.1: 写测试 `test/unit/rate-limit.test.ts`**

```ts
import { env } from 'cloudflare:test'
import { describe, expect, it, beforeEach } from 'vitest'
import { recordFailure, clearAttempts, isLockedOut } from '../../src/auth/rate-limit'

beforeEach(async () => {
  const list = await env.STORAGE.list()
  for (const k of list.keys) await env.STORAGE.delete(k.name)
})

describe('auth/rate-limit', () => {
  it('5 次失败后锁定 10 分钟', async () => {
    for (let i = 0; i < 4; i++) {
      const r = await recordFailure(env, '1.1.1.1')
      expect(r.lockedOut).toBe(false)
    }
    const r5 = await recordFailure(env, '1.1.1.1')
    expect(r5.lockedOut).toBe(true)

    const status = await isLockedOut(env, '1.1.1.1')
    expect(status.lockedOut).toBe(true)
    expect(status.remainingMs ?? 0).toBeGreaterThan(0)
  })

  it('成功登录后 clearAttempts 清零', async () => {
    for (let i = 0; i < 3; i++) await recordFailure(env, '2.2.2.2')
    await clearAttempts(env, '2.2.2.2')
    const status = await isLockedOut(env, '2.2.2.2')
    expect(status.lockedOut).toBe(false)
  })

  it('不同 IP 隔离', async () => {
    for (let i = 0; i < 5; i++) await recordFailure(env, '3.3.3.3')
    expect((await isLockedOut(env, '3.3.3.3')).lockedOut).toBe(true)
    expect((await isLockedOut(env, '4.4.4.4')).lockedOut).toBe(false)
  })

  it('未尝试过的 IP 不锁定', async () => {
    expect((await isLockedOut(env, '9.9.9.9')).lockedOut).toBe(false)
  })
})
```

- [ ] **Step 3.4.2: 跑测试 FAIL**

```bash
npm run test -- rate-limit
```

- [ ] **Step 3.4.3: 实现 `src/auth/rate-limit.ts`**

```ts
import type { Env } from '../env'
import { KV } from '../storage/keys'

const MAX_FAILURES = 5
const LOCKOUT_MS = 10 * 60 * 1000
const LOCKOUT_TTL_SECONDS = 600

type Attempts = { count: number; lockedUntil: number | null }

export type FailureResult = {
  count: number
  lockedOut: boolean
  remainingAttempts: number
}

async function read(env: Env, ip: string): Promise<Attempts | null> {
  return (await env.STORAGE.get(KV.loginAttemptsKey(ip), 'json')) as Attempts | null
}

async function write(env: Env, ip: string, value: Attempts): Promise<void> {
  await env.STORAGE.put(
    KV.loginAttemptsKey(ip), JSON.stringify(value),
    { expirationTtl: LOCKOUT_TTL_SECONDS },
  )
}

export async function recordFailure(env: Env, ip: string): Promise<FailureResult> {
  const existing = (await read(env, ip)) ?? { count: 0, lockedUntil: null }
  const next: Attempts = {
    count: existing.count + 1,
    lockedUntil: existing.lockedUntil,
  }
  if (next.count >= MAX_FAILURES) next.lockedUntil = Date.now() + LOCKOUT_MS
  await write(env, ip, next)
  return {
    count: next.count,
    lockedOut: next.lockedUntil !== null && next.lockedUntil > Date.now(),
    remainingAttempts: Math.max(0, MAX_FAILURES - next.count),
  }
}

export async function clearAttempts(env: Env, ip: string): Promise<void> {
  await env.STORAGE.delete(KV.loginAttemptsKey(ip))
}

export type LockoutStatus =
  | { lockedOut: false }
  | { lockedOut: true; remainingMs: number }

export async function isLockedOut(env: Env, ip: string): Promise<LockoutStatus> {
  const r = await read(env, ip)
  if (!r || r.lockedUntil === null) return { lockedOut: false }
  const remaining = r.lockedUntil - Date.now()
  if (remaining <= 0) return { lockedOut: false }
  return { lockedOut: true, remainingMs: remaining }
}
```

- [ ] **Step 3.4.4: 测试 PASS**

```bash
npm run test -- rate-limit
```

### Step 3.5 校验 + 提交

- [ ] **Step 3.5.1: typecheck + 全量测试**

```bash
npm run typecheck && npm run test
```

Expected: 全绿。

- [ ] **Step 3.5.2: 提交**

```bash
git add src/lib src/auth test/unit
git commit -m "$(cat <<'EOF'
feat(auth): PBKDF2 密码 + 签名 session + 登录失败限流

- lib/crypto: base64 / base64url / sha256 / hmac-sha256 / timing-safe-equal
- auth/password: PBKDF2-SHA256 100k 迭代，格式 \$pbkdf2\$iter=N\$salt\$hash
- auth/session: 32 字节 token + HMAC 签名 cookie，KV TTL 与 rememberMe 联动
- auth/rate-limit: 5 次失败锁 10 分钟，IP 隔离

含 16 个单元测试。

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Phase 4: auth 中间件 + GitHub & Telegram 客户端 + 消息构建

**Files:**
- Create: `src/auth/middleware.ts`
- Create: `src/lib/time.ts`
- Create: `src/services/github.ts`
- Create: `src/services/telegram.ts`
- Create: `test/unit/message-builder.test.ts`

### Step 4.1 lib/time.ts

- [ ] **Step 4.1.1: 写入 `src/lib/time.ts`**

```ts
export function formatShanghai(date: Date): string {
  return date.toLocaleString('zh-CN', {
    timeZone: 'Asia/Shanghai',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

export function formatShanghaiShort(date: Date): string {
  return date.toLocaleString('zh-CN', {
    timeZone: 'Asia/Shanghai',
    hour: '2-digit', minute: '2-digit',
  })
}

export function relativeTime(from: Date, now: Date = new Date()): string {
  const sec = Math.floor((now.getTime() - from.getTime()) / 1000)
  if (sec < 60) return '刚刚'
  const min = Math.floor(sec / 60)
  if (min < 60) return `${min} 分钟前`
  const hr = Math.floor(min / 60)
  if (hr < 24) return `${hr} 小时前`
  const day = Math.floor(hr / 24)
  if (day < 30) return `${day} 天前`
  const mon = Math.floor(day / 30)
  if (mon < 12) return `${mon} 个月前`
  return `${Math.floor(mon / 12)} 年前`
}
```

### Step 4.2 GitHub 客户端

- [ ] **Step 4.2.1: 写入 `src/services/github.ts`**

```ts
export type GhCommit = {
  sha: string
  html_url: string
  commit: { author: { name: string; date: string }; message: string }
}

export type GhRepo = {
  full_name: string
  default_branch: string
  fork: boolean
  parent?: { full_name: string }
}

export type GhBranch = {
  name: string
  commit: { sha: string; commit: { author: { date: string } } }
}

export type GhCompare = {
  status: 'identical' | 'ahead' | 'behind' | 'diverged'
  ahead_by: number
  behind_by: number
}

export type GhMergeUpstreamResult = {
  message: string
  merge_type?: string
  base_branch?: string
}

export type GhUser = { login: string }

export class GitHubError extends Error {
  constructor(
    public status: number,
    message: string,
    public path: string,
    public isRateLimit = false,
    public needsAuth = false,
  ) {
    super(message)
    this.name = 'GitHubError'
  }
}

export class GitHubClient {
  constructor(private readonly token?: string) {}

  private async req<T>(path: string, init: RequestInit = {}): Promise<T> {
    const r = await fetch(`https://api.github.com${path}`, {
      ...init,
      headers: {
        'User-Agent': 'github-monitor',
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        ...(this.token ? { Authorization: `Bearer ${this.token}` } : {}),
        ...(init.headers as Record<string, string> | undefined ?? {}),
      },
    })
    if (!r.ok) {
      const text = await r.text()
      const isRateLimit = r.status === 403 && /rate limit/i.test(text)
      throw new GitHubError(
        r.status,
        `GitHub ${path}: ${r.status} ${r.statusText} ${text.slice(0, 200)}`,
        path, isRateLimit, r.status === 401 || r.status === 403,
      )
    }
    return r.json() as Promise<T>
  }

  getAuthenticatedUser(): Promise<GhUser> {
    return this.req<GhUser>('/user')
  }

  async getLatestCommit(owner: string, repo: string, branch: string): Promise<GhCommit> {
    const commits = await this.req<GhCommit[]>(
      `/repos/${owner}/${repo}/commits?sha=${encodeURIComponent(branch)}&per_page=1`,
    )
    const first = commits[0]
    if (!first) throw new GitHubError(404, `该分支没有提交记录`, `/repos/${owner}/${repo}/commits`)
    return first
  }

  async getCommitsBetween(
    owner: string, repo: string, branch: string, sinceSha: string | null,
  ): Promise<{ commits: GhCommit[]; isComplete: boolean }> {
    const commits = await this.req<GhCommit[]>(
      `/repos/${owner}/${repo}/commits?sha=${encodeURIComponent(branch)}&per_page=100`,
    )
    if (commits.length === 0) return { commits: [], isComplete: true }
    if (!sinceSha) return { commits: [commits[0]!], isComplete: true }
    const idx = commits.findIndex((c) => c.sha === sinceSha)
    if (idx > 0) return { commits: commits.slice(0, idx), isComplete: true }
    if (idx === -1) return { commits, isComplete: false }
    return { commits: [], isComplete: true }  // sinceSha 就是最新
  }

  getRepo(owner: string, repo: string): Promise<GhRepo> {
    return this.req<GhRepo>(`/repos/${owner}/${repo}`)
  }

  async listUserForks(username: string): Promise<GhRepo[]> {
    const all: GhRepo[] = []
    let page = 1
    while (true) {
      const batch = await this.req<GhRepo[]>(
        `/users/${username}/repos?type=forks&per_page=100&page=${page}`,
      )
      all.push(...batch)
      if (batch.length < 100) break
      page++
      if (page > 20) break  // 兜底，2000 个 fork 应足够
    }
    return all
  }

  compareCommits(owner: string, repo: string, base: string, head: string): Promise<GhCompare> {
    return this.req<GhCompare>(
      `/repos/${owner}/${repo}/compare/${encodeURIComponent(base)}...${encodeURIComponent(head)}`,
    )
  }

  getBranch(owner: string, repo: string, branch: string): Promise<GhBranch> {
    return this.req<GhBranch>(`/repos/${owner}/${repo}/branches/${encodeURIComponent(branch)}`)
  }

  syncFork(owner: string, repo: string, branch: string): Promise<GhMergeUpstreamResult> {
    return this.req<GhMergeUpstreamResult>(
      `/repos/${owner}/${repo}/merge-upstream`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ branch }) },
    )
  }

  createFork(owner: string, repo: string): Promise<GhRepo> {
    return this.req<GhRepo>(
      `/repos/${owner}/${repo}/forks`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' },
    )
  }
}
```

### Step 4.3 Telegram 客户端 + 消息构建

- [ ] **Step 4.3.1: 写测试 `test/unit/message-builder.test.ts`**

```ts
import { describe, expect, it } from 'vitest'
import {
  buildCommitNotification, buildCronLogMessage, buildErrorMessage,
} from '../../src/services/telegram'

const repo = { owner: 'vercel', repo: 'next.js', branch: 'main' } as const

const commit = (sha: string, msg: string, author = 'tester', date = '2026-05-23T10:00:00Z') => ({
  sha,
  html_url: `https://github.com/vercel/next.js/commit/${sha}`,
  commit: { author: { name: author, date }, message: msg },
})

describe('buildCommitNotification', () => {
  it('单提交格式', () => {
    const m = buildCommitNotification(repo, [commit('abc1234', 'fix bug')], true)
    expect(m).toContain('vercel/next.js')
    expect(m).toContain('abc1234')
    expect(m).toContain('fix bug')
    expect(m).toContain('main')
  })

  it('多提交 ≤10 条', () => {
    const commits = Array.from({ length: 8 }, (_, i) => commit(`s${i}`.padEnd(7, 'x'), `msg ${i}`))
    const m = buildCommitNotification(repo, commits, true)
    expect(m).toContain('发现 8 个新提交')
  })

  it('多提交 >10 条截断', () => {
    const commits = Array.from({ length: 15 }, (_, i) => commit(`s${i}`.padEnd(7, 'x'), `msg ${i}`))
    const m = buildCommitNotification(repo, commits, true)
    expect(m).toContain('发现 15 个新提交')
    expect(m).toContain('只显示最新的10个提交')
    expect(m).toContain('还有5个提交未显示')
  })

  it('不完整历史标注', () => {
    const commits = Array.from({ length: 3 }, (_, i) => commit(`s${i}`.padEnd(7, 'x'), `msg ${i}`))
    const m = buildCommitNotification(repo, commits, false)
    expect(m).toContain('可能未显示所有提交')
  })

  it('fork 落后时附加提示', () => {
    const m = buildCommitNotification(
      repo, [commit('abc1234', 'fix bug')], true,
      { exists: true, behind: 5, fullName: 'laityts/next.js' } as any,
    )
    expect(m).toContain('你的 fork 落后 5')
  })
})

describe('buildCronLogMessage', () => {
  it('成功格式', () => {
    const m = buildCronLogMessage({
      timestamp: '', startTime: '2026/05/23 10:00:00', endTime: '', duration: '500ms',
      success: true,
      result: { success: true, message: '检查完成', checkedCount: 3, updatedCount: 1, errorCount: 0 },
      error: null,
    })
    expect(m).toContain('执行成功')
    expect(m).toContain('已检查仓库: 3')
    expect(m).toContain('发现更新: 1')
  })

  it('失败格式', () => {
    const m = buildCronLogMessage({
      timestamp: '', startTime: '2026/05/23 10:00:00', endTime: '', duration: '500ms',
      success: false, result: { success: false, error: 'boom' }, error: 'boom',
    })
    expect(m).toContain('执行失败')
    expect(m).toContain('boom')
  })
})

describe('buildErrorMessage', () => {
  it('包含仓库与错误', () => {
    const m = buildErrorMessage(repo, new Error('Network down'))
    expect(m).toContain('vercel/next.js')
    expect(m).toContain('Network down')
  })
})
```

- [ ] **Step 4.3.2: 跑测试 FAIL**

```bash
npm run test -- message-builder
```

- [ ] **Step 4.3.3: 实现 `src/services/telegram.ts`**

```ts
import type { GhCommit } from './github'
import type { CronLog } from '../storage/cron-log'
import type { RepoEntry } from '../storage/repos'
import { formatShanghai, formatShanghaiShort } from '../lib/time'

export class TelegramError extends Error {
  constructor(public status: number, public description: string) {
    super(`Telegram API ${status}: ${description}`)
    this.name = 'TelegramError'
  }
}

export class TelegramClient {
  constructor(private botToken: string, private chatId: string) {}

  async send(text: string): Promise<void> {
    const r = await fetch(`https://api.telegram.org/bot${this.botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: this.chatId,
        text,
        parse_mode: 'HTML',
        disable_web_page_preview: false,
      }),
    })
    if (!r.ok) {
      const data = await r.json().catch(() => ({})) as { description?: string }
      throw new TelegramError(r.status, data.description ?? r.statusText)
    }
  }
}

export type ForkSummary = {
  exists: true
  fullName: string
  behind: number
} | { exists: false } | { error: string }

export function buildCommitNotification(
  repo: Pick<RepoEntry, 'owner' | 'repo' | 'branch'>,
  commits: GhCommit[],
  isCompleteHistory: boolean,
  fork?: ForkSummary,
): string {
  const repoUrl = `https://github.com/${repo.owner}/${repo.repo}`
  let m = `🚀 <b>代码仓库已更新！</b>\n\n`
  m += `📦 <b>仓库:</b> <a href="${repoUrl}">${repo.owner}/${repo.repo}</a>\n`
  m += `🌿 <b>分支:</b> <code>${repo.branch}</code>\n\n`

  if (commits.length === 1) {
    const c = commits[0]!
    const shortSha = c.sha.substring(0, 7)
    const firstLine = c.commit.message.split('\n')[0]
    const date = new Date(c.commit.author.date)
    m += `📝 <b>最新提交:</b> <a href="${c.html_url}">${shortSha}</a>\n`
    m += `👤 <b>作者:</b> ${c.commit.author.name}\n`
    m += `💬 <b>提交信息:</b> ${firstLine}\n`
    m += `⏰ <b>时间:</b> ${formatShanghai(date)}\n\n`
  } else {
    const display = commits.slice(0, 10)
    const remaining = commits.length - display.length
    m += `📋 <b>发现 ${commits.length} 个新提交</b>\n\n`
    display.forEach((c, i) => {
      const shortSha = c.sha.substring(0, 7)
      const firstLine = c.commit.message.split('\n')[0]
      const date = new Date(c.commit.author.date)
      m += `${i + 1}. <a href="${c.html_url}">${shortSha}</a> - ${firstLine}\n`
      m += `   👤 ${c.commit.author.name} • ⏰ ${formatShanghaiShort(date)}\n\n`
    })
    if (remaining > 0) {
      m += `📝 <i>由于提交数量较多，只显示最新的10个提交（还有${remaining}个提交未显示）</i>\n\n`
    }
    if (!isCompleteHistory) {
      m += `⚠️ <i>注意：由于提交历史较长，可能未显示所有提交</i>\n\n`
    }
  }

  if (fork && 'exists' in fork && fork.exists && fork.behind > 0) {
    m += `💡 <b>你的 fork 落后 ${fork.behind} commit</b>（<code>${fork.fullName}</code>）\n\n`
  }

  m += `<a href="${repoUrl}/commits/${repo.branch}">查看完整提交历史</a>`
  return m
}

export function buildCronLogMessage(log: CronLog): string {
  const statusIcon = log.success ? '✅' : '❌'
  const statusText = log.success ? '执行成功' : '执行失败'
  const title = `${statusIcon} <b>GitHub Monitor 定时任务报告</b>`

  const basicInfo = [
    `📅 <b>执行时间:</b> ${log.startTime}`,
    `⏱️ <b>执行时长:</b> ${log.duration}`,
    `🔄 <b>执行状态:</b> ${statusText}`,
  ].join('\n')

  let resultDetails = ''
  if (log.success && log.result) {
    const r = log.result
    resultDetails = [
      `📊 <b>检查结果:</b>`,
      `   • 已检查仓库: ${r.checkedCount ?? 0}`,
      `   • 发现更新: ${r.updatedCount ?? 0}`,
      `   • 错误数量: ${r.errorCount ?? 0}`,
      `💬 <b>总结:</b> ${r.message ?? '检查完成'}`,
    ].join('\n')
  } else if (log.error) {
    resultDetails = `🚨 <b>错误信息:</b>\n<code>${log.error}</code>`
  }

  const systemInfo = [
    `💻 <b>系统状态:</b> ${log.success ? '正常运行' : '遇到问题'}`,
    `🔔 <b>通知渠道:</b> Telegram`,
  ].join('\n')

  return `${title}\n\n${basicInfo}\n\n${resultDetails}\n\n${systemInfo}\n\n<i>此消息由GitHub Monitor定时任务自动发送</i>`
}

export function buildErrorMessage(
  repo: Pick<RepoEntry, 'owner' | 'repo' | 'branch'>, err: unknown,
): string {
  const msg = err instanceof Error ? err.message : String(err)
  return `❌ <b>监控错误</b>\n\n检查仓库 ${repo.owner}/${repo.repo} (${repo.branch}) 时出错:\n<code>${msg}</code>`
}
```

- [ ] **Step 4.3.4: 测试 PASS**

```bash
npm run test -- message-builder
```

Expected: 8 个测试 PASS。

### Step 4.4 auth 中间件

- [ ] **Step 4.4.1: 写入 `src/auth/middleware.ts`**

```ts
import type { MiddlewareHandler } from 'hono'
import type { Env, Variables } from '../env'
import { parseSessionCookie, verifySessionCookie } from './session'
import { KV } from '../storage/keys'

const PUBLIC_PATHS = new Set(['/login', '/logout'])
const FORCE_PASSWORD_ALLOWLIST = new Set(['/settings/password', '/logout'])

export const authMiddleware: MiddlewareHandler<{ Bindings: Env; Variables: Variables }> = async (c, next) => {
  if (PUBLIC_PATHS.has(c.req.path)) return next()

  const cookie = parseSessionCookie(c.req.header('Cookie'))
  if (!cookie) return c.redirect('/login', 302)
  const result = await verifySessionCookie(c.env, cookie)
  if (!result.valid) return c.redirect('/login', 302)

  // 强制改密：除允许的路径外，其他都跳到 password
  const mustChange = await c.env.STORAGE.get(KV.MUST_CHANGE_PASSWORD)
  if (mustChange === '1' && !FORCE_PASSWORD_ALLOWLIST.has(c.req.path)) {
    return c.redirect('/settings/password?forced=1', 302)
  }

  return next()
}

export function clientIp(c: { req: { header: (k: string) => string | undefined } }): string {
  return c.req.header('CF-Connecting-IP') ?? '0.0.0.0'
}
```

### Step 4.5 校验 + 提交

- [ ] **Step 4.5.1: typecheck + 全量测试**

```bash
npm run typecheck && npm run test
```

Expected: 全绿（已累计 24+ 测试）。

- [ ] **Step 4.5.2: 提交**

```bash
git add src/lib/time.ts src/services src/auth/middleware.ts test/unit/message-builder.test.ts
git commit -m "$(cat <<'EOF'
feat(services): GitHub/Telegram 客户端 + 消息构建 + auth 中间件

- services/github: GitHubClient 类 + GitHubError，封装 commits/forks/compare/sync/createFork
- services/telegram: TelegramClient + buildCommitNotification / buildCronLogMessage / buildErrorMessage 纯函数
- lib/time: 上海时区格式化与相对时间
- auth/middleware: 校验 cookie + 强制改密 redirect

消息格式保留与 worker.js 一致。8 个消息构建单测覆盖。

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Phase 5: services/checker + services/cron + GitHub 用户解析

**Files:**
- Create: `src/services/username.ts`
- Create: `src/services/checker.ts`
- Create: `src/services/cron.ts`

### Step 5.1 username.ts

- [ ] **Step 5.1.1: 写入 `src/services/username.ts`**

```ts
import type { Env } from '../env'
import { GitHubClient } from './github'
import { getGithub, setGithub } from '../storage/settings'

const USERNAME_TTL_MS = 24 * 60 * 60 * 1000

export async function resolveUsername(env: Env): Promise<string | null> {
  const gh = await getGithub(env)
  if (!gh) return null
  if (
    gh.username &&
    gh.usernameFetchedAt &&
    Date.now() - Date.parse(gh.usernameFetchedAt) < USERNAME_TTL_MS
  ) {
    return gh.username
  }
  if (!gh.token) return null
  try {
    const client = new GitHubClient(gh.token)
    const user = await client.getAuthenticatedUser()
    await setGithub(env, {
      token: gh.token,
      username: user.login,
      usernameFetchedAt: new Date().toISOString(),
    })
    return user.login
  } catch (err) {
    console.error('resolveUsername 失败:', err)
    return gh.username || null
  }
}
```

### Step 5.2 checker.ts

- [ ] **Step 5.2.1: 写入 `src/services/checker.ts`**

```ts
import type { Env } from '../env'
import { getRepoList, getRepoState, setRepoState } from '../storage/repos'
import { getGithub, getTelegram } from '../storage/settings'
import { setLastCheckTime } from '../storage/cron-log'
import { GitHubClient } from './github'
import { TelegramClient, buildCommitNotification, buildErrorMessage } from './telegram'
import { formatShanghai } from '../lib/time'

export type CheckResult = {
  success: boolean
  message: string
  checkedCount: number
  updatedCount: number
  errorCount: number
  error?: string
}

export async function runCheck(env: Env): Promise<CheckResult> {
  console.log('🔍 开始检查所有仓库更新...')
  const checkTime = formatShanghai(new Date())
  await setLastCheckTime(env, checkTime)

  const repoList = await getRepoList(env)
  const tg = await getTelegram(env)
  const gh = await getGithub(env)

  if (repoList.length === 0) {
    console.log('ℹ️ 没有监控的仓库需要检查')
    return { success: true, message: '没有监控的仓库需要检查', checkedCount: 0, updatedCount: 0, errorCount: 0 }
  }

  const client = new GitHubClient(gh?.token)
  const telegram = tg && tg.botToken && tg.chatId
    ? new TelegramClient(tg.botToken, tg.chatId) : null

  let checked = 0, updated = 0, errors = 0

  for (const repo of repoList) {
    try {
      console.log(`🔎 检查 ${repo.owner}/${repo.repo} (${repo.branch})`)
      const latest = await client.getLatestCommit(repo.owner, repo.repo, repo.branch)
      const state = await getRepoState(env, repo.owner, repo.repo, repo.branch)
      checked++

      if (!state) {
        await setRepoState(env, repo.owner, repo.repo, repo.branch, {
          lastSha: latest.sha, lastCheckedAt: new Date().toISOString(),
        })
        continue
      }

      if (latest.sha === state.lastSha) continue

      updated++
      let between
      try {
        between = await client.getCommitsBetween(repo.owner, repo.repo, repo.branch, state.lastSha)
      } catch (err) {
        console.error('getCommitsBetween 失败，退化为单条:', err)
        between = { commits: [latest], isComplete: false }
      }

      if (telegram && between.commits.length > 0) {
        const msg = buildCommitNotification(repo, between.commits, between.isComplete)
        try { await telegram.send(msg) } catch (err) {
          console.error('Telegram 发送失败:', err)
        }
      }

      await setRepoState(env, repo.owner, repo.repo, repo.branch, {
        lastSha: latest.sha, lastCheckedAt: new Date().toISOString(),
      })
    } catch (err) {
      console.error('检查仓库出错:', err)
      errors++
      if (telegram) {
        try { await telegram.send(buildErrorMessage(repo, err)) } catch {}
      }
    }
    const delay = gh?.token ? 500 : 2000
    await new Promise((r) => setTimeout(r, delay))
  }

  const message = `检查完成: 已检查 ${checked} 个仓库，发现 ${updated} 个更新，${errors} 个错误`
  console.log(`✅ ${message}`)
  return { success: true, message, checkedCount: checked, updatedCount: updated, errorCount: errors }
}
```

### Step 5.3 cron.ts

- [ ] **Step 5.3.1: 写入 `src/services/cron.ts`**

```ts
import type { Env } from '../env'
import { runCheck } from './checker'
import { type CronLog, setLastCronLog } from '../storage/cron-log'
import { getNotifications, getTelegram } from '../storage/settings'
import { TelegramClient, buildCronLogMessage } from './telegram'
import { formatShanghai } from '../lib/time'

export async function runCron(env: Env): Promise<CronLog> {
  console.log('🕒 开始执行定时检查任务')
  const startTime = Date.now()
  let result: CronLog['result']
  let errorMsg: string | null = null

  try {
    const r = await runCheck(env)
    result = r
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    errorMsg = msg
    result = { success: false, error: msg }
    console.error('❌ 定时任务失败:', err)
  }
  const endTime = Date.now()

  const log: CronLog = {
    timestamp: new Date().toISOString(),
    startTime: formatShanghai(new Date(startTime)),
    endTime: formatShanghai(new Date(endTime)),
    duration: `${endTime - startTime}ms`,
    success: errorMsg === null,
    result,
    error: errorMsg,
  }
  await setLastCronLog(env, log)
  await maybeSendCronLog(env, log)
  return log
}

async function maybeSendCronLog(env: Env, log: CronLog): Promise<void> {
  try {
    const tg = await getTelegram(env)
    const notif = await getNotifications(env)
    if (!tg?.botToken || !tg?.chatId) {
      console.log('⚠️ Telegram 未配置，跳过 cron 日志')
      return
    }
    if (!notif.cronEnabled) {
      console.log('🔇 cron 通知关闭，跳过')
      return
    }
    const client = new TelegramClient(tg.botToken, tg.chatId)
    await client.send(buildCronLogMessage(log))
    console.log('📨 cron 日志已推送')
  } catch (err) {
    console.error('cron 日志推送失败:', err)
  }
}
```

### Step 5.4 校验 + 提交

- [ ] **Step 5.4.1: typecheck**

```bash
npm run typecheck
```

Expected: 无错误。

- [ ] **Step 5.4.2: 提交**

```bash
git add src/services/username.ts src/services/checker.ts src/services/cron.ts
git commit -m "$(cat <<'EOF'
feat(services): checker + cron 编排 + username 解析

- checker.runCheck：主循环，行为等价 worker.js#checkAllRepos
  含限流延迟（有 token 500ms / 无 token 2000ms）、首次记录跳过通知、
  fetchCommitsBetween 失败降级、单条 Telegram 失败不阻塞
- cron.runCron：编排执行 + 写入 cron 日志 + 按开关推送 Telegram
- username.resolveUsername：缓存 24h，使用 GitHub Token 自动获取

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Phase 6: UI — 主题、Layout、Login 视图

**Files:**
- Create: `src/views/theme.ts`
- Create: `src/views/layout.tsx`
- Create: `src/views/login.tsx`
- Create: `src/views/components/status-banner.tsx`

### Step 6.1 views/theme.ts

- [ ] **Step 6.1.1: 写入 `src/views/theme.ts`**

```ts
export const THEME_CSS = `
:root[data-theme="light"] {
  --bg: #ffffff; --bg-soft: #f8fafc; --surface: #ffffff;
  --border: #e2e8f0; --text: #0f172a; --text-muted: #64748b;
  --primary: #0f172a; --accent: #2563eb;
  --success: #16a34a; --danger: #dc2626; --warning: #d97706;
  --warning-bg: #fffbeb;
}
:root[data-theme="dark"] {
  --bg: #0b1220; --bg-soft: #111827; --surface: #1e293b;
  --border: #334155; --text: #f1f5f9; --text-muted: #94a3b8;
  --primary: #f1f5f9; --accent: #38bdf8;
  --success: #4ade80; --danger: #f87171; --warning: #fbbf24;
  --warning-bg: #1f1306;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: var(--bg-soft); color: var(--text); min-height: 100vh;
  padding: 16px;
}
.container { max-width: 920px; margin: 0 auto; }
header.topbar {
  display: flex; justify-content: space-between; align-items: center;
  padding: 12px 16px; background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; margin-bottom: 16px;
}
header.topbar .actions { display: flex; gap: 8px; align-items: center; }
.btn { display: inline-flex; align-items: center; gap: 6px; padding: 8px 14px;
  border: 1px solid var(--border); border-radius: 6px; background: var(--surface);
  color: var(--text); cursor: pointer; font-size: 14px; }
.btn:hover { background: var(--bg-soft); }
.btn.primary { background: var(--primary); color: var(--bg); border-color: var(--primary); }
.btn.accent { background: var(--accent); color: var(--bg); border-color: var(--accent); }
.btn.danger { color: var(--danger); border-color: var(--danger); }
.btn.small { padding: 4px 10px; font-size: 12px; }
.card { background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; padding: 16px; margin-bottom: 16px; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 12px; margin-bottom: 16px; }
.stat { background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; padding: 12px 14px; }
.stat .label { font-size: 12px; color: var(--text-muted); text-transform: uppercase; }
.stat .value { font-size: 20px; font-weight: 600; margin-top: 4px; }
input, select, textarea {
  width: 100%; padding: 10px 12px; border: 1px solid var(--border); border-radius: 6px;
  background: var(--bg); color: var(--text); font-size: 14px; font-family: inherit;
}
input:focus, select:focus, textarea:focus { outline: 2px solid var(--accent); outline-offset: -1px; }
label { display: block; font-size: 13px; color: var(--text-muted); margin-bottom: 6px; }
.form-row { display: flex; gap: 12px; flex-wrap: wrap; }
.form-row > * { flex: 1 1 200px; }
.banner { padding: 12px 14px; border-radius: 8px; margin-bottom: 16px; font-size: 14px; }
.banner.success { background: rgba(22, 163, 74, 0.08); color: var(--success);
  border-left: 3px solid var(--success); }
.banner.error { background: rgba(220, 38, 38, 0.08); color: var(--danger);
  border-left: 3px solid var(--danger); }
.banner.info { background: rgba(37, 99, 235, 0.08); color: var(--accent);
  border-left: 3px solid var(--accent); }
code { background: var(--bg-soft); padding: 1px 5px; border-radius: 3px; font-size: 0.9em; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.repo-card { background: var(--surface); border: 1px solid var(--border);
  border-radius: 10px; padding: 16px; margin-bottom: 12px; }
.repo-card .repo-header { display: flex; justify-content: space-between; align-items: flex-start; }
.repo-card .branch-tag { background: var(--bg-soft); color: var(--text-muted);
  padding: 2px 8px; border-radius: 6px; font-size: 12px; font-weight: 500; margin-left: 8px; }
.repo-card .fork-section { border-top: 1px solid var(--border); margin: 12px -16px -16px;
  padding: 12px 16px; background: var(--bg-soft); border-radius: 0 0 10px 10px; }
.repo-card .fork-section.warning { background: var(--warning-bg); }
.muted { color: var(--text-muted); font-size: 13px; }
footer.footer { margin-top: 24px; padding: 12px 16px; font-size: 12px;
  color: var(--text-muted); text-align: center; }
`

export const THEME_INIT_SCRIPT = `
(function() {
  function read(name) {
    var m = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]+)'));
    return m ? decodeURIComponent(m[1]) : null;
  }
  var saved = read('theme');
  var pref = saved || (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  document.documentElement.setAttribute('data-theme', pref);
})();
`

export const THEME_TOGGLE_SCRIPT = `
function toggleTheme() {
  var cur = document.documentElement.getAttribute('data-theme');
  var next = cur === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  document.cookie = 'theme=' + next + '; path=/; max-age=' + (60*60*24*365) + '; SameSite=Strict';
}
`
```

### Step 6.2 views/layout.tsx

- [ ] **Step 6.2.1: 写入 `src/views/layout.tsx`**

```tsx
/** @jsxImportSource hono/jsx */
import { html, raw } from 'hono/html'
import { THEME_CSS, THEME_INIT_SCRIPT, THEME_TOGGLE_SCRIPT } from './theme'

type LayoutProps = {
  title: string
  username?: string | null
  showTopbar?: boolean
  banner?: { type: 'success' | 'error' | 'info'; message: string } | null
  footer?: { lastCheck?: string; cronEnabled?: boolean } | null
  children: any
}

export function Layout(props: LayoutProps) {
  const showTopbar = props.showTopbar !== false
  return html`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${props.title}</title>
  <script>${raw(THEME_INIT_SCRIPT)}</script>
  <style>${raw(THEME_CSS)}</style>
  <script>${raw(THEME_TOGGLE_SCRIPT)}</script>
</head>
<body>
  <div class="container">
    ${showTopbar ? raw(`
      <header class="topbar">
        <div><strong>📦 GitHub Monitor</strong></div>
        <div class="actions">
          ${props.username ? `<span class="muted">👤 ${escapeHtml(props.username)}</span>` : ''}
          <button class="btn small" type="button" onclick="toggleTheme()">🌓 主题</button>
          <form method="post" action="/logout" style="display:inline;">
            <button class="btn small" type="submit">⎋ 登出</button>
          </form>
        </div>
      </header>
    `) : ''}
    ${props.banner ? raw(renderBanner(props.banner)) : ''}
    ${props.children}
    ${props.footer ? raw(renderFooter(props.footer)) : ''}
  </div>
</body>
</html>`
}

function renderBanner(b: { type: string; message: string }): string {
  return `<div class="banner ${b.type}">${escapeHtml(b.message)}</div>`
}

function renderFooter(f: { lastCheck?: string; cronEnabled?: boolean }): string {
  return `<footer class="footer">
    上次检查: ${escapeHtml(f.lastCheck ?? '从未检查')}
    · Cron 通知: ${f.cronEnabled ? '开启' : '关闭'}
    · v2.0.0
  </footer>`
}

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!))
}
```

### Step 6.3 views/login.tsx

- [ ] **Step 6.3.1: 写入 `src/views/login.tsx`**

```tsx
/** @jsxImportSource hono/jsx */
import { html, raw } from 'hono/html'
import { Layout, escapeHtml } from './layout'

export function LoginView(opts: { error?: string; locked?: { remainingMs: number } | null }) {
  let banner = null as { type: 'error' | 'info'; message: string } | null
  if (opts.locked) {
    const min = Math.ceil(opts.locked.remainingMs / 60000)
    banner = { type: 'error', message: `账户已锁定，剩余 ${min} 分钟` }
  } else if (opts.error) {
    banner = { type: 'error', message: opts.error }
  }
  const body = raw(`
    <div class="card" style="max-width: 420px; margin: 80px auto;">
      <h1 style="font-size: 22px; margin-bottom: 4px;">登录</h1>
      <p class="muted" style="margin-bottom: 20px;">GitHub Monitor 管理面板</p>
      <form method="post" action="/login">
        <label for="password">密码</label>
        <input id="password" type="password" name="password" autocomplete="current-password" required autofocus />
        <label style="display:flex; align-items:center; gap:8px; margin: 12px 0; font-size: 13px;">
          <input type="checkbox" name="remember_me" style="width:auto;" />
          记住我（7 天）
        </label>
        <button class="btn primary" type="submit" style="width:100%;">登录</button>
      </form>
    </div>
  `)
  return Layout({
    title: '登录 · GitHub Monitor',
    showTopbar: false,
    banner,
    children: body,
  })
}
```

### Step 6.4 校验 + 提交

- [ ] **Step 6.4.1: typecheck**

```bash
npm run typecheck
```

Expected: 无错误。

- [ ] **Step 6.4.2: 提交**

```bash
git add src/views/theme.ts src/views/layout.tsx src/views/login.tsx
git commit -m "$(cat <<'EOF'
feat(views): 主题系统 + Layout + Login 视图

- views/theme: 浅色/深色 CSS 变量 + FOUC-free 初始化脚本 + 主题切换函数
- views/layout: Hono html 模板渲染顶部条 / 横幅 / 页脚 / 内容
- views/login: 登录页（含「记住我」复选框 + 锁定提示）

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Phase 7: Dashboard 视图 + 组件（不含 fork 子块）

**Files:**
- Create: `src/views/components/repo-card.tsx`
- Create: `src/views/components/settings-panel.tsx`
- Create: `src/views/components/change-password-form.tsx`
- Create: `src/views/dashboard.tsx`

### Step 7.1 repo-card（暂不含 fork 段）

- [ ] **Step 7.1.1: 写入 `src/views/components/repo-card.tsx`**

```tsx
/** @jsxImportSource hono/jsx */
import { raw } from 'hono/html'
import type { RepoEntry, RepoState } from '../../storage/repos'
import { escapeHtml } from '../layout'
import { relativeTime } from '../../lib/time'

export type RepoCardData = {
  entry: RepoEntry
  state: RepoState | null
}

export function renderRepoCard(data: RepoCardData): string {
  const { entry, state } = data
  const lastInfo = state
    ? `上次提交 <code>${escapeHtml(state.lastSha.substring(0, 7))}</code> · ${escapeHtml(relativeTime(new Date(state.lastCheckedAt)))}`
    : '尚未检查过'

  return `
    <div class="repo-card" data-repo="${escapeHtml(entry.owner)}/${escapeHtml(entry.repo)}" data-branch="${escapeHtml(entry.branch)}">
      <div class="repo-header">
        <div>
          <div style="font-weight: 600;">
            <a href="https://github.com/${escapeHtml(entry.owner)}/${escapeHtml(entry.repo)}" target="_blank" rel="noopener">
              ${escapeHtml(entry.owner)}/${escapeHtml(entry.repo)}
            </a>
            <span class="branch-tag">${escapeHtml(entry.branch)}</span>
          </div>
          <div class="muted" style="margin-top: 4px;">${lastInfo}</div>
        </div>
        <form method="post" action="/repos/delete" onsubmit="return confirm('确定删除该监控？')">
          <input type="hidden" name="owner" value="${escapeHtml(entry.owner)}" />
          <input type="hidden" name="repo" value="${escapeHtml(entry.repo)}" />
          <input type="hidden" name="branch" value="${escapeHtml(entry.branch)}" />
          <button class="btn small danger" type="submit">删除</button>
        </form>
      </div>
      <!-- FORK_PLACEHOLDER -->
    </div>
  `
}
```

### Step 7.2 settings-panel.tsx

- [ ] **Step 7.2.1: 写入 `src/views/components/settings-panel.tsx`**

```tsx
/** @jsxImportSource hono/jsx */
import type { TelegramSettings, GithubSettings, NotificationSettings } from '../../storage/settings'
import { escapeHtml } from '../layout'

export type SettingsPanelData = {
  telegram: TelegramSettings | null
  github: GithubSettings | null
  notifications: NotificationSettings
}

export function renderSettingsPanel(d: SettingsPanelData): string {
  return `
    <div class="card">
      <h2 style="margin-bottom: 12px;">系统设置</h2>
      <form method="post" action="/settings/update">
        <div class="form-row">
          <div>
            <label>Telegram Bot Token</label>
            <input name="tg_bot_token" value="${escapeHtml(d.telegram?.botToken ?? '')}" />
          </div>
          <div>
            <label>Telegram Chat ID</label>
            <input name="tg_chat_id" value="${escapeHtml(d.telegram?.chatId ?? '')}" />
          </div>
        </div>
        <div class="form-row" style="margin-top: 12px;">
          <div>
            <label>GitHub Token（fork sync/create 需 repo / public_repo 权限）</label>
            <input name="github_token" value="${escapeHtml(d.github?.token ?? '')}" autocomplete="off" />
          </div>
        </div>
        <label style="display:flex; align-items:center; gap:8px; margin: 12px 0;">
          <input type="checkbox" name="cron_notification_enabled" ${d.notifications.cronEnabled ? 'checked' : ''} style="width:auto;" />
          开启定时任务报告（关闭后仍会发送 commit 通知与错误通知）
        </label>
        <div style="display:flex; gap: 8px;">
          <button class="btn primary" type="submit">保存设置</button>
        </div>
      </form>
      <div style="display:flex; gap: 8px; margin-top: 12px; flex-wrap: wrap;">
        <form method="post" action="/settings/test-telegram"><button class="btn small" type="submit">测试 Telegram</button></form>
        <form method="post" action="/settings/test-github"><button class="btn small" type="submit">测试 GitHub</button></form>
        <form method="post" action="/repos/clear" onsubmit="return confirm('确定清空所有监控？')">
          <button class="btn small danger" type="submit">清空所有仓库</button>
        </form>
      </div>
    </div>
  `
}
```

### Step 7.3 change-password-form.tsx

- [ ] **Step 7.3.1: 写入 `src/views/components/change-password-form.tsx`**

```tsx
/** @jsxImportSource hono/jsx */
import { Layout } from '../layout'
import { html, raw } from 'hono/html'

export function ChangePasswordView(opts: {
  forced: boolean
  error?: string
  username?: string | null
}) {
  const banner = opts.forced
    ? { type: 'info' as const, message: '检测到您正在使用默认密码，请先修改后继续使用。' }
    : opts.error
      ? { type: 'error' as const, message: opts.error }
      : null

  const body = raw(`
    <div class="card" style="max-width: 480px; margin: 40px auto;">
      <h1 style="font-size: 22px; margin-bottom: 16px;">修改密码</h1>
      <form method="post" action="/settings/password">
        ${opts.forced ? '<input type="hidden" name="forced" value="1" />' : ''}
        <label>当前密码</label>
        <input type="password" name="current_password" autocomplete="current-password" required />
        <label style="margin-top: 12px;">新密码（至少 8 位）</label>
        <input type="password" name="new_password" autocomplete="new-password" required minlength="8" />
        <label style="margin-top: 12px;">确认新密码</label>
        <input type="password" name="confirm_password" autocomplete="new-password" required minlength="8" />
        <div style="display:flex; gap: 8px; margin-top: 16px;">
          <button class="btn primary" type="submit">保存</button>
          ${opts.forced ? '' : '<a class="btn" href="/">返回</a>'}
        </div>
      </form>
    </div>
  `)
  return Layout({
    title: '修改密码 · GitHub Monitor',
    username: opts.username,
    banner,
    children: body,
  })
}
```

### Step 7.4 dashboard.tsx

- [ ] **Step 7.4.1: 写入 `src/views/dashboard.tsx`**

```tsx
/** @jsxImportSource hono/jsx */
import { raw } from 'hono/html'
import { Layout } from './layout'
import { renderRepoCard, type RepoCardData } from './components/repo-card'
import { renderSettingsPanel, type SettingsPanelData } from './components/settings-panel'

export type DashboardData = {
  username: string | null
  banner: { type: 'success' | 'error' | 'info'; message: string } | null
  stats: {
    repoCount: number
    lastCheck: string
    cronEnabled: boolean
    githubUser: string
  }
  repos: RepoCardData[]
  settings: SettingsPanelData
}

export function DashboardView(d: DashboardData) {
  const body = raw(`
    <div class="stats">
      <div class="stat"><div class="label">监控仓库</div><div class="value">${d.stats.repoCount}</div></div>
      <div class="stat"><div class="label">上次检查</div><div class="value" style="font-size: 14px;">${escapeAttr(d.stats.lastCheck)}</div></div>
      <div class="stat"><div class="label">Cron 通知</div><div class="value" style="font-size: 16px;">${d.stats.cronEnabled ? '✅ 开启' : '⏸️ 关闭'}</div></div>
      <div class="stat"><div class="label">GitHub 用户</div><div class="value" style="font-size: 16px;">${escapeAttr(d.stats.githubUser)}</div></div>
    </div>

    <div class="card">
      <h2 style="margin-bottom: 12px;">添加监控仓库</h2>
      <form method="post" action="/repos/add">
        <div class="form-row">
          <div style="flex: 2 1 320px;">
            <label>仓库（owner/repo）</label>
            <input name="repo_full_name" placeholder="vercel/next.js" required />
          </div>
          <div>
            <label>分支</label>
            <input name="branch" placeholder="main" />
          </div>
        </div>
        <div style="margin-top: 12px;">
          <button class="btn primary" type="submit">添加</button>
        </div>
      </form>
    </div>

    <div class="card">
      <h2 style="margin-bottom: 12px;">监控列表</h2>
      ${d.repos.length === 0 ? '<p class="muted">暂无监控仓库</p>' : d.repos.map(renderRepoCard).join('')}
    </div>

    ${renderSettingsPanel(d.settings)}

    <div class="card">
      <h2 style="margin-bottom: 12px;">操作</h2>
      <div style="display:flex; gap:8px; flex-wrap:wrap;">
        <form method="post" action="/check-updates"><button class="btn" type="submit">立即检查更新</button></form>
        <a class="btn" href="/settings/password">修改密码</a>
      </div>
    </div>
  `)
  return Layout({
    title: '仪表盘 · GitHub Monitor',
    username: d.username,
    banner: d.banner,
    footer: { lastCheck: d.stats.lastCheck, cronEnabled: d.stats.cronEnabled },
    children: body,
  })
}

function escapeAttr(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!))
}
```

### Step 7.5 提交

- [ ] **Step 7.5.1: typecheck + 测试**

```bash
npm run typecheck && npm run test
```

Expected: 全绿。

- [ ] **Step 7.5.2: 提交**

```bash
git add src/views/components src/views/dashboard.tsx
git commit -m "$(cat <<'EOF'
feat(views): Dashboard 与组件（不含 fork 子块）

- repo-card: 卡片结构 + 删除表单，预留 FORK_PLACEHOLDER
- settings-panel: Telegram/GitHub/通知开关 + 测试按钮
- change-password-form: 标准 + 强制改密两种模式
- dashboard: 统计卡片 + 添加表单 + 仓库列表 + 设置 + 操作

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Phase 8: Routes 接入 + 集成测试 auth-flow

**Files:**
- Create: `src/routes/index.ts` (re-export)
- Create: `src/routes/auth.ts`
- Create: `src/routes/dashboard.ts`
- Create: `src/routes/repos.ts`
- Create: `src/routes/settings.ts`
- Create: `src/routes/system.ts`
- Modify: `src/index.ts`
- Create: `test/integration/auth-flow.test.ts`

### Step 8.1 routes/auth.ts

- [ ] **Step 8.1.1: 写入 `src/routes/auth.ts`**

```ts
import { Hono } from 'hono'
import type { Env, Variables } from '../env'
import { KV } from '../storage/keys'
import { hashPassword, verifyPassword } from '../auth/password'
import {
  buildSessionCookie, createSession, deleteSessionCookie,
  destroySession, parseSessionCookie, verifySessionCookie,
} from '../auth/session'
import { clearAttempts, isLockedOut, recordFailure } from '../auth/rate-limit'
import { clientIp } from '../auth/middleware'
import { sha256Hex } from '../lib/crypto'
import { LoginView } from '../views/login'

const DEFAULT_PASSWORD = 'admin123'

export const loginRoute = new Hono<{ Bindings: Env; Variables: Variables }>()

loginRoute.get('/', async (c) => {
  // 已登录则跳首页
  const cookie = parseSessionCookie(c.req.header('Cookie'))
  if (cookie) {
    const v = await verifySessionCookie(c.env, cookie)
    if (v.valid) return c.redirect('/', 302)
  }
  return c.html(LoginView({}) as unknown as string)
})

loginRoute.post('/', async (c) => {
  const ip = clientIp(c)
  const lock = await isLockedOut(c.env, ip)
  if (lock.lockedOut) {
    c.status(429)
    return c.html(LoginView({ locked: { remainingMs: lock.remainingMs } }) as unknown as string)
  }
  const form = await c.req.formData()
  const password = (form.get('password') as string | null)?.trim() ?? ''
  const rememberMe = form.get('remember_me') === 'on'

  await ensurePasswordInitialized(c.env)
  const stored = await c.env.STORAGE.get(KV.PASSWORD_HASH)
  if (!stored) {
    c.status(500)
    return c.html(LoginView({ error: '系统未初始化密码' }) as unknown as string)
  }

  const ok = await verifyPassword(password, stored)
  if (!ok) {
    const r = await recordFailure(c.env, ip)
    c.status(401)
    return c.html(LoginView({
      error: `密码错误，剩余 ${r.remainingAttempts} 次尝试`,
      ...(r.lockedOut ? { locked: { remainingMs: 10 * 60 * 1000 } } : {}),
    }) as unknown as string)
  }

  await clearAttempts(c.env, ip)
  const { cookieValue } = await createSession(c.env, { rememberMe })
  c.header('Set-Cookie', buildSessionCookie(cookieValue, { rememberMe }))
  return c.redirect('/', 302)
})

export const logoutRoute = new Hono<{ Bindings: Env; Variables: Variables }>()

logoutRoute.post('/', async (c) => {
  const cookie = parseSessionCookie(c.req.header('Cookie'))
  if (cookie) {
    const v = await verifySessionCookie(c.env, cookie)
    if (v.valid) await destroySession(c.env, v.token)
  }
  c.header('Set-Cookie', deleteSessionCookie())
  return c.redirect('/login', 302)
})

async function ensurePasswordInitialized(env: Env): Promise<void> {
  const existing = await env.STORAGE.get(KV.PASSWORD_HASH)
  if (existing) return
  const hash = await sha256Hex(DEFAULT_PASSWORD)  // 旧格式以便兼容（迁移后会被 detect 为默认密码）
  // 新部署不走旧格式路径：直接写入 PBKDF2 哈希 + 标志为强制改密
  const pbkdf2 = await hashPassword(DEFAULT_PASSWORD)
  await env.STORAGE.put(KV.PASSWORD_HASH, pbkdf2)
  await env.STORAGE.put(KV.MUST_CHANGE_PASSWORD, '1')
  console.log('🆕 初始化默认密码 admin123（标记强制改密）', hash.slice(0, 8))
}
```

### Step 8.2 routes/dashboard.ts

- [ ] **Step 8.2.1: 写入 `src/routes/dashboard.ts`**

```ts
import { Hono } from 'hono'
import type { Env, Variables } from '../env'
import { getRepoList, getRepoState } from '../storage/repos'
import { getGithub, getNotifications, getTelegram } from '../storage/settings'
import { getLastCheckTime } from '../storage/cron-log'
import { resolveUsername } from '../services/username'
import { DashboardView } from '../views/dashboard'

export const dashboardRoute = new Hono<{ Bindings: Env; Variables: Variables }>()

dashboardRoute.get('/', async (c) => {
  const username = await resolveUsername(c.env)
  const repoList = await getRepoList(c.env)
  const lastCheck = await getLastCheckTime(c.env)
  const notif = await getNotifications(c.env)
  const tg = await getTelegram(c.env)
  const gh = await getGithub(c.env)

  const repos = await Promise.all(
    repoList.map(async (entry) => ({
      entry,
      state: await getRepoState(c.env, entry.owner, entry.repo, entry.branch),
    })),
  )

  const messageQuery = c.req.query('message')
  const errorQuery = c.req.query('error')
  const banner = messageQuery
    ? { type: 'success' as const, message: messageQuery }
    : errorQuery
      ? { type: 'error' as const, message: errorQuery }
      : null

  return c.html(DashboardView({
    username,
    banner,
    stats: {
      repoCount: repoList.length,
      lastCheck,
      cronEnabled: notif.cronEnabled,
      githubUser: username || (gh?.token ? '(检测中)' : '(未配置)'),
    },
    repos,
    settings: { telegram: tg, github: gh, notifications: notif },
  }) as unknown as string)
})
```

### Step 8.3 routes/repos.ts

- [ ] **Step 8.3.1: 写入 `src/routes/repos.ts`**

```ts
import { Hono } from 'hono'
import type { Env, Variables } from '../env'
import { deleteRepoState, getRepoList, setRepoList } from '../storage/repos'
import { getGithub } from '../storage/settings'
import { GitHubClient } from '../services/github'
import { runCheck } from '../services/checker'

export const reposRoute = new Hono<{ Bindings: Env; Variables: Variables }>()

reposRoute.post('/add', async (c) => {
  const form = await c.req.formData()
  const repoFullName = (form.get('repo_full_name') as string | null)?.trim() ?? ''
  let branch = (form.get('branch') as string | null)?.trim() ?? ''

  if (!repoFullName) return c.redirect('/?error=仓库名称不能为空', 302)
  const parts = repoFullName.split('/')
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return c.redirect('/?error=格式应为 owner/repo', 302)
  }
  const owner = parts[0].trim()
  const repo = parts[1].trim()
  if (!branch) branch = 'main'

  const list = await getRepoList(c.env)
  if (list.some((r) => r.owner === owner && r.repo === repo && r.branch === branch)) {
    return c.redirect('/?error=该仓库和分支已存在', 302)
  }

  try {
    const gh = await getGithub(c.env)
    const client = new GitHubClient(gh?.token)
    await client.getLatestCommit(owner, repo, branch)
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    return c.redirect(`/?error=${encodeURIComponent('无法添加：' + msg)}`, 302)
  }

  list.push({ owner, repo, branch, addedAt: new Date().toISOString() })
  await setRepoList(c.env, list)
  return c.redirect(`/?message=${encodeURIComponent(`已添加 ${owner}/${repo} (${branch})`)}`, 302)
})

reposRoute.post('/delete', async (c) => {
  const form = await c.req.formData()
  const owner = (form.get('owner') as string | null) ?? ''
  const repo = (form.get('repo') as string | null) ?? ''
  const branch = (form.get('branch') as string | null) ?? ''
  const list = await getRepoList(c.env)
  const filtered = list.filter((r) => !(r.owner === owner && r.repo === repo && r.branch === branch))
  await setRepoList(c.env, filtered)
  await deleteRepoState(c.env, owner, repo, branch)
  return c.redirect(`/?message=${encodeURIComponent(`已删除 ${owner}/${repo} (${branch})`)}`, 302)
})

reposRoute.post('/clear', async (c) => {
  await setRepoList(c.env, [])
  return c.redirect('/?message=已清空所有监控仓库', 302)
})

// 注意：/check-updates 是 GET（保留旧 API），/repos/check 是表单触发的 POST
reposRoute.post('/check', async (c) => {
  const r = await runCheck(c.env)
  return c.redirect(`/?message=${encodeURIComponent(r.message)}`, 302)
})
```

### Step 8.4 routes/settings.ts

- [ ] **Step 8.4.1: 写入 `src/routes/settings.ts`**

```ts
import { Hono } from 'hono'
import type { Env, Variables } from '../env'
import { KV } from '../storage/keys'
import {
  getTelegram, getGithub, getNotifications,
  setTelegram, setGithub, setNotifications,
} from '../storage/settings'
import { GitHubClient } from '../services/github'
import { TelegramClient } from '../services/telegram'
import { hashPassword, verifyPassword } from '../auth/password'
import { ChangePasswordView } from '../views/components/change-password-form'
import { resolveUsername } from '../services/username'
import { formatShanghai } from '../lib/time'

export const settingsRoute = new Hono<{ Bindings: Env; Variables: Variables }>()

settingsRoute.post('/update', async (c) => {
  const form = await c.req.formData()
  const botToken = ((form.get('tg_bot_token') as string | null) ?? '').trim()
  const chatId = ((form.get('tg_chat_id') as string | null) ?? '').trim()
  const ghToken = ((form.get('github_token') as string | null) ?? '').trim()
  const cronEnabled = form.get('cron_notification_enabled') === 'on'

  await setTelegram(c.env, { botToken, chatId })

  const prevGh = await getGithub(c.env)
  if (ghToken) {
    await setGithub(c.env, {
      token: ghToken,
      username: prevGh && prevGh.token === ghToken ? prevGh.username : '',
      usernameFetchedAt: prevGh && prevGh.token === ghToken ? prevGh.usernameFetchedAt : '',
    })
  } else {
    await setGithub(c.env, { token: '', username: '', usernameFetchedAt: '' })
  }
  await setNotifications(c.env, { cronEnabled })
  return c.redirect('/?message=设置已保存', 302)
})

settingsRoute.post('/test-telegram', async (c) => {
  const tg = await getTelegram(c.env)
  if (!tg?.botToken || !tg?.chatId) {
    return c.redirect('/?error=请先配置 Telegram', 302)
  }
  try {
    const client = new TelegramClient(tg.botToken, tg.chatId)
    await client.send(
      `🔔 <b>测试通知</b>\n\n✅ GitHub Monitor 运行正常\n⏰ ${formatShanghai(new Date())}`,
    )
    return c.redirect('/?message=测试通知已发送', 302)
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    return c.redirect(`/?error=${encodeURIComponent('Telegram 测试失败: ' + msg)}`, 302)
  }
})

settingsRoute.post('/test-github', async (c) => {
  const gh = await getGithub(c.env)
  if (!gh?.token) return c.redirect('/?error=请先配置 GitHub Token', 302)
  try {
    const client = new GitHubClient(gh.token)
    const user = await client.getAuthenticatedUser()
    return c.redirect(`/?message=${encodeURIComponent('GitHub 连接成功，用户 ' + user.login)}`, 302)
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    return c.redirect(`/?error=${encodeURIComponent('GitHub 测试失败: ' + msg)}`, 302)
  }
})

settingsRoute.get('/password', async (c) => {
  const forced = c.req.query('forced') === '1'
  const username = await resolveUsername(c.env)
  return c.html(ChangePasswordView({ forced, username }) as unknown as string)
})

settingsRoute.post('/password', async (c) => {
  const form = await c.req.formData()
  const forced = form.get('forced') === '1'
  const current = ((form.get('current_password') as string | null) ?? '')
  const next = ((form.get('new_password') as string | null) ?? '')
  const confirm = ((form.get('confirm_password') as string | null) ?? '')
  const username = await resolveUsername(c.env)

  const fail = (msg: string) =>
    c.html(ChangePasswordView({ forced, error: msg, username }) as unknown as string, 400)

  if (next.length < 8) return fail('新密码至少 8 位')
  if (next !== confirm) return fail('两次输入的新密码不一致')

  const stored = await c.env.STORAGE.get(KV.PASSWORD_HASH)
  if (!stored || !(await verifyPassword(current, stored))) return fail('当前密码错误')

  await c.env.STORAGE.put(KV.PASSWORD_HASH, await hashPassword(next))
  await c.env.STORAGE.delete(KV.MUST_CHANGE_PASSWORD)
  return c.redirect('/?message=密码已修改', 302)
})
```

### Step 8.5 routes/system.ts

- [ ] **Step 8.5.1: 写入 `src/routes/system.ts`**

```ts
import { Hono } from 'hono'
import type { Env, Variables } from '../env'
import { runCheck } from '../services/checker'

export const systemRoute = new Hono<{ Bindings: Env; Variables: Variables }>()

systemRoute.get('/check-updates', async (c) => {
  const r = await runCheck(c.env)
  return c.json(r)
})

systemRoute.get('/health', (c) =>
  c.json({ status: 'ok', timestamp: new Date().toISOString() }),
)
```

### Step 8.6 routes/index.ts re-export

- [ ] **Step 8.6.1: 写入 `src/routes/index.ts`**

```ts
export { loginRoute, logoutRoute } from './auth'
export { dashboardRoute } from './dashboard'
export { reposRoute } from './repos'
export { settingsRoute } from './settings'
export { systemRoute } from './system'
```

### Step 8.7 接入 src/index.ts

- [ ] **Step 8.7.1: 用以下内容**替换** `src/index.ts`**

```ts
import { Hono } from 'hono'
import type { Env, Variables } from './env'
import { runMigrations } from './storage/migration'
import { authMiddleware } from './auth/middleware'
import { runCron } from './services/cron'
import {
  loginRoute, logoutRoute,
  dashboardRoute, reposRoute, settingsRoute, systemRoute,
} from './routes'

const app = new Hono<{ Bindings: Env; Variables: Variables }>()

app.use('*', async (c, next) => {
  await runMigrations(c.env)
  return next()
})

app.route('/login', loginRoute)
app.route('/logout', logoutRoute)

app.use('/*', authMiddleware)

app.route('/', dashboardRoute)
app.route('/repos', reposRoute)
app.route('/settings', settingsRoute)
app.route('/', systemRoute)

export default {
  fetch: app.fetch,
  scheduled: (_event: ScheduledEvent, env: Env, ctx: ExecutionContext) =>
    ctx.waitUntil((async () => {
      await runMigrations(env)
      await runCron(env)
    })()),
}
```

### Step 8.8 集成测试 auth-flow

- [ ] **Step 8.8.1: 写入 `test/integration/auth-flow.test.ts`**

```ts
import { env, SELF } from 'cloudflare:test'
import { beforeEach, describe, expect, it } from 'vitest'
import { KV } from '../../src/storage/keys'

async function clearAll() {
  const list = await env.STORAGE.list()
  for (const k of list.keys) await env.STORAGE.delete(k.name)
}

function extractSessionCookie(setCookie: string | null): string | null {
  if (!setCookie) return null
  const m = setCookie.match(/session=([^;]+)/)
  return m ? `session=${m[1]}` : null
}

describe('auth flow integration', () => {
  beforeEach(async () => { await clearAll() })

  it('未登录访问 / 跳到 /login', async () => {
    const r = await SELF.fetch('http://x/', { redirect: 'manual' })
    expect(r.status).toBe(302)
    expect(r.headers.get('Location')).toBe('/login')
  })

  it('默认密码登录成功 → 强制跳改密页', async () => {
    const r1 = await SELF.fetch('http://x/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'password=admin123',
      redirect: 'manual',
    })
    expect(r1.status).toBe(302)
    const cookie = extractSessionCookie(r1.headers.get('Set-Cookie'))
    expect(cookie).toBeTruthy()
    const r2 = await SELF.fetch('http://x/', {
      headers: { Cookie: cookie! }, redirect: 'manual',
    })
    expect(r2.status).toBe(302)
    expect(r2.headers.get('Location')).toBe('/settings/password?forced=1')
  })

  it('错密码 5 次后锁定', async () => {
    for (let i = 0; i < 5; i++) {
      await SELF.fetch('http://x/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'password=wrong',
      })
    }
    const r = await SELF.fetch('http://x/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'password=admin123',
    })
    expect(r.status).toBe(429)
  })

  it('记住我勾选时 cookie 带 Max-Age', async () => {
    const r = await SELF.fetch('http://x/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'password=admin123&remember_me=on',
      redirect: 'manual',
    })
    expect(r.headers.get('Set-Cookie')).toContain('Max-Age=604800')
  })

  it('未勾选记住我时 cookie 无 Max-Age', async () => {
    const r = await SELF.fetch('http://x/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'password=admin123',
      redirect: 'manual',
    })
    const sc = r.headers.get('Set-Cookie')
    expect(sc).toContain('HttpOnly')
    expect(sc).not.toMatch(/Max-Age=\d+/)
  })

  it('登出后 cookie 失效', async () => {
    const r1 = await SELF.fetch('http://x/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'password=admin123', redirect: 'manual',
    })
    const cookie = extractSessionCookie(r1.headers.get('Set-Cookie'))!
    await SELF.fetch('http://x/logout', {
      method: 'POST', headers: { Cookie: cookie }, redirect: 'manual',
    })
    const r2 = await SELF.fetch('http://x/', { headers: { Cookie: cookie }, redirect: 'manual' })
    expect(r2.status).toBe(302)
    expect(r2.headers.get('Location')).toBe('/login')
  })

  it('改密后强制标志清除，登录回到首页', async () => {
    // 登录
    const r1 = await SELF.fetch('http://x/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'password=admin123', redirect: 'manual',
    })
    const cookie = extractSessionCookie(r1.headers.get('Set-Cookie'))!
    // 改密
    await SELF.fetch('http://x/settings/password', {
      method: 'POST',
      headers: { Cookie: cookie, 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'forced=1&current_password=admin123&new_password=newpw1234&confirm_password=newpw1234',
      redirect: 'manual',
    })
    expect(await env.STORAGE.get(KV.MUST_CHANGE_PASSWORD)).toBeNull()
    const r3 = await SELF.fetch('http://x/', { headers: { Cookie: cookie }, redirect: 'manual' })
    expect(r3.status).toBe(200)
  })
})
```

### Step 8.9 校验 + 提交

- [ ] **Step 8.9.1: typecheck + 全量测试**

```bash
npm run typecheck && npm run test
```

Expected: 全部通过（含 7 个 auth-flow 集成测试）。

- [ ] **Step 8.9.2: 提交**

```bash
git add src/routes src/index.ts test/integration/auth-flow.test.ts
git commit -m "$(cat <<'EOF'
feat(routes): 接入 auth/dashboard/repos/settings/system 路由

src/index.ts 接入所有路由 + 启动迁移中间件。POST /login 实现
首次默认密码初始化、限流、签名 session、记住我。包含 7 个 auth-flow
集成测试覆盖：未登录跳转、默认密码强制改密、错密码限流、记住我
cookie 差异、登出 cookie 失效、改密后标志清除。

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Phase 9: Fork 检测 + Fork 路由 + UI 子块

**Files:**
- Create: `src/services/fork-detector.ts`
- Create: `test/unit/fork-detector.test.ts`
- Create: `src/routes/fork.ts`
- Modify: `src/views/components/repo-card.tsx`
- Modify: `src/views/dashboard.tsx`
- Modify: `src/routes/dashboard.ts`
- Modify: `src/index.ts`

### Step 9.1 fork-detector tests first

- [ ] **Step 9.1.1: 写入 `test/unit/fork-detector.test.ts`**

```ts
import { env } from 'cloudflare:test'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { detectFork } from '../../src/services/fork-detector'
import { GitHubClient } from '../../src/services/github'
import { KV } from '../../src/storage/keys'

beforeEach(async () => {
  vi.restoreAllMocks()
  const list = await env.STORAGE.list()
  for (const k of list.keys) await env.STORAGE.delete(k.name)
})

function fakeFetch(handlers: Array<{ match: RegExp; body: any; status?: number }>) {
  vi.stubGlobal('fetch', async (url: string) => {
    for (const h of handlers) {
      if (h.match.test(url)) {
        return new Response(JSON.stringify(h.body), { status: h.status ?? 200 })
      }
    }
    return new Response('not handled: ' + url, { status: 599 })
  })
}

describe('detectFork', () => {
  it('同名命中（阶段 1）', async () => {
    fakeFetch([
      { match: /\/repos\/laityts\/next\.js$/, body: { full_name: 'laityts/next.js', default_branch: 'main', fork: true, parent: { full_name: 'vercel/next.js' } } },
      { match: /\/branches\/main$/, body: { name: 'main', commit: { sha: 'a3f0e1b', commit: { author: { date: '2026-05-20T10:00:00Z' } } } } },
      { match: /\/compare\//, body: { status: 'behind', ahead_by: 0, behind_by: 12 } },
    ])
    const r = await detectFork(env, new GitHubClient('tok'), 'laityts', 'vercel', 'next.js', 'main')
    expect(r.exists).toBe(true)
    if (r.exists) {
      expect(r.fullName).toBe('laityts/next.js')
      expect(r.behind).toBe(12)
      expect(r.ahead).toBe(0)
      expect(r.canSync).toBe(true)
    }
  })

  it('同名 404 → 阶段 2 兜底全量', async () => {
    fakeFetch([
      { match: /\/repos\/laityts\/next\.js$/, body: { message: 'Not Found' }, status: 404 },
      { match: /\/users\/laityts\/repos/, body: [
        { full_name: 'laityts/my-next', default_branch: 'main', fork: true, parent: { full_name: 'vercel/next.js' } },
      ] },
      { match: /\/repos\/laityts\/my-next$/, body: { full_name: 'laityts/my-next', default_branch: 'main', fork: true, parent: { full_name: 'vercel/next.js' } } },
      { match: /\/branches\/main$/, body: { name: 'main', commit: { sha: 'sha1', commit: { author: { date: '2026-05-22T10:00:00Z' } } } } },
      { match: /\/compare\//, body: { status: 'identical', ahead_by: 0, behind_by: 0 } },
    ])
    const r = await detectFork(env, new GitHubClient('tok'), 'laityts', 'vercel', 'next.js', 'main')
    expect(r.exists).toBe(true)
    if (r.exists) expect(r.fullName).toBe('laityts/my-next')
  })

  it('parent 不匹配跳兜底 → 兜底找不到', async () => {
    fakeFetch([
      { match: /\/repos\/laityts\/next\.js$/, body: { full_name: 'laityts/next.js', fork: true, parent: { full_name: 'other/next.js' } } },
      { match: /\/users\/laityts\/repos/, body: [] },
    ])
    const r = await detectFork(env, new GitHubClient('tok'), 'laityts', 'vercel', 'next.js', 'main')
    expect(r).toEqual({ exists: false })
  })

  it('两阶段都找不到 → exists: false', async () => {
    fakeFetch([
      { match: /\/repos\/laityts\/next\.js$/, body: { message: 'Not Found' }, status: 404 },
      { match: /\/users\/laityts\/repos/, body: [] },
    ])
    const r = await detectFork(env, new GitHubClient('tok'), 'laityts', 'vercel', 'next.js', 'main')
    expect(r).toEqual({ exists: false })
  })

  it('GitHub 失败 → 返回 error', async () => {
    fakeFetch([
      { match: /\/repos\/laityts\/next\.js$/, body: { message: 'rate limit' }, status: 403 },
      { match: /\/users\/laityts\/repos/, body: { message: 'rate limit' }, status: 403 },
    ])
    const r = await detectFork(env, new GitHubClient('tok'), 'laityts', 'vercel', 'next.js', 'main')
    expect('error' in r).toBe(true)
  })

  it('缓存命中跳过阶段 1/2', async () => {
    await env.STORAGE.put(
      KV.forkCacheKey('vercel', 'next.js'),
      JSON.stringify({ forkFullName: 'laityts/next.js', parentVerified: true, fetchedAt: new Date().toISOString() }),
    )
    fakeFetch([
      { match: /\/branches\/main$/, body: { name: 'main', commit: { sha: 'cached', commit: { author: { date: '2026-05-21T10:00:00Z' } } } } },
      { match: /\/compare\//, body: { status: 'behind', ahead_by: 1, behind_by: 2 } },
    ])
    const r = await detectFork(env, new GitHubClient('tok'), 'laityts', 'vercel', 'next.js', 'main')
    expect(r.exists).toBe(true)
    if (r.exists) {
      expect(r.fullName).toBe('laityts/next.js')
      expect(r.behind).toBe(2)
    }
  })

  it('canSync 为 false 当 token 缺失', async () => {
    fakeFetch([
      { match: /\/repos\/laityts\/next\.js$/, body: { full_name: 'laityts/next.js', fork: true, parent: { full_name: 'vercel/next.js' } } },
      { match: /\/branches\/main$/, body: { name: 'main', commit: { sha: 'x', commit: { author: { date: '2026-05-20T10:00:00Z' } } } } },
      { match: /\/compare\//, body: { status: 'behind', ahead_by: 0, behind_by: 3 } },
    ])
    const r = await detectFork(env, new GitHubClient(undefined), 'laityts', 'vercel', 'next.js', 'main')
    if (r.exists) expect(r.canSync).toBe(false)
  })
})
```

- [ ] **Step 9.1.2: 跑测试 FAIL**

```bash
npm run test -- fork-detector
```

### Step 9.2 实现 fork-detector

- [ ] **Step 9.2.1: 写入 `src/services/fork-detector.ts`**

```ts
import type { Env } from '../env'
import { KV } from '../storage/keys'
import { GitHubClient, type GhRepo } from './github'

const CACHE_TTL_MS = 60 * 60 * 1000  // 1h
const CACHE_TTL_SECONDS = 3600

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

type ForkCache = {
  forkFullName: string | null
  parentVerified: boolean
  fetchedAt: string  // ISO
}

export async function detectFork(
  env: Env, gh: GitHubClient, me: string,
  upstreamOwner: string, upstreamRepo: string, upstreamBranch: string,
): Promise<ForkInfo> {
  try {
    const cacheKey = KV.forkCacheKey(upstreamOwner, upstreamRepo)
    const cached = (await env.STORAGE.get(cacheKey, 'json')) as ForkCache | null
    let forkFullName: string | null = null

    if (cached && Date.now() - Date.parse(cached.fetchedAt) < CACHE_TTL_MS) {
      forkFullName = cached.forkFullName
    } else {
      forkFullName = await findFork(env, gh, me, upstreamOwner, upstreamRepo)
      await env.STORAGE.put(cacheKey, JSON.stringify({
        forkFullName, parentVerified: true,
        fetchedAt: new Date().toISOString(),
      } satisfies ForkCache), { expirationTtl: CACHE_TTL_SECONDS })
    }

    if (!forkFullName) return { exists: false }

    const [forkOwner, forkRepoName] = forkFullName.split('/')
    if (!forkOwner || !forkRepoName) return { exists: false }

    const [branch, compare] = await Promise.all([
      gh.getBranch(forkOwner, forkRepoName, upstreamBranch),
      gh.compareCommits(
        upstreamOwner, upstreamRepo,
        upstreamBranch, `${forkOwner}:${upstreamBranch}`,
      ),
    ])

    return {
      exists: true,
      fullName: forkFullName,
      defaultBranch: upstreamBranch,
      latestCommitSha: branch.commit.sha,
      latestCommitAt: branch.commit.commit.author.date,
      ahead: compare.ahead_by,
      behind: compare.behind_by,
      canSync: compare.behind_by > 0 && gh.hasToken(),
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    return { error: msg }
  }
}

async function findFork(
  env: Env, gh: GitHubClient, me: string, upstreamOwner: string, upstreamRepo: string,
): Promise<string | null> {
  // 阶段 1：同名猜测
  try {
    const repo = await gh.getRepo(me, upstreamRepo)
    if (repo.fork && repo.parent?.full_name === `${upstreamOwner}/${upstreamRepo}`) {
      return repo.full_name
    }
  } catch (err) {
    // 404 之外的错误重新抛出
    if (!(err instanceof Error) || !/404/.test(err.message)) throw err
  }

  // 阶段 2：全量扫描
  const listKey = KV.FORK_USER_FORKS_LIST
  let forks = (await env.STORAGE.get(listKey, 'json')) as GhRepo[] | null
  if (!forks) {
    forks = await gh.listUserForks(me)
    await env.STORAGE.put(listKey, JSON.stringify(forks), { expirationTtl: CACHE_TTL_SECONDS })
  }
  const target = `${upstreamOwner}/${upstreamRepo}`
  const match = forks.find((r) => r.parent?.full_name === target)
  return match?.full_name ?? null
}
```

- [ ] **Step 9.2.2: 在 `src/services/github.ts` 末尾加一个方法**：

```ts
// 追加到 GitHubClient 类末尾（在闭合 } 之前）
hasToken(): boolean { return !!this.token }
```

- [ ] **Step 9.2.3: 测试 PASS**

```bash
npm run test -- fork-detector
```

Expected: 7 个 fork-detector 测试 PASS。

### Step 9.3 fork 路由

- [ ] **Step 9.3.1: 写入 `src/routes/fork.ts`**

```ts
import { Hono } from 'hono'
import type { Env, Variables } from '../env'
import { KV } from '../storage/keys'
import { getGithub } from '../storage/settings'
import { GitHubClient } from '../services/github'
import { resolveUsername } from '../services/username'

export const forkRoute = new Hono<{ Bindings: Env; Variables: Variables }>()

forkRoute.post('/sync', async (c) => {
  const form = await c.req.formData()
  const owner = (form.get('owner') as string) ?? ''   // 上游 owner
  const repo = (form.get('repo') as string) ?? ''
  const branch = (form.get('branch') as string) ?? 'main'
  const gh = await getGithub(c.env)
  if (!gh?.token) return c.redirect('/?error=请先配置 GitHub Token', 302)

  const username = await resolveUsername(c.env)
  if (!username) return c.redirect('/?error=无法解析 GitHub 用户名', 302)

  // 推断 fork 名（先用缓存，否则用同名）
  const cached = await c.env.STORAGE.get(KV.forkCacheKey(owner, repo), 'json') as { forkFullName: string | null } | null
  const forkFull = cached?.forkFullName ?? `${username}/${repo}`
  const [forkOwner, forkName] = forkFull.split('/')
  if (!forkOwner || !forkName) return c.redirect('/?error=fork 名解析失败', 302)

  try {
    const client = new GitHubClient(gh.token)
    await client.syncFork(forkOwner, forkName, branch)
    await c.env.STORAGE.delete(KV.forkCacheKey(owner, repo))  // 失效缓存，下次拉取新数据
    return c.redirect(`/?message=${encodeURIComponent(`已同步上游到 ${forkFull}`)}`, 302)
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    return c.redirect(`/?error=${encodeURIComponent('同步失败: ' + msg)}`, 302)
  }
})

forkRoute.post('/create', async (c) => {
  const form = await c.req.formData()
  const owner = (form.get('owner') as string) ?? ''
  const repo = (form.get('repo') as string) ?? ''
  const gh = await getGithub(c.env)
  if (!gh?.token) return c.redirect('/?error=请先配置 GitHub Token', 302)

  try {
    const client = new GitHubClient(gh.token)
    await client.createFork(owner, repo)
    await c.env.STORAGE.delete(KV.forkCacheKey(owner, repo))
    await c.env.STORAGE.delete(KV.FORK_USER_FORKS_LIST)
    return c.redirect(`/?message=${encodeURIComponent(`已 fork ${owner}/${repo}`)}`, 302)
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    return c.redirect(`/?error=${encodeURIComponent('Fork 失败: ' + msg)}`, 302)
  }
})

forkRoute.post('/refresh', async (c) => {
  const form = await c.req.formData()
  const owner = (form.get('owner') as string) ?? ''
  const repo = (form.get('repo') as string) ?? ''
  await c.env.STORAGE.delete(KV.forkCacheKey(owner, repo))
  await c.env.STORAGE.delete(KV.FORK_USER_FORKS_LIST)
  return c.redirect(`/?message=${encodeURIComponent(`已刷新 ${owner}/${repo} 的 fork 缓存`)}`, 302)
})
```

### Step 9.4 dashboard 接入 fork 数据

- [ ] **Step 9.4.1: 修改 `src/routes/dashboard.ts`，在仓库 mapping 处加上 fork 检测**

完整替换文件：

```ts
import { Hono } from 'hono'
import type { Env, Variables } from '../env'
import { getRepoList, getRepoState } from '../storage/repos'
import { getGithub, getNotifications, getTelegram } from '../storage/settings'
import { getLastCheckTime } from '../storage/cron-log'
import { resolveUsername } from '../services/username'
import { GitHubClient } from '../services/github'
import { detectFork } from '../services/fork-detector'
import { DashboardView } from '../views/dashboard'

export const dashboardRoute = new Hono<{ Bindings: Env; Variables: Variables }>()

dashboardRoute.get('/', async (c) => {
  const username = await resolveUsername(c.env)
  const repoList = await getRepoList(c.env)
  const lastCheck = await getLastCheckTime(c.env)
  const notif = await getNotifications(c.env)
  const tg = await getTelegram(c.env)
  const gh = await getGithub(c.env)
  const client = new GitHubClient(gh?.token)

  const repos = await Promise.all(repoList.map(async (entry) => {
    const state = await getRepoState(c.env, entry.owner, entry.repo, entry.branch)
    let fork = null
    if (username) {
      // 仅读缓存（避免一次请求里发起 N 次 GitHub 调用导致慢/限流）
      fork = await detectForkCachedOnly(c.env, entry.owner, entry.repo, entry.branch, client, username)
    }
    return { entry, state, fork }
  }))

  // 异步预热缓存（不阻塞响应）
  if (username && gh?.token) {
    c.executionCtx.waitUntil(prewarmForks(c.env, repoList, client, username))
  }

  const messageQuery = c.req.query('message')
  const errorQuery = c.req.query('error')
  const banner = messageQuery
    ? { type: 'success' as const, message: messageQuery }
    : errorQuery
      ? { type: 'error' as const, message: errorQuery }
      : null

  return c.html(DashboardView({
    username,
    banner,
    stats: {
      repoCount: repoList.length,
      lastCheck,
      cronEnabled: notif.cronEnabled,
      githubUser: username || (gh?.token ? '(检测中)' : '(未配置)'),
    },
    repos,
    settings: { telegram: tg, github: gh, notifications: notif },
  }) as unknown as string)
})

async function detectForkCachedOnly(
  env: Env,
  upstreamOwner: string, upstreamRepo: string, upstreamBranch: string,
  client: GitHubClient, me: string,
) {
  // 在 dashboard 渲染时仅使用缓存；首次访问没有缓存就显示"检测中"
  const key = `fork:cache:${upstreamOwner}:${upstreamRepo}`
  const cached = await env.STORAGE.get(key, 'json') as any
  if (!cached) return { error: '检测中…' }
  if (!cached.forkFullName) return { exists: false }
  // 缓存命中，再补全 ahead/behind（一次请求）
  return detectFork(env, client, me, upstreamOwner, upstreamRepo, upstreamBranch)
}

async function prewarmForks(
  env: Env, repos: Array<{ owner: string; repo: string; branch: string }>,
  client: GitHubClient, me: string,
) {
  for (const r of repos) {
    try { await detectFork(env, client, me, r.owner, r.repo, r.branch) } catch {}
  }
}
```

### Step 9.5 dashboard 视图传入 fork

- [ ] **Step 9.5.1: 在 `src/views/dashboard.tsx` 中扩展 RepoCardData 引用**

把 `import { renderRepoCard, type RepoCardData } from './components/repo-card'` 这一行不变；改用从 repo-card 重新导出的、扩展过的 RepoCardData（下一步会改）。

- [ ] **Step 9.5.2: 替换 `src/views/components/repo-card.tsx` 全文**

```tsx
/** @jsxImportSource hono/jsx */
import type { RepoEntry, RepoState } from '../../storage/repos'
import type { ForkInfo } from '../../services/fork-detector'
import { escapeHtml } from '../layout'
import { relativeTime } from '../../lib/time'

export type RepoCardData = {
  entry: RepoEntry
  state: RepoState | null
  fork: ForkInfo | null
}

export function renderRepoCard(data: RepoCardData): string {
  const { entry, state, fork } = data
  const lastInfo = state
    ? `上次提交 <code>${escapeHtml(state.lastSha.substring(0, 7))}</code> · ${escapeHtml(relativeTime(new Date(state.lastCheckedAt)))}`
    : '尚未检查过'

  return `
    <div class="repo-card" data-repo="${escapeHtml(entry.owner)}/${escapeHtml(entry.repo)}" data-branch="${escapeHtml(entry.branch)}">
      <div class="repo-header">
        <div>
          <div style="font-weight: 600;">
            <a href="https://github.com/${escapeHtml(entry.owner)}/${escapeHtml(entry.repo)}" target="_blank" rel="noopener">
              ${escapeHtml(entry.owner)}/${escapeHtml(entry.repo)}
            </a>
            <span class="branch-tag">${escapeHtml(entry.branch)}</span>
          </div>
          <div class="muted" style="margin-top: 4px;">${lastInfo}</div>
        </div>
        <form method="post" action="/repos/delete" onsubmit="return confirm('确定删除该监控？')">
          <input type="hidden" name="owner" value="${escapeHtml(entry.owner)}" />
          <input type="hidden" name="repo" value="${escapeHtml(entry.repo)}" />
          <input type="hidden" name="branch" value="${escapeHtml(entry.branch)}" />
          <button class="btn small danger" type="submit">删除</button>
        </form>
      </div>
      ${renderForkSection(entry, fork)}
    </div>
  `
}

function renderForkSection(entry: RepoEntry, fork: ForkInfo | null): string {
  if (!fork) {
    return ''
  }
  const baseForm = `
    <input type="hidden" name="owner" value="${escapeHtml(entry.owner)}" />
    <input type="hidden" name="repo" value="${escapeHtml(entry.repo)}" />
    <input type="hidden" name="branch" value="${escapeHtml(entry.branch)}" />
  `

  if ('error' in fork) {
    return `
      <div class="fork-section warning">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div>
            <div class="muted" style="font-size: 12px;">🍴 我的 Fork</div>
            <div style="font-size: 13px;">⚠ ${escapeHtml(fork.error)}</div>
          </div>
          <form method="post" action="/fork/refresh">${baseForm}<button class="btn small" type="submit">重试</button></form>
        </div>
      </div>
    `
  }

  if (!fork.exists) {
    return `
      <div class="fork-section">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div>
            <div class="muted" style="font-size: 12px;">🍴 我的 Fork</div>
            <div class="muted" style="font-size: 13px;">你还没有 fork 这个仓库</div>
          </div>
          <form method="post" action="/fork/create" onsubmit="return confirm('确定 fork 此仓库？')">
            ${baseForm}<button class="btn small accent" type="submit">Fork 此仓库 →</button>
          </form>
        </div>
      </div>
    `
  }

  const behindLabel = fork.behind > 0 ? `<span style="color: var(--warning);">落后 ${fork.behind}</span>` : `落后 ${fork.behind}`
  const aheadLabel = `领先 ${fork.ahead}`

  return `
    <div class="fork-section">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <div>
          <div class="muted" style="font-size: 12px;">🍴 我的 Fork</div>
          <div style="font-weight: 500;">
            <a href="https://github.com/${escapeHtml(fork.fullName)}" target="_blank" rel="noopener">${escapeHtml(fork.fullName)}</a>
            <span class="muted" style="font-size: 12px;">✓</span>
          </div>
          <div class="muted" style="font-size: 12px; margin-top: 2px;">
            ${behindLabel} · ${aheadLabel} · 最新 <code>${escapeHtml(fork.latestCommitSha.substring(0, 7))}</code> · ${escapeHtml(relativeTime(new Date(fork.latestCommitAt)))}
          </div>
        </div>
        <div style="display:flex; gap:8px;">
          ${fork.canSync ? `
            <form method="post" action="/fork/sync" onsubmit="return confirm('确定同步上游到 ${escapeHtml(fork.fullName)}？')">
              ${baseForm}<button class="btn small primary" type="submit">同步上游</button>
            </form>` : ''}
          <a class="btn small" href="https://github.com/${escapeHtml(fork.fullName)}" target="_blank" rel="noopener">↗</a>
        </div>
      </div>
    </div>
  `
}
```

### Step 9.6 接入 fork 路由

- [ ] **Step 9.6.1: 修改 `src/routes/index.ts`**

```ts
export { loginRoute, logoutRoute } from './auth'
export { dashboardRoute } from './dashboard'
export { reposRoute } from './repos'
export { settingsRoute } from './settings'
export { systemRoute } from './system'
export { forkRoute } from './fork'
```

- [ ] **Step 9.6.2: 修改 `src/index.ts` 接入 forkRoute**

把 `import {` 这一行 import 的列表里加入 `forkRoute`，并在路由挂载处加：

```ts
app.route('/fork', forkRoute)
```

完整替换 `src/index.ts`：

```ts
import { Hono } from 'hono'
import type { Env, Variables } from './env'
import { runMigrations } from './storage/migration'
import { authMiddleware } from './auth/middleware'
import { runCron } from './services/cron'
import {
  loginRoute, logoutRoute,
  dashboardRoute, reposRoute, settingsRoute, systemRoute, forkRoute,
} from './routes'

const app = new Hono<{ Bindings: Env; Variables: Variables }>()

app.use('*', async (c, next) => {
  await runMigrations(c.env)
  return next()
})

app.route('/login', loginRoute)
app.route('/logout', logoutRoute)

app.use('/*', authMiddleware)

app.route('/', dashboardRoute)
app.route('/repos', reposRoute)
app.route('/settings', settingsRoute)
app.route('/fork', forkRoute)
app.route('/', systemRoute)

export default {
  fetch: app.fetch,
  scheduled: (_event: ScheduledEvent, env: Env, ctx: ExecutionContext) =>
    ctx.waitUntil((async () => {
      await runMigrations(env)
      await runCron(env)
    })()),
}
```

### Step 9.7 校验 + 提交

- [ ] **Step 9.7.1: typecheck + 全量测试**

```bash
npm run typecheck && npm run test
```

Expected: 全绿。

- [ ] **Step 9.7.2: 提交**

```bash
git add src/services/fork-detector.ts src/services/github.ts src/routes/fork.ts src/routes/index.ts src/routes/dashboard.ts src/views/components/repo-card.tsx src/index.ts test/unit/fork-detector.test.ts
git commit -m "$(cat <<'EOF'
feat(fork): 检测我的 fork 并在仓库卡片展示同步/Fork 按钮

- services/fork-detector: 同名校验 → 全量扫描兜底，1h KV 缓存
- routes/fork: /fork/sync (merge-upstream) /fork/create /fork/refresh
- views/components/repo-card: 三种状态（有 fork / 无 fork / 检测失败）
- dashboard: 仅从缓存读 fork 信息，缺失时 waitUntil 异步预热

含 7 个 fork-detector 单元测试（mock fetch）。

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Phase 10: README 更新

**Files:**
- Modify: `README.md`

### Step 10.1 更新 README

- [ ] **Step 10.1.1: 替换 `README.md` 中的关键部分**

在 README 开头「快速部署」之前加入：

```markdown
## 🛠 本地开发

```bash
npm install
npm run dev              # 本地启动 wrangler dev
npm run typecheck        # TypeScript 校验
npm run test             # 跑全部测试
npm run deploy           # 部署到 Cloudflare Workers
```

需要 Node.js ≥ 20。
```

并在 「配置指南」段里的 GitHub Token 表格下方添加：

```markdown
> ⚠️ **GitHub Token 权限**：
> - 只读监控：无需特殊权限（公开仓库）或 `public_repo`（私有仓库）
> - **「同步上游」与「Fork 此仓库」功能**：需要 `repo` 或 `public_repo` 权限
```

把「方式 A：网页控制台部署」改为：

```markdown
### 方式 A：网页控制台部署（适合不安装 CLI 的用户）

⚠️ v2.0.0 起 worker 已重构为 TypeScript 多文件，**不能直接复制单文件到网页控制台**。
推荐使用方式 B（CLI）。如确需网页部署，请先 `npm run deploy --dry-run`
或 `wrangler deploy --dry-run` 拿到 bundle 单文件再粘贴。
```

### Step 10.2 提交

- [ ] **Step 10.2.1: 提交**

```bash
git add README.md
git commit -m "$(cat <<'EOF'
docs: 更新 README 反映 TypeScript 重构

- 增加「本地开发」段落
- 标注 GitHub Token 权限要求（fork sync/create 需要 repo）
- 方式 A 部署改为 dry-run + 粘贴 bundle 的说明

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Phase 11: 删除旧 worker.js + 最终验证

**Files:**
- Delete: `worker.js`

### Step 11.1 删除 worker.js

- [ ] **Step 11.1.1: 删除旧文件**

```bash
git rm worker.js
```

- [ ] **Step 11.1.2: 验证 typecheck + 测试**

```bash
npm run typecheck && npm run test
```

Expected: 全绿。

- [ ] **Step 11.1.3: 本地 dev 验证**

```bash
npm run dev
```

打开 `http://127.0.0.1:8787`，手动测试：

- [ ] **Step 11.1.4: 浏览器验收清单**

逐条勾选（参考 spec 第 13 章）：

```
[ ] 浏览器访问 /，未登录跳 /login
[ ] 用 admin123 登录 → 跳 /settings/password?forced=1
[ ] 改密后回到 / 看到 dashboard
[ ] 「记住我」勾选 → cookie 有 Max-Age；不勾选 → 无
[ ] 错密码 5 次后锁定
[ ] 仓库列表完整、每条 fork 状态正常
[ ] 主题切换持久（cookie）
[ ] /check-updates 返回 200 JSON
```

按 Ctrl+C 退出 dev server。

- [ ] **Step 11.1.5: 提交删除**

```bash
git commit -m "$(cat <<'EOF'
chore: 删除旧 worker.js（已被 src/ 完全取代）

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

### Step 11.2 部署

- [ ] **Step 11.2.1: 部署前 Cloudflare 后台备份 KV**

到 Cloudflare 后台 → KV → GITHUB_MONITOR_KV → Export → 保存 CSV 到本地。

- [ ] **Step 11.2.2: 部署**

```bash
npm run deploy
```

- [ ] **Step 11.2.3: 监控部署日志**

另一终端：

```bash
wrangler tail
```

- [ ] **Step 11.2.4: 触发一次请求验证迁移**

浏览器访问线上 URL。检查 `wrangler tail` 输出包含 `🔄 开始 KV 迁移` 与 `✅ KV 迁移完成`。

- [ ] **Step 11.2.5: 验收**

按 Step 11.1.4 的浏览器验收清单逐项在线上验证。

---

## 完成

到此所有 Phase 完成。最终 git 历史应有约 10 个原子提交，每个都通过 `typecheck + test`。

总测试数（单元 + 集成）：
- 集成：migration (7) + auth-flow (7) = 14
- 单元：crypto (5) + password (4) + session (7) + rate-limit (4) + message-builder (8) + fork-detector (7) = 35
- **合计：49 个测试**
