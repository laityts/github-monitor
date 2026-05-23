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
