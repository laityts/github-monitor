import { describe, expect, it, beforeEach } from 'vitest'
import { runMigrations } from '../../src/storage/migration'
import { KV, LEGACY, MIGRATION_VERSION } from '../../src/storage/keys'
import { makeKvMock, type MockEnv } from './kv-mock'

let env: MockEnv

beforeEach(() => { env = makeKvMock() })

describe('storage/migration', () => {
  it('迁移密码、Telegram、GitHub、通知开关', async () => {
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
