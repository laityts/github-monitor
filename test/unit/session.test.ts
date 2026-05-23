import { describe, expect, it, beforeEach } from 'vitest'
import { makeKvMock, type MockEnv } from './kv-mock'
import { createSession, verifySessionCookie, deleteSessionCookie, buildSessionCookie } from '../../src/auth/session'
import { KV } from '../../src/storage/keys'

let env: MockEnv

beforeEach(async () => {
  env = makeKvMock()
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
