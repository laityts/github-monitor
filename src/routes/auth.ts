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
import { LoginView } from '../views/login'

const DEFAULT_PASSWORD = 'admin123'

export const loginRoute = new Hono<{ Bindings: Env; Variables: Variables }>()

loginRoute.get('/', async (c) => {
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
  const pbkdf2 = await hashPassword(DEFAULT_PASSWORD)
  await env.STORAGE.put(KV.PASSWORD_HASH, pbkdf2)
  await env.STORAGE.put(KV.MUST_CHANGE_PASSWORD, '1')
  console.log('🆕 初始化默认密码 admin123（标记强制改密）')
}
