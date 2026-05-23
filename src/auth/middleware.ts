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

  const mustChange = await c.env.STORAGE.get(KV.MUST_CHANGE_PASSWORD)
  if (mustChange === '1' && !FORCE_PASSWORD_ALLOWLIST.has(c.req.path)) {
    return c.redirect('/settings/password?forced=1', 302)
  }

  return next()
}

export function clientIp(c: { req: { header: (k: string) => string | undefined } }): string {
  return c.req.header('CF-Connecting-IP') ?? '0.0.0.0'
}
