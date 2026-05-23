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
