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
