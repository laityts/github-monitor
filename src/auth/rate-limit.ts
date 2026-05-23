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
