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
