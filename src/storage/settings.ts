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
