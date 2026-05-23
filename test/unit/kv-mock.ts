import type { Env } from '../../src/env'

export type MockEnv = Env

export function makeKvMock(): MockEnv {
  const store = new Map<string, { value: string; expiresAt?: number }>()

  const ns = {
    async get(key: string, type?: 'text' | 'json') {
      const entry = store.get(key)
      if (!entry) return null
      if (entry.expiresAt && entry.expiresAt < Date.now()) {
        store.delete(key)
        return null
      }
      return type === 'json' ? JSON.parse(entry.value) : entry.value
    },
    async put(key: string, value: string, opts?: { expirationTtl?: number }) {
      const expiresAt = opts?.expirationTtl
        ? Date.now() + opts.expirationTtl * 1000
        : undefined
      const entry: { value: string; expiresAt?: number } = expiresAt
        ? { value, expiresAt }
        : { value }
      store.set(key, entry)
    },
    async delete(key: string) {
      store.delete(key)
    },
    async list({ prefix }: { prefix?: string; cursor?: string } = {}) {
      const keys = [...store.keys()]
        .filter((k) => !prefix || k.startsWith(prefix))
        .map((name) => ({ name }))
      return { keys, list_complete: true, cursor: undefined as string | undefined }
    },
  } as unknown as KVNamespace

  return { STORAGE: ns }
}
