import { beforeEach, describe, expect, it, vi } from 'vitest'
import { makeKvMock, type MockEnv } from './kv-mock'
import { detectFork } from '../../src/services/fork-detector'
import { GitHubClient } from '../../src/services/github'
import { KV } from '../../src/storage/keys'

let env: MockEnv

beforeEach(() => {
  vi.restoreAllMocks()
  env = makeKvMock()
})

function fakeFetch(handlers: Array<{ match: RegExp; body: any; status?: number }>) {
  vi.stubGlobal('fetch', async (url: string) => {
    for (const h of handlers) {
      if (h.match.test(url)) {
        return new Response(JSON.stringify(h.body), { status: h.status ?? 200 })
      }
    }
    return new Response('not handled: ' + url, { status: 599 })
  })
}

describe('detectFork', () => {
  it('同名命中（阶段 1）', async () => {
    fakeFetch([
      { match: /\/repos\/laityts\/next\.js$/, body: { full_name: 'laityts/next.js', default_branch: 'main', fork: true, parent: { full_name: 'vercel/next.js' } } },
      { match: /\/branches\/main$/, body: { name: 'main', commit: { sha: 'a3f0e1b', commit: { author: { date: '2026-05-20T10:00:00Z' } } } } },
      { match: /\/compare\//, body: { status: 'behind', ahead_by: 0, behind_by: 12 } },
    ])
    const r = await detectFork(env, new GitHubClient('tok'), 'laityts', 'vercel', 'next.js', 'main')
    expect('exists' in r && r.exists).toBe(true)
    if ('exists' in r && r.exists) {
      expect(r.fullName).toBe('laityts/next.js')
      expect(r.behind).toBe(12)
      expect(r.ahead).toBe(0)
      expect(r.canSync).toBe(true)
    }
  })

  it('同名 404 → 阶段 2 兜底全量', async () => {
    fakeFetch([
      { match: /\/repos\/laityts\/next\.js$/, body: { message: 'Not Found' }, status: 404 },
      { match: /\/users\/laityts\/repos/, body: [
        { full_name: 'laityts/my-next', default_branch: 'main', fork: true, parent: { full_name: 'vercel/next.js' } },
      ] },
      { match: /\/repos\/laityts\/my-next$/, body: { full_name: 'laityts/my-next', default_branch: 'main', fork: true, parent: { full_name: 'vercel/next.js' } } },
      { match: /\/branches\/main$/, body: { name: 'main', commit: { sha: 'sha1', commit: { author: { date: '2026-05-22T10:00:00Z' } } } } },
      { match: /\/compare\//, body: { status: 'identical', ahead_by: 0, behind_by: 0 } },
    ])
    const r = await detectFork(env, new GitHubClient('tok'), 'laityts', 'vercel', 'next.js', 'main')
    expect('exists' in r && r.exists).toBe(true)
    if ('exists' in r && r.exists) expect(r.fullName).toBe('laityts/my-next')
  })

  it('parent 不匹配跳兜底 → 兜底找不到', async () => {
    fakeFetch([
      { match: /\/repos\/laityts\/next\.js$/, body: { full_name: 'laityts/next.js', fork: true, parent: { full_name: 'other/next.js' } } },
      { match: /\/users\/laityts\/repos/, body: [] },
    ])
    const r = await detectFork(env, new GitHubClient('tok'), 'laityts', 'vercel', 'next.js', 'main')
    expect(r).toEqual({ exists: false })
  })

  it('两阶段都找不到 → exists: false', async () => {
    fakeFetch([
      { match: /\/repos\/laityts\/next\.js$/, body: { message: 'Not Found' }, status: 404 },
      { match: /\/users\/laityts\/repos/, body: [] },
    ])
    const r = await detectFork(env, new GitHubClient('tok'), 'laityts', 'vercel', 'next.js', 'main')
    expect(r).toEqual({ exists: false })
  })

  it('GitHub 失败 → 返回 error', async () => {
    fakeFetch([
      { match: /\/repos\/laityts\/next\.js$/, body: { message: 'rate limit' }, status: 403 },
      { match: /\/users\/laityts\/repos/, body: { message: 'rate limit' }, status: 403 },
    ])
    const r = await detectFork(env, new GitHubClient('tok'), 'laityts', 'vercel', 'next.js', 'main')
    expect('error' in r).toBe(true)
  })

  it('缓存命中跳过阶段 1/2', async () => {
    await env.STORAGE.put(
      KV.forkCacheKey('vercel', 'next.js'),
      JSON.stringify({ forkFullName: 'laityts/next.js', parentVerified: true, fetchedAt: new Date().toISOString() }),
    )
    fakeFetch([
      { match: /\/branches\/main$/, body: { name: 'main', commit: { sha: 'cached', commit: { author: { date: '2026-05-21T10:00:00Z' } } } } },
      { match: /\/compare\//, body: { status: 'behind', ahead_by: 1, behind_by: 2 } },
    ])
    const r = await detectFork(env, new GitHubClient('tok'), 'laityts', 'vercel', 'next.js', 'main')
    expect('exists' in r && r.exists).toBe(true)
    if ('exists' in r && r.exists) {
      expect(r.fullName).toBe('laityts/next.js')
      expect(r.behind).toBe(2)
    }
  })

  it('canSync 为 false 当 token 缺失', async () => {
    fakeFetch([
      { match: /\/repos\/laityts\/next\.js$/, body: { full_name: 'laityts/next.js', fork: true, parent: { full_name: 'vercel/next.js' } } },
      { match: /\/branches\/main$/, body: { name: 'main', commit: { sha: 'x', commit: { author: { date: '2026-05-20T10:00:00Z' } } } } },
      { match: /\/compare\//, body: { status: 'behind', ahead_by: 0, behind_by: 3 } },
    ])
    const r = await detectFork(env, new GitHubClient(undefined), 'laityts', 'vercel', 'next.js', 'main')
    if ('exists' in r && r.exists) expect(r.canSync).toBe(false)
  })
})
