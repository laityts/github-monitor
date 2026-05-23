import { Hono } from 'hono'
import type { Env, Variables } from '../env'
import { KV } from '../storage/keys'
import { getGithub } from '../storage/settings'
import { GitHubClient } from '../services/github'
import { resolveUsername } from '../services/username'

export const forkRoute = new Hono<{ Bindings: Env; Variables: Variables }>()

forkRoute.post('/sync', async (c) => {
  const form = await c.req.formData()
  const owner = (form.get('owner') as string) ?? ''
  const repo = (form.get('repo') as string) ?? ''
  const branch = (form.get('branch') as string) ?? 'main'
  const gh = await getGithub(c.env)
  if (!gh?.token) return c.redirect('/?error=请先配置 GitHub Token', 302)

  const username = await resolveUsername(c.env)
  if (!username) return c.redirect('/?error=无法解析 GitHub 用户名', 302)

  const cached = await c.env.STORAGE.get(KV.forkCacheKey(owner, repo), 'json') as { forkFullName: string | null } | null
  const forkFull = cached?.forkFullName ?? `${username}/${repo}`
  const [forkOwner, forkName] = forkFull.split('/')
  if (!forkOwner || !forkName) return c.redirect('/?error=fork 名解析失败', 302)

  try {
    const client = new GitHubClient(gh.token)
    await client.syncFork(forkOwner, forkName, branch)
    await c.env.STORAGE.delete(KV.forkCacheKey(owner, repo))
    return c.redirect(`/?message=${encodeURIComponent(`已同步上游到 ${forkFull}`)}`, 302)
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    return c.redirect(`/?error=${encodeURIComponent('同步失败: ' + msg)}`, 302)
  }
})

forkRoute.post('/create', async (c) => {
  const form = await c.req.formData()
  const owner = (form.get('owner') as string) ?? ''
  const repo = (form.get('repo') as string) ?? ''
  const gh = await getGithub(c.env)
  if (!gh?.token) return c.redirect('/?error=请先配置 GitHub Token', 302)

  try {
    const client = new GitHubClient(gh.token)
    await client.createFork(owner, repo)
    await c.env.STORAGE.delete(KV.forkCacheKey(owner, repo))
    await c.env.STORAGE.delete(KV.FORK_USER_FORKS_LIST)
    return c.redirect(`/?message=${encodeURIComponent(`已 fork ${owner}/${repo}`)}`, 302)
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    return c.redirect(`/?error=${encodeURIComponent('Fork 失败: ' + msg)}`, 302)
  }
})

forkRoute.post('/refresh', async (c) => {
  const form = await c.req.formData()
  const owner = (form.get('owner') as string) ?? ''
  const repo = (form.get('repo') as string) ?? ''
  await c.env.STORAGE.delete(KV.forkCacheKey(owner, repo))
  await c.env.STORAGE.delete(KV.FORK_USER_FORKS_LIST)
  return c.redirect(`/?message=${encodeURIComponent(`已刷新 ${owner}/${repo} 的 fork 缓存`)}`, 302)
})
