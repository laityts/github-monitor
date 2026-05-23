import { Hono } from 'hono'
import type { Env, Variables } from '../env'
import { getRepoList, getRepoState } from '../storage/repos'
import { getGithub, getNotifications, getTelegram } from '../storage/settings'
import { getLastCheckTime } from '../storage/cron-log'
import { resolveUsername } from '../services/username'
import { GitHubClient } from '../services/github'
import { detectFork, type ForkInfo } from '../services/fork-detector'
import { KV } from '../storage/keys'
import { DashboardView } from '../views/dashboard'

export const dashboardRoute = new Hono<{ Bindings: Env; Variables: Variables }>()

dashboardRoute.get('/', async (c) => {
  const username = await resolveUsername(c.env)
  const repoList = await getRepoList(c.env)
  const lastCheck = await getLastCheckTime(c.env)
  const notif = await getNotifications(c.env)
  const tg = await getTelegram(c.env)
  const gh = await getGithub(c.env)
  const client = new GitHubClient(gh?.token)

  const repos = await Promise.all(repoList.map(async (entry) => {
    const state = await getRepoState(c.env, entry.owner, entry.repo, entry.branch)
    let fork: ForkInfo | null = null
    if (username) {
      fork = await detectForkCachedOnly(c.env, entry.owner, entry.repo, entry.branch, client, username)
    }
    return { entry, state, fork }
  }))

  if (username && gh?.token) {
    c.executionCtx.waitUntil(prewarmForks(c.env, repoList, client, username))
  }

  const messageQuery = c.req.query('message')
  const errorQuery = c.req.query('error')
  const banner = messageQuery
    ? { type: 'success' as const, message: messageQuery }
    : errorQuery
      ? { type: 'error' as const, message: errorQuery }
      : null

  return c.html(DashboardView({
    username,
    banner,
    stats: {
      repoCount: repoList.length,
      lastCheck,
      cronEnabled: notif.cronEnabled,
      githubUser: username || (gh?.token ? '(检测中)' : '(未配置)'),
    },
    repos,
    settings: { telegram: tg, github: gh, notifications: notif },
  }) as unknown as string)
})

async function detectForkCachedOnly(
  env: Env,
  upstreamOwner: string, upstreamRepo: string, upstreamBranch: string,
  client: GitHubClient, me: string,
): Promise<ForkInfo> {
  const cached = await env.STORAGE.get(KV.forkCacheKey(upstreamOwner, upstreamRepo), 'json') as { forkFullName: string | null } | null
  if (!cached) return { error: '检测中…' }
  if (!cached.forkFullName) return { exists: false }
  return detectFork(env, client, me, upstreamOwner, upstreamRepo, upstreamBranch)
}

async function prewarmForks(
  env: Env, repos: Array<{ owner: string; repo: string; branch: string }>,
  client: GitHubClient, me: string,
) {
  for (const r of repos) {
    try { await detectFork(env, client, me, r.owner, r.repo, r.branch) } catch {}
  }
}
