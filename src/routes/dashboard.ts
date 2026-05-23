import { Hono } from 'hono'
import type { Env, Variables } from '../env'
import { getRepoList, getRepoState } from '../storage/repos'
import { getGithub, getNotifications, getTelegram } from '../storage/settings'
import { getLastCheckTime } from '../storage/cron-log'
import { resolveUsername } from '../services/username'
import { DashboardView } from '../views/dashboard'

export const dashboardRoute = new Hono<{ Bindings: Env; Variables: Variables }>()

dashboardRoute.get('/', async (c) => {
  const username = await resolveUsername(c.env)
  const repoList = await getRepoList(c.env)
  const lastCheck = await getLastCheckTime(c.env)
  const notif = await getNotifications(c.env)
  const tg = await getTelegram(c.env)
  const gh = await getGithub(c.env)

  const repos = await Promise.all(
    repoList.map(async (entry) => ({
      entry,
      state: await getRepoState(c.env, entry.owner, entry.repo, entry.branch),
    })),
  )

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
