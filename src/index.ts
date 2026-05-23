import { Hono } from 'hono'
import type { Env, Variables } from './env'
import { runMigrations } from './storage/migration'
import { authMiddleware } from './auth/middleware'
import { runCron } from './services/cron'
import {
  loginRoute, logoutRoute,
  dashboardRoute, reposRoute, settingsRoute, systemRoute, forkRoute,
} from './routes'

const app = new Hono<{ Bindings: Env; Variables: Variables }>()

app.use('*', async (c, next) => {
  await runMigrations(c.env)
  return next()
})

app.route('/login', loginRoute)
app.route('/logout', logoutRoute)

app.use('/*', authMiddleware)

app.route('/', dashboardRoute)
app.route('/repos', reposRoute)
app.route('/settings', settingsRoute)
app.route('/fork', forkRoute)
app.route('/', systemRoute)

export default {
  fetch: app.fetch,
  scheduled: (_event: ScheduledEvent, env: Env, ctx: ExecutionContext) =>
    ctx.waitUntil((async () => {
      await runMigrations(env)
      await runCron(env)
    })()),
}
