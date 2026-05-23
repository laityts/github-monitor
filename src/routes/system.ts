import { Hono } from 'hono'
import type { Env, Variables } from '../env'
import { runCheck } from '../services/checker'

export const systemRoute = new Hono<{ Bindings: Env; Variables: Variables }>()

systemRoute.get('/check-updates', async (c) => {
  const r = await runCheck(c.env)
  return c.json(r)
})

systemRoute.get('/health', (c) =>
  c.json({ status: 'ok', timestamp: new Date().toISOString() }),
)
