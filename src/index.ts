import { Hono } from 'hono'
import type { Env, Variables } from './env'

const app = new Hono<{ Bindings: Env; Variables: Variables }>()

app.get('/health', (c) =>
  c.json({ status: 'ok', timestamp: new Date().toISOString() })
)

export default {
  fetch: app.fetch,
  scheduled: async (_event: ScheduledEvent, _env: Env, _ctx: ExecutionContext) => {
    // 后续阶段补全
  },
}
