/** @jsxImportSource hono/jsx */
import { raw } from 'hono/html'
import { Layout } from './layout'

export function LoginView(opts: { error?: string; locked?: { remainingMs: number } | null }) {
  let banner = null as { type: 'error' | 'info'; message: string } | null
  if (opts.locked) {
    const min = Math.ceil(opts.locked.remainingMs / 60000)
    banner = { type: 'error', message: `账户已锁定，剩余 ${min} 分钟` }
  } else if (opts.error) {
    banner = { type: 'error', message: opts.error }
  }
  const body = raw(`
    <div class="card" style="max-width: 420px; margin: 80px auto;">
      <h1 style="font-size: 22px; margin-bottom: 4px;">登录</h1>
      <p class="muted" style="margin-bottom: 20px;">GitHub Monitor 管理面板</p>
      <form method="post" action="/login">
        <label for="password">密码</label>
        <input id="password" type="password" name="password" autocomplete="current-password" required autofocus />
        <label style="display:flex; align-items:center; gap:8px; margin: 12px 0; font-size: 13px;">
          <input type="checkbox" name="remember_me" style="width:auto;" />
          记住我（7 天）
        </label>
        <button class="btn primary" type="submit" style="width:100%;">登录</button>
      </form>
    </div>
  `)
  return Layout({
    title: '登录 · GitHub Monitor',
    showTopbar: false,
    banner,
    children: body,
  })
}
