/** @jsxImportSource hono/jsx */
import { raw } from 'hono/html'
import { Layout } from '../layout'

export function ChangePasswordView(opts: {
  forced: boolean
  error?: string
  username?: string | null
}) {
  const banner = opts.forced
    ? { type: 'info' as const, message: '检测到您正在使用默认密码，请先修改后继续使用。' }
    : opts.error
      ? { type: 'error' as const, message: opts.error }
      : null

  const body = raw(`
    <div class="card" style="max-width: 480px; margin: 40px auto;">
      <h1 style="font-size: 22px; margin-bottom: 16px;">修改密码</h1>
      <form method="post" action="/settings/password">
        ${opts.forced ? '<input type="hidden" name="forced" value="1" />' : ''}
        <label>当前密码</label>
        <input type="password" name="current_password" autocomplete="current-password" required />
        <label style="margin-top: 12px;">新密码（至少 8 位）</label>
        <input type="password" name="new_password" autocomplete="new-password" required minlength="8" />
        <label style="margin-top: 12px;">确认新密码</label>
        <input type="password" name="confirm_password" autocomplete="new-password" required minlength="8" />
        <div style="display:flex; gap: 8px; margin-top: 16px;">
          <button class="btn primary" type="submit">保存</button>
          ${opts.forced ? '' : '<a class="btn" href="/">返回</a>'}
        </div>
      </form>
    </div>
  `)
  return Layout({
    title: '修改密码 · GitHub Monitor',
    username: opts.username ?? null,
    banner,
    children: body,
  })
}
