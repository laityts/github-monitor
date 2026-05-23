import { Hono } from 'hono'
import type { Env, Variables } from '../env'
import { KV } from '../storage/keys'
import {
  getTelegram, getGithub, setTelegram, setGithub, setNotifications,
} from '../storage/settings'
import { GitHubClient } from '../services/github'
import { TelegramClient } from '../services/telegram'
import { hashPassword, verifyPassword } from '../auth/password'
import { ChangePasswordView } from '../views/components/change-password-form'
import { resolveUsername } from '../services/username'
import { formatShanghai } from '../lib/time'

export const settingsRoute = new Hono<{ Bindings: Env; Variables: Variables }>()

settingsRoute.post('/update', async (c) => {
  const form = await c.req.formData()
  const botToken = ((form.get('tg_bot_token') as string | null) ?? '').trim()
  const chatId = ((form.get('tg_chat_id') as string | null) ?? '').trim()
  const ghToken = ((form.get('github_token') as string | null) ?? '').trim()
  const cronEnabled = form.get('cron_notification_enabled') === 'on'

  await setTelegram(c.env, { botToken, chatId })

  const prevGh = await getGithub(c.env)
  if (ghToken) {
    await setGithub(c.env, {
      token: ghToken,
      username: prevGh && prevGh.token === ghToken ? prevGh.username : '',
      usernameFetchedAt: prevGh && prevGh.token === ghToken ? prevGh.usernameFetchedAt : '',
    })
  } else {
    await setGithub(c.env, { token: '', username: '', usernameFetchedAt: '' })
  }
  await setNotifications(c.env, { cronEnabled })
  return c.redirect('/?message=设置已保存', 302)
})

settingsRoute.post('/test-telegram', async (c) => {
  const tg = await getTelegram(c.env)
  if (!tg?.botToken || !tg?.chatId) {
    return c.redirect('/?error=请先配置 Telegram', 302)
  }
  try {
    const client = new TelegramClient(tg.botToken, tg.chatId)
    await client.send(
      `🔔 <b>测试通知</b>\n\n✅ GitHub Monitor 运行正常\n⏰ ${formatShanghai(new Date())}`,
    )
    return c.redirect('/?message=测试通知已发送', 302)
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    return c.redirect(`/?error=${encodeURIComponent('Telegram 测试失败: ' + msg)}`, 302)
  }
})

settingsRoute.post('/test-github', async (c) => {
  const gh = await getGithub(c.env)
  if (!gh?.token) return c.redirect('/?error=请先配置 GitHub Token', 302)
  try {
    const client = new GitHubClient(gh.token)
    const user = await client.getAuthenticatedUser()
    return c.redirect(`/?message=${encodeURIComponent('GitHub 连接成功，用户 ' + user.login)}`, 302)
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    return c.redirect(`/?error=${encodeURIComponent('GitHub 测试失败: ' + msg)}`, 302)
  }
})

settingsRoute.get('/password', async (c) => {
  const forced = c.req.query('forced') === '1'
  const username = await resolveUsername(c.env)
  return c.html(ChangePasswordView({ forced, username }) as unknown as string)
})

settingsRoute.post('/password', async (c) => {
  const form = await c.req.formData()
  const forced = form.get('forced') === '1'
  const current = ((form.get('current_password') as string | null) ?? '')
  const next = ((form.get('new_password') as string | null) ?? '')
  const confirm = ((form.get('confirm_password') as string | null) ?? '')
  const username = await resolveUsername(c.env)

  const fail = (msg: string) =>
    c.html(ChangePasswordView({ forced, error: msg, username }) as unknown as string, 400)

  if (next.length < 8) return fail('新密码至少 8 位')
  if (next !== confirm) return fail('两次输入的新密码不一致')

  const stored = await c.env.STORAGE.get(KV.PASSWORD_HASH)
  if (!stored || !(await verifyPassword(current, stored))) return fail('当前密码错误')

  await c.env.STORAGE.put(KV.PASSWORD_HASH, await hashPassword(next))
  await c.env.STORAGE.delete(KV.MUST_CHANGE_PASSWORD)
  return c.redirect('/?message=密码已修改', 302)
})
