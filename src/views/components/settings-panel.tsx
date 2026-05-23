/** @jsxImportSource hono/jsx */
import type { TelegramSettings, GithubSettings, NotificationSettings } from '../../storage/settings'
import { escapeHtml } from '../layout'

export type SettingsPanelData = {
  telegram: TelegramSettings | null
  github: GithubSettings | null
  notifications: NotificationSettings
}

export function renderSettingsPanel(d: SettingsPanelData): string {
  return `
    <div class="card">
      <h2 style="margin-bottom: 12px;">系统设置</h2>
      <form method="post" action="/settings/update">
        <div class="form-row">
          <div>
            <label>Telegram Bot Token</label>
            <input name="tg_bot_token" value="${escapeHtml(d.telegram?.botToken ?? '')}" />
          </div>
          <div>
            <label>Telegram Chat ID</label>
            <input name="tg_chat_id" value="${escapeHtml(d.telegram?.chatId ?? '')}" />
          </div>
        </div>
        <div class="form-row" style="margin-top: 12px;">
          <div>
            <label>GitHub Token（fork sync/create 需 repo / public_repo 权限）</label>
            <input name="github_token" value="${escapeHtml(d.github?.token ?? '')}" autocomplete="off" />
          </div>
        </div>
        <label style="display:flex; align-items:center; gap:8px; margin: 12px 0;">
          <input type="checkbox" name="cron_notification_enabled" ${d.notifications.cronEnabled ? 'checked' : ''} style="width:auto;" />
          开启定时任务报告（关闭后仍会发送 commit 通知与错误通知）
        </label>
        <div style="display:flex; gap: 8px;">
          <button class="btn primary" type="submit">保存设置</button>
        </div>
      </form>
      <div style="display:flex; gap: 8px; margin-top: 12px; flex-wrap: wrap;">
        <form method="post" action="/settings/test-telegram"><button class="btn small" type="submit">测试 Telegram</button></form>
        <form method="post" action="/settings/test-github"><button class="btn small" type="submit">测试 GitHub</button></form>
        <form method="post" action="/repos/clear" onsubmit="return confirm('确定清空所有监控？')">
          <button class="btn small danger" type="submit">清空所有仓库</button>
        </form>
      </div>
    </div>
  `
}
