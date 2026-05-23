/** @jsxImportSource hono/jsx */
import { raw } from 'hono/html'
import { Layout } from './layout'
import { renderRepoCard, type RepoCardData } from './components/repo-card'
import { renderSettingsPanel, type SettingsPanelData } from './components/settings-panel'

export type DashboardData = {
  username: string | null
  banner: { type: 'success' | 'error' | 'info'; message: string } | null
  stats: {
    repoCount: number
    lastCheck: string
    cronEnabled: boolean
    githubUser: string
  }
  repos: RepoCardData[]
  settings: SettingsPanelData
}

export function DashboardView(d: DashboardData) {
  const body = raw(`
    <div class="stats">
      <div class="stat"><div class="label">监控仓库</div><div class="value">${d.stats.repoCount}</div></div>
      <div class="stat"><div class="label">上次检查</div><div class="value" style="font-size: 14px;">${escapeAttr(d.stats.lastCheck)}</div></div>
      <div class="stat"><div class="label">Cron 通知</div><div class="value" style="font-size: 16px;">${d.stats.cronEnabled ? '✅ 开启' : '⏸️ 关闭'}</div></div>
      <div class="stat"><div class="label">GitHub 用户</div><div class="value" style="font-size: 16px;">${escapeAttr(d.stats.githubUser)}</div></div>
    </div>

    <div class="card">
      <h2 style="margin-bottom: 12px;">添加监控仓库</h2>
      <form method="post" action="/repos/add">
        <div class="form-row">
          <div style="flex: 2 1 320px;">
            <label>仓库（owner/repo）</label>
            <input name="repo_full_name" placeholder="vercel/next.js" required />
          </div>
          <div>
            <label>分支</label>
            <input name="branch" placeholder="main" />
          </div>
        </div>
        <div style="margin-top: 12px;">
          <button class="btn primary" type="submit">添加</button>
        </div>
      </form>
    </div>

    <div class="card">
      <h2 style="margin-bottom: 12px;">监控列表</h2>
      ${d.repos.length === 0 ? '<p class="muted">暂无监控仓库</p>' : d.repos.map(renderRepoCard).join('')}
    </div>

    ${renderSettingsPanel(d.settings)}

    <div class="card">
      <h2 style="margin-bottom: 12px;">操作</h2>
      <div style="display:flex; gap:8px; flex-wrap:wrap;">
        <form method="post" action="/repos/check"><button class="btn" type="submit">立即检查更新</button></form>
        <a class="btn" href="/settings/password">修改密码</a>
      </div>
    </div>
  `)
  return Layout({
    title: '仪表盘 · GitHub Monitor',
    username: d.username,
    banner: d.banner,
    footer: { lastCheck: d.stats.lastCheck, cronEnabled: d.stats.cronEnabled },
    children: body,
  })
}

function escapeAttr(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!))
}
