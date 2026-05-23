/** @jsxImportSource hono/jsx */
import { html, raw } from 'hono/html'
import { THEME_CSS, THEME_INIT_SCRIPT, THEME_TOGGLE_SCRIPT } from './theme'

type LayoutProps = {
  title: string
  username?: string | null
  showTopbar?: boolean
  banner?: { type: 'success' | 'error' | 'info'; message: string } | null
  footer?: { lastCheck?: string; cronEnabled?: boolean } | null
  children: any
}

export function Layout(props: LayoutProps) {
  const showTopbar = props.showTopbar !== false
  return html`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${props.title}</title>
  <script>${raw(THEME_INIT_SCRIPT)}</script>
  <style>${raw(THEME_CSS)}</style>
  <script>${raw(THEME_TOGGLE_SCRIPT)}</script>
</head>
<body>
  <div class="container">
    ${showTopbar ? raw(`
      <header class="topbar">
        <div><strong>📦 GitHub Monitor</strong></div>
        <div class="actions">
          ${props.username ? `<span class="muted">👤 ${escapeHtml(props.username)}</span>` : ''}
          <button class="btn small" type="button" onclick="toggleTheme()">🌓 主题</button>
          <form method="post" action="/logout" style="display:inline;">
            <button class="btn small" type="submit">⎋ 登出</button>
          </form>
        </div>
      </header>
    `) : ''}
    ${props.banner ? raw(renderBanner(props.banner)) : ''}
    ${props.children}
    ${props.footer ? raw(renderFooter(props.footer)) : ''}
  </div>
</body>
</html>`
}

function renderBanner(b: { type: string; message: string }): string {
  return `<div class="banner ${b.type}">${escapeHtml(b.message)}</div>`
}

function renderFooter(f: { lastCheck?: string; cronEnabled?: boolean }): string {
  return `<footer class="footer">
    上次检查: ${escapeHtml(f.lastCheck ?? '从未检查')}
    · Cron 通知: ${f.cronEnabled ? '开启' : '关闭'}
    · v2.0.0
  </footer>`
}

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!))
}
