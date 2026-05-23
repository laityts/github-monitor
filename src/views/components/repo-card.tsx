/** @jsxImportSource hono/jsx */
import type { RepoEntry, RepoState } from '../../storage/repos'
import type { ForkInfo } from '../../services/fork-detector'
import { escapeHtml } from '../layout'
import { relativeTime } from '../../lib/time'

export type RepoCardData = {
  entry: RepoEntry
  state: RepoState | null
  fork: ForkInfo | null
}

export function renderRepoCard(data: RepoCardData): string {
  const { entry, state, fork } = data
  const lastInfo = state
    ? `上次提交 <code>${escapeHtml(state.lastSha.substring(0, 7))}</code> · ${escapeHtml(relativeTime(new Date(state.lastCheckedAt)))}`
    : '尚未检查过'

  return `
    <div class="repo-card" data-repo="${escapeHtml(entry.owner)}/${escapeHtml(entry.repo)}" data-branch="${escapeHtml(entry.branch)}">
      <div class="repo-header">
        <div>
          <div style="font-weight: 600;">
            <a href="https://github.com/${escapeHtml(entry.owner)}/${escapeHtml(entry.repo)}" target="_blank" rel="noopener">
              ${escapeHtml(entry.owner)}/${escapeHtml(entry.repo)}
            </a>
            <span class="branch-tag">${escapeHtml(entry.branch)}</span>
          </div>
          <div class="muted" style="margin-top: 4px;">${lastInfo}</div>
        </div>
        <form method="post" action="/repos/delete" onsubmit="return confirm('确定删除该监控？')">
          <input type="hidden" name="owner" value="${escapeHtml(entry.owner)}" />
          <input type="hidden" name="repo" value="${escapeHtml(entry.repo)}" />
          <input type="hidden" name="branch" value="${escapeHtml(entry.branch)}" />
          <button class="btn small danger" type="submit">删除</button>
        </form>
      </div>
      ${renderForkSection(entry, fork)}
    </div>
  `
}

function renderForkSection(entry: RepoEntry, fork: ForkInfo | null): string {
  if (!fork) {
    return ''
  }
  const baseForm = `
    <input type="hidden" name="owner" value="${escapeHtml(entry.owner)}" />
    <input type="hidden" name="repo" value="${escapeHtml(entry.repo)}" />
    <input type="hidden" name="branch" value="${escapeHtml(entry.branch)}" />
  `

  if ('error' in fork) {
    return `
      <div class="fork-section warning">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div>
            <div class="muted" style="font-size: 12px;">🍴 我的 Fork</div>
            <div style="font-size: 13px;">⚠ ${escapeHtml(fork.error)}</div>
          </div>
          <form method="post" action="/fork/refresh">${baseForm}<button class="btn small" type="submit">重试</button></form>
        </div>
      </div>
    `
  }

  if (!fork.exists) {
    return `
      <div class="fork-section">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div>
            <div class="muted" style="font-size: 12px;">🍴 我的 Fork</div>
            <div class="muted" style="font-size: 13px;">你还没有 fork 这个仓库</div>
          </div>
          <form method="post" action="/fork/create" onsubmit="return confirm('确定 fork 此仓库？')">
            ${baseForm}<button class="btn small accent" type="submit">Fork 此仓库 →</button>
          </form>
        </div>
      </div>
    `
  }

  const behindLabel = fork.behind > 0 ? `<span style="color: var(--warning);">落后 ${fork.behind}</span>` : `落后 ${fork.behind}`
  const aheadLabel = `领先 ${fork.ahead}`

  return `
    <div class="fork-section">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <div>
          <div class="muted" style="font-size: 12px;">🍴 我的 Fork</div>
          <div style="font-weight: 500;">
            <a href="https://github.com/${escapeHtml(fork.fullName)}" target="_blank" rel="noopener">${escapeHtml(fork.fullName)}</a>
            <span class="muted" style="font-size: 12px;">✓</span>
          </div>
          <div class="muted" style="font-size: 12px; margin-top: 2px;">
            ${behindLabel} · ${aheadLabel} · 最新 <code>${escapeHtml(fork.latestCommitSha.substring(0, 7))}</code> · ${escapeHtml(relativeTime(new Date(fork.latestCommitAt)))}
          </div>
        </div>
        <div style="display:flex; gap:8px;">
          ${fork.canSync ? `
            <form method="post" action="/fork/sync" onsubmit="return confirm('确定同步上游到 ${escapeHtml(fork.fullName)}？')">
              ${baseForm}<button class="btn small primary" type="submit">同步上游</button>
            </form>` : ''}
          <a class="btn small" href="https://github.com/${escapeHtml(fork.fullName)}" target="_blank" rel="noopener">↗</a>
        </div>
      </div>
    </div>
  `
}
