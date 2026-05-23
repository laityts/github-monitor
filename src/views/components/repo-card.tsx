/** @jsxImportSource hono/jsx */
import type { RepoEntry, RepoState } from '../../storage/repos'
import { escapeHtml } from '../layout'
import { relativeTime } from '../../lib/time'

export type RepoCardData = {
  entry: RepoEntry
  state: RepoState | null
}

export function renderRepoCard(data: RepoCardData): string {
  const { entry, state } = data
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
      <!-- FORK_PLACEHOLDER -->
    </div>
  `
}
