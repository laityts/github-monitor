import type { GhCommit } from './github'
import type { CronLog } from '../storage/cron-log'
import type { RepoEntry } from '../storage/repos'
import { formatShanghai, formatShanghaiShort } from '../lib/time'

export class TelegramError extends Error {
  constructor(public status: number, public description: string) {
    super(`Telegram API ${status}: ${description}`)
    this.name = 'TelegramError'
  }
}

export class TelegramClient {
  constructor(private botToken: string, private chatId: string) {}

  async send(text: string): Promise<void> {
    const r = await fetch(`https://api.telegram.org/bot${this.botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: this.chatId,
        text,
        parse_mode: 'HTML',
        disable_web_page_preview: false,
      }),
    })
    if (!r.ok) {
      const data = await r.json().catch(() => ({})) as { description?: string }
      throw new TelegramError(r.status, data.description ?? r.statusText)
    }
  }
}

export type ForkSummary =
  | { exists: true; fullName: string; behind: number }
  | { exists: false }
  | { error: string }

export function buildCommitNotification(
  repo: Pick<RepoEntry, 'owner' | 'repo' | 'branch'>,
  commits: GhCommit[],
  isCompleteHistory: boolean,
  fork?: ForkSummary,
): string {
  const repoUrl = `https://github.com/${repo.owner}/${repo.repo}`
  let m = `🚀 <b>代码仓库已更新！</b>\n\n`
  m += `📦 <b>仓库:</b> <a href="${repoUrl}">${repo.owner}/${repo.repo}</a>\n`
  m += `🌿 <b>分支:</b> <code>${repo.branch}</code>\n\n`

  if (commits.length === 1) {
    const c = commits[0]!
    const shortSha = c.sha.substring(0, 7)
    const firstLine = c.commit.message.split('\n')[0]
    const date = new Date(c.commit.author.date)
    m += `📝 <b>最新提交:</b> <a href="${c.html_url}">${shortSha}</a>\n`
    m += `👤 <b>作者:</b> ${c.commit.author.name}\n`
    m += `💬 <b>提交信息:</b> ${firstLine}\n`
    m += `⏰ <b>时间:</b> ${formatShanghai(date)}\n\n`
  } else {
    const display = commits.slice(0, 10)
    const remaining = commits.length - display.length
    m += `📋 <b>发现 ${commits.length} 个新提交</b>\n\n`
    display.forEach((c, i) => {
      const shortSha = c.sha.substring(0, 7)
      const firstLine = c.commit.message.split('\n')[0]
      const date = new Date(c.commit.author.date)
      m += `${i + 1}. <a href="${c.html_url}">${shortSha}</a> - ${firstLine}\n`
      m += `   👤 ${c.commit.author.name} • ⏰ ${formatShanghaiShort(date)}\n\n`
    })
    if (remaining > 0) {
      m += `📝 <i>由于提交数量较多，只显示最新的10个提交（还有${remaining}个提交未显示）</i>\n\n`
    }
    if (!isCompleteHistory) {
      m += `⚠️ <i>注意：由于提交历史较长，可能未显示所有提交</i>\n\n`
    }
  }

  if (fork && 'exists' in fork && fork.exists) {
    const forkUrl = `https://github.com/${fork.fullName}`
    m += `🍴 <b>我的仓库:</b> <a href="${forkUrl}">${fork.fullName}</a>\n`
    if (fork.behind > 0) {
      m += `💡 <b>你的 fork 落后 ${fork.behind} commit</b>\n`
    }
    m += '\n'
  }

  m += `<a href="${repoUrl}/commits/${repo.branch}">查看完整提交历史</a>`
  return m
}

export function buildCronLogMessage(log: CronLog): string {
  const statusIcon = log.success ? '✅' : '❌'
  const statusText = log.success ? '执行成功' : '执行失败'
  const title = `${statusIcon} <b>GitHub Monitor 定时任务报告</b>`

  const basicInfo = [
    `📅 <b>执行时间:</b> ${log.startTime}`,
    `⏱️ <b>执行时长:</b> ${log.duration}`,
    `🔄 <b>执行状态:</b> ${statusText}`,
  ].join('\n')

  let resultDetails = ''
  if (log.success && log.result) {
    const r = log.result
    resultDetails = [
      `📊 <b>检查结果:</b>`,
      `   • 已检查仓库: ${r.checkedCount ?? 0}`,
      `   • 发现更新: ${r.updatedCount ?? 0}`,
      `   • 错误数量: ${r.errorCount ?? 0}`,
      `💬 <b>总结:</b> ${r.message ?? '检查完成'}`,
    ].join('\n')
  } else if (log.error) {
    resultDetails = `🚨 <b>错误信息:</b>\n<code>${log.error}</code>`
  }

  const systemInfo = [
    `💻 <b>系统状态:</b> ${log.success ? '正常运行' : '遇到问题'}`,
    `🔔 <b>通知渠道:</b> Telegram`,
  ].join('\n')

  return `${title}\n\n${basicInfo}\n\n${resultDetails}\n\n${systemInfo}\n\n<i>此消息由GitHub Monitor定时任务自动发送</i>`
}

export function buildErrorMessage(
  repo: Pick<RepoEntry, 'owner' | 'repo' | 'branch'>, err: unknown,
): string {
  const msg = err instanceof Error ? err.message : String(err)
  return `❌ <b>监控错误</b>\n\n检查仓库 ${repo.owner}/${repo.repo} (${repo.branch}) 时出错:\n<code>${msg}</code>`
}
