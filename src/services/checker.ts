import type { Env } from '../env'
import { getRepoList, getRepoState, setRepoState } from '../storage/repos'
import { getGithub, getTelegram } from '../storage/settings'
import { setLastCheckTime } from '../storage/cron-log'
import { GitHubClient } from './github'
import { TelegramClient, buildCommitNotification, buildErrorMessage } from './telegram'
import { formatShanghai } from '../lib/time'

export type CheckResult = {
  success: boolean
  message: string
  checkedCount: number
  updatedCount: number
  errorCount: number
  error?: string
}

export async function runCheck(env: Env): Promise<CheckResult> {
  console.log('🔍 开始检查所有仓库更新...')
  const checkTime = formatShanghai(new Date())
  await setLastCheckTime(env, checkTime)

  const repoList = await getRepoList(env)
  const tg = await getTelegram(env)
  const gh = await getGithub(env)

  if (repoList.length === 0) {
    console.log('ℹ️ 没有监控的仓库需要检查')
    return { success: true, message: '没有监控的仓库需要检查', checkedCount: 0, updatedCount: 0, errorCount: 0 }
  }

  const client = new GitHubClient(gh?.token)
  const telegram = tg && tg.botToken && tg.chatId
    ? new TelegramClient(tg.botToken, tg.chatId) : null

  let checked = 0, updated = 0, errors = 0

  for (const repo of repoList) {
    try {
      console.log(`🔎 检查 ${repo.owner}/${repo.repo} (${repo.branch})`)
      const latest = await client.getLatestCommit(repo.owner, repo.repo, repo.branch)
      const state = await getRepoState(env, repo.owner, repo.repo, repo.branch)
      checked++

      if (!state) {
        await setRepoState(env, repo.owner, repo.repo, repo.branch, {
          lastSha: latest.sha, lastCheckedAt: new Date().toISOString(),
        })
        continue
      }

      if (latest.sha === state.lastSha) continue

      updated++
      let between
      try {
        between = await client.getCommitsBetween(repo.owner, repo.repo, repo.branch, state.lastSha)
      } catch (err) {
        console.error('getCommitsBetween 失败，退化为单条:', err)
        between = { commits: [latest], isComplete: false }
      }

      if (telegram && between.commits.length > 0) {
        const msg = buildCommitNotification(repo, between.commits, between.isComplete)
        try { await telegram.send(msg) } catch (err) {
          console.error('Telegram 发送失败:', err)
        }
      }

      await setRepoState(env, repo.owner, repo.repo, repo.branch, {
        lastSha: latest.sha, lastCheckedAt: new Date().toISOString(),
      })
    } catch (err) {
      console.error('检查仓库出错:', err)
      errors++
      if (telegram) {
        try { await telegram.send(buildErrorMessage(repo, err)) } catch {}
      }
    }
    const delay = gh?.token ? 500 : 2000
    await new Promise((r) => setTimeout(r, delay))
  }

  const message = `检查完成: 已检查 ${checked} 个仓库，发现 ${updated} 个更新，${errors} 个错误`
  console.log(`✅ ${message}`)
  return { success: true, message, checkedCount: checked, updatedCount: updated, errorCount: errors }
}
