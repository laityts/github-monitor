import { describe, expect, it } from 'vitest'
import {
  buildCommitNotification, buildCronLogMessage, buildErrorMessage,
} from '../../src/services/telegram'

const repo = { owner: 'vercel', repo: 'next.js', branch: 'main' } as const

const commit = (sha: string, msg: string, author = 'tester', date = '2026-05-23T10:00:00Z') => ({
  sha,
  html_url: `https://github.com/vercel/next.js/commit/${sha}`,
  commit: { author: { name: author, date }, message: msg },
})

describe('buildCommitNotification', () => {
  it('单提交格式', () => {
    const m = buildCommitNotification(repo, [commit('abc1234', 'fix bug')], true)
    expect(m).toContain('vercel/next.js')
    expect(m).toContain('abc1234')
    expect(m).toContain('fix bug')
    expect(m).toContain('main')
  })

  it('多提交 ≤10 条', () => {
    const commits = Array.from({ length: 8 }, (_, i) => commit(`s${i}`.padEnd(7, 'x'), `msg ${i}`))
    const m = buildCommitNotification(repo, commits, true)
    expect(m).toContain('发现 8 个新提交')
  })

  it('多提交 >10 条截断', () => {
    const commits = Array.from({ length: 15 }, (_, i) => commit(`s${i}`.padEnd(7, 'x'), `msg ${i}`))
    const m = buildCommitNotification(repo, commits, true)
    expect(m).toContain('发现 15 个新提交')
    expect(m).toContain('只显示最新的10个提交')
    expect(m).toContain('还有5个提交未显示')
  })

  it('不完整历史标注', () => {
    const commits = Array.from({ length: 3 }, (_, i) => commit(`s${i}`.padEnd(7, 'x'), `msg ${i}`))
    const m = buildCommitNotification(repo, commits, false)
    expect(m).toContain('可能未显示所有提交')
  })

  it('fork 落后时附加提示', () => {
    const m = buildCommitNotification(
      repo, [commit('abc1234', 'fix bug')], true,
      { exists: true, behind: 5, fullName: 'laityts/next.js' } as any,
    )
    expect(m).toContain('<a href="https://github.com/laityts/next.js">laityts/next.js</a>')
    expect(m).toContain('你的 fork 落后 5')
  })

  it('fork 存在时同时显示上游仓库和自己的仓库', () => {
    const m = buildCommitNotification(
      repo, [commit('abc1234', 'fix bug')], true,
      { exists: true, behind: 0, fullName: 'laityts/my-next' } as any,
    )
    expect(m).toContain('<a href="https://github.com/vercel/next.js">vercel/next.js</a>')
    expect(m).toContain('<a href="https://github.com/laityts/my-next">laityts/my-next</a>')
  })
})

describe('buildCronLogMessage', () => {
  it('成功格式', () => {
    const m = buildCronLogMessage({
      timestamp: '', startTime: '2026/05/23 10:00:00', endTime: '', duration: '500ms',
      success: true,
      result: { success: true, message: '检查完成', checkedCount: 3, updatedCount: 1, errorCount: 0 },
      error: null,
    })
    expect(m).toContain('执行成功')
    expect(m).toContain('已检查仓库: 3')
    expect(m).toContain('发现更新: 1')
  })

  it('失败格式', () => {
    const m = buildCronLogMessage({
      timestamp: '', startTime: '2026/05/23 10:00:00', endTime: '', duration: '500ms',
      success: false, result: { success: false, error: 'boom' }, error: 'boom',
    })
    expect(m).toContain('执行失败')
    expect(m).toContain('boom')
  })
})

describe('buildErrorMessage', () => {
  it('包含仓库与错误', () => {
    const m = buildErrorMessage(repo, new Error('Network down'))
    expect(m).toContain('vercel/next.js')
    expect(m).toContain('Network down')
  })
})
