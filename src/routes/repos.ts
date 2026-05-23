import { Hono } from 'hono'
import type { Env, Variables } from '../env'
import { deleteRepoState, getRepoList, setRepoList } from '../storage/repos'
import { getGithub } from '../storage/settings'
import { GitHubClient } from '../services/github'
import { runCheck } from '../services/checker'

export const reposRoute = new Hono<{ Bindings: Env; Variables: Variables }>()

reposRoute.post('/add', async (c) => {
  const form = await c.req.formData()
  const repoFullName = (form.get('repo_full_name') as string | null)?.trim() ?? ''
  let branch = (form.get('branch') as string | null)?.trim() ?? ''

  if (!repoFullName) return c.redirect('/?error=仓库名称不能为空', 302)
  const parts = repoFullName.split('/')
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return c.redirect('/?error=格式应为 owner/repo', 302)
  }
  const owner = parts[0].trim()
  const repo = parts[1].trim()
  if (!branch) branch = 'main'

  const list = await getRepoList(c.env)
  if (list.some((r) => r.owner === owner && r.repo === repo && r.branch === branch)) {
    return c.redirect('/?error=该仓库和分支已存在', 302)
  }

  try {
    const gh = await getGithub(c.env)
    const client = new GitHubClient(gh?.token)
    await client.getLatestCommit(owner, repo, branch)
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    return c.redirect(`/?error=${encodeURIComponent('无法添加：' + msg)}`, 302)
  }

  list.push({ owner, repo, branch, addedAt: new Date().toISOString() })
  await setRepoList(c.env, list)
  return c.redirect(`/?message=${encodeURIComponent(`已添加 ${owner}/${repo} (${branch})`)}`, 302)
})

reposRoute.post('/delete', async (c) => {
  const form = await c.req.formData()
  const owner = (form.get('owner') as string | null) ?? ''
  const repo = (form.get('repo') as string | null) ?? ''
  const branch = (form.get('branch') as string | null) ?? ''
  const list = await getRepoList(c.env)
  const filtered = list.filter((r) => !(r.owner === owner && r.repo === repo && r.branch === branch))
  await setRepoList(c.env, filtered)
  await deleteRepoState(c.env, owner, repo, branch)
  return c.redirect(`/?message=${encodeURIComponent(`已删除 ${owner}/${repo} (${branch})`)}`, 302)
})

reposRoute.post('/clear', async (c) => {
  await setRepoList(c.env, [])
  return c.redirect('/?message=已清空所有监控仓库', 302)
})

reposRoute.post('/check', async (c) => {
  const r = await runCheck(c.env)
  return c.redirect(`/?message=${encodeURIComponent(r.message)}`, 302)
})
