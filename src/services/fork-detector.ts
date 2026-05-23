import type { Env } from '../env'
import { KV } from '../storage/keys'
import { GitHubClient, type GhRepo } from './github'

const CACHE_TTL_MS = 60 * 60 * 1000
const CACHE_TTL_SECONDS = 3600

export type ForkInfo =
  | {
      exists: true
      fullName: string
      defaultBranch: string
      latestCommitSha: string
      latestCommitAt: string
      ahead: number
      behind: number
      canSync: boolean
    }
  | { exists: false }
  | { error: string }

type ForkCache = {
  forkFullName: string | null
  parentVerified: boolean
  fetchedAt: string
}

export async function detectFork(
  env: Env, gh: GitHubClient, me: string,
  upstreamOwner: string, upstreamRepo: string, upstreamBranch: string,
): Promise<ForkInfo> {
  try {
    const cacheKey = KV.forkCacheKey(upstreamOwner, upstreamRepo)
    const cached = (await env.STORAGE.get(cacheKey, 'json')) as ForkCache | null
    let forkFullName: string | null = null

    if (cached && Date.now() - Date.parse(cached.fetchedAt) < CACHE_TTL_MS) {
      forkFullName = cached.forkFullName
    } else {
      forkFullName = await findFork(env, gh, me, upstreamOwner, upstreamRepo)
      await env.STORAGE.put(cacheKey, JSON.stringify({
        forkFullName, parentVerified: true,
        fetchedAt: new Date().toISOString(),
      } satisfies ForkCache), { expirationTtl: CACHE_TTL_SECONDS })
    }

    if (!forkFullName) return { exists: false }

    const [forkOwner, forkRepoName] = forkFullName.split('/')
    if (!forkOwner || !forkRepoName) return { exists: false }

    const [branch, compare] = await Promise.all([
      gh.getBranch(forkOwner, forkRepoName, upstreamBranch),
      gh.compareCommits(
        upstreamOwner, upstreamRepo,
        upstreamBranch, `${forkOwner}:${upstreamBranch}`,
      ),
    ])

    return {
      exists: true,
      fullName: forkFullName,
      defaultBranch: upstreamBranch,
      latestCommitSha: branch.commit.sha,
      latestCommitAt: branch.commit.commit.author.date,
      ahead: compare.ahead_by,
      behind: compare.behind_by,
      canSync: compare.behind_by > 0 && gh.hasToken(),
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    return { error: msg }
  }
}

async function findFork(
  env: Env, gh: GitHubClient, me: string, upstreamOwner: string, upstreamRepo: string,
): Promise<string | null> {
  try {
    const repo = await gh.getRepo(me, upstreamRepo)
    if (repo.fork && repo.parent?.full_name === `${upstreamOwner}/${upstreamRepo}`) {
      return repo.full_name
    }
  } catch (err) {
    if (!(err instanceof Error) || !/404/.test(err.message)) throw err
  }

  const listKey = KV.FORK_USER_FORKS_LIST
  let forks = (await env.STORAGE.get(listKey, 'json')) as GhRepo[] | null
  if (!forks) {
    forks = await gh.listUserForks(me)
    await env.STORAGE.put(listKey, JSON.stringify(forks), { expirationTtl: CACHE_TTL_SECONDS })
  }
  const target = `${upstreamOwner}/${upstreamRepo}`
  const match = forks.find((r) => r.parent?.full_name === target)
  return match?.full_name ?? null
}
