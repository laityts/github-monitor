import type { Env } from '../env'
import { GitHubClient } from './github'
import { getGithub, setGithub } from '../storage/settings'

const USERNAME_TTL_MS = 24 * 60 * 60 * 1000

export async function resolveUsername(env: Env): Promise<string | null> {
  const gh = await getGithub(env)
  if (!gh) return null
  if (
    gh.username &&
    gh.usernameFetchedAt &&
    Date.now() - Date.parse(gh.usernameFetchedAt) < USERNAME_TTL_MS
  ) {
    return gh.username
  }
  if (!gh.token) return null
  try {
    const client = new GitHubClient(gh.token)
    const user = await client.getAuthenticatedUser()
    await setGithub(env, {
      token: gh.token,
      username: user.login,
      usernameFetchedAt: new Date().toISOString(),
    })
    return user.login
  } catch (err) {
    console.error('resolveUsername 失败:', err)
    return gh.username || null
  }
}
