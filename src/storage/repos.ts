import type { Env } from '../env'
import { KV } from './keys'

export type RepoEntry = {
  owner: string
  repo: string
  branch: string
  addedAt: string  // ISO
}

export type RepoState = {
  lastSha: string
  lastCheckedAt: string  // ISO
}

export async function getRepoList(env: Env): Promise<RepoEntry[]> {
  const raw = await env.STORAGE.get(KV.REPOS_LIST, 'json')
  return (raw as RepoEntry[] | null) ?? []
}

export async function setRepoList(env: Env, list: RepoEntry[]): Promise<void> {
  await env.STORAGE.put(KV.REPOS_LIST, JSON.stringify(list))
}

export async function getRepoState(
  env: Env, owner: string, repo: string, branch: string,
): Promise<RepoState | null> {
  const raw = await env.STORAGE.get(KV.repoStateKey(owner, repo, branch), 'json')
  return (raw as RepoState | null) ?? null
}

export async function setRepoState(
  env: Env, owner: string, repo: string, branch: string, state: RepoState,
): Promise<void> {
  await env.STORAGE.put(KV.repoStateKey(owner, repo, branch), JSON.stringify(state))
}

export async function deleteRepoState(
  env: Env, owner: string, repo: string, branch: string,
): Promise<void> {
  await env.STORAGE.delete(KV.repoStateKey(owner, repo, branch))
}
