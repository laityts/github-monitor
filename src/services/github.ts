export type GhCommit = {
  sha: string
  html_url: string
  commit: { author: { name: string; date: string }; message: string }
}

export type GhRepo = {
  full_name: string
  default_branch: string
  fork: boolean
  parent?: { full_name: string }
}

export type GhBranch = {
  name: string
  commit: { sha: string; commit: { author: { date: string } } }
}

export type GhCompare = {
  status: 'identical' | 'ahead' | 'behind' | 'diverged'
  ahead_by: number
  behind_by: number
}

export type GhMergeUpstreamResult = {
  message: string
  merge_type?: string
  base_branch?: string
}

export type GhUser = { login: string }

export class GitHubError extends Error {
  constructor(
    public status: number,
    message: string,
    public path: string,
    public isRateLimit = false,
    public needsAuth = false,
  ) {
    super(message)
    this.name = 'GitHubError'
  }
}

export class GitHubClient {
  constructor(private readonly token?: string) {}

  private async req<T>(path: string, init: RequestInit = {}): Promise<T> {
    const r = await fetch(`https://api.github.com${path}`, {
      ...init,
      headers: {
        'User-Agent': 'github-monitor',
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        ...(this.token ? { Authorization: `Bearer ${this.token}` } : {}),
        ...(init.headers as Record<string, string> | undefined ?? {}),
      },
    })
    if (!r.ok) {
      const text = await r.text()
      const isRateLimit = r.status === 403 && /rate limit/i.test(text)
      throw new GitHubError(
        r.status,
        `GitHub ${path}: ${r.status} ${r.statusText} ${text.slice(0, 200)}`,
        path, isRateLimit, r.status === 401 || r.status === 403,
      )
    }
    return r.json() as Promise<T>
  }

  getAuthenticatedUser(): Promise<GhUser> {
    return this.req<GhUser>('/user')
  }

  async getLatestCommit(owner: string, repo: string, branch: string): Promise<GhCommit> {
    const commits = await this.req<GhCommit[]>(
      `/repos/${owner}/${repo}/commits?sha=${encodeURIComponent(branch)}&per_page=1`,
    )
    const first = commits[0]
    if (!first) throw new GitHubError(404, `该分支没有提交记录`, `/repos/${owner}/${repo}/commits`)
    return first
  }

  async getCommitsBetween(
    owner: string, repo: string, branch: string, sinceSha: string | null,
  ): Promise<{ commits: GhCommit[]; isComplete: boolean }> {
    const commits = await this.req<GhCommit[]>(
      `/repos/${owner}/${repo}/commits?sha=${encodeURIComponent(branch)}&per_page=100`,
    )
    if (commits.length === 0) return { commits: [], isComplete: true }
    if (!sinceSha) return { commits: [commits[0]!], isComplete: true }
    const idx = commits.findIndex((c) => c.sha === sinceSha)
    if (idx > 0) return { commits: commits.slice(0, idx), isComplete: true }
    if (idx === -1) return { commits, isComplete: false }
    return { commits: [], isComplete: true }
  }

  getRepo(owner: string, repo: string): Promise<GhRepo> {
    return this.req<GhRepo>(`/repos/${owner}/${repo}`)
  }

  async listUserForks(username: string): Promise<GhRepo[]> {
    const all: GhRepo[] = []
    let page = 1
    while (true) {
      const batch = await this.req<GhRepo[]>(
        `/users/${username}/repos?type=forks&per_page=100&page=${page}`,
      )
      all.push(...batch)
      if (batch.length < 100) break
      page++
      if (page > 20) break
    }
    return all
  }

  compareCommits(owner: string, repo: string, base: string, head: string): Promise<GhCompare> {
    return this.req<GhCompare>(
      `/repos/${owner}/${repo}/compare/${encodeURIComponent(base)}...${encodeURIComponent(head)}`,
    )
  }

  getBranch(owner: string, repo: string, branch: string): Promise<GhBranch> {
    return this.req<GhBranch>(`/repos/${owner}/${repo}/branches/${encodeURIComponent(branch)}`)
  }

  syncFork(owner: string, repo: string, branch: string): Promise<GhMergeUpstreamResult> {
    return this.req<GhMergeUpstreamResult>(
      `/repos/${owner}/${repo}/merge-upstream`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ branch }) },
    )
  }

  createFork(owner: string, repo: string): Promise<GhRepo> {
    return this.req<GhRepo>(
      `/repos/${owner}/${repo}/forks`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' },
    )
  }

  hasToken(): boolean { return !!this.token }
}
