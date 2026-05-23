# UI 重构 + FORK 关联显示 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把 GitHub Monitor 完整重构为 GitHub 原生风(Primer)的 SPA,引入 FORK 关联展示与一键 FORK 流程。

**Architecture:** 单文件 `worker.js`,前端 SPA(原生 JS、无框架),与 JSON API 并存于同一 Worker。仓库数据模型扩展 `fork` 字段,从 GitHub `/user` 自动推断用户名,通过 `repos/X/Y` 检测 FORK 关系,失败时提供一键 FORK。新 UI 用 `[data-theme=light|dark]` 切主题、Primer CSS 变量、左侧栏(可折叠)、模态框、AJAX 局部刷新。

**Tech Stack:** Cloudflare Workers · KV · GitHub REST API · Telegram Bot API · 原生 JS / CSS(无构建工具)

**设计文档:** `docs/superpowers/specs/2026-05-23-ui-refactor-fork-display-design.md`

**验证手段:** 项目无单元测试基建。每个 Task 用 `npx wrangler dev --local` + curl 或浏览器手动验证。Cron 用 `npx wrangler dev --test-scheduled` + `curl localhost:8787/__scheduled`。

**通用约定:**
- 行号引用以最近一次 `git show HEAD:worker.js` 为准,执行任务前 `git diff HEAD~1 worker.js` 确认偏移
- 所有 `git commit` 都附 `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>`
- 每个 Task 完成后单独 commit,不批量

---

## 文件结构

只改 **`worker.js`** 一个文件。任务粒度按提交划分,文件内不分包。

| 区段 | 当前行 | 备注 |
|------|--------|------|
| 顶部 `export default { fetch, scheduled }` | 1-43 | Task 1 新增 `/api/*` 分发 |
| `STORAGE_KEYS` | 45-56 | Task 6 新增 `GITHUB_USERNAME` |
| `handleCronExecution` 等 | 59-97 | 不动 |
| 认证 (`checkAuth` / `initAdminPassword` / `verifyPassword`) | 99-152 | 不动 |
| `handleLogin` / `handleLogout` | 154-211 | Task 8 调整登录页主题 |
| `handleDashboard` | 213-252 | Task 8 简化,移除 POST 分发(改走 API) |
| 旧仓库 / 设置 / 密码 POST 处理函数 (`handleAddRepo` 等 9 个) | 255-436 | Task 8 删除 |
| `getRepoList` / `saveRepoList` / `getSettings` / `saveSettings` 等 | 438-506 | Task 6 改 `getRepoList` 懒迁移 |
| GitHub / Telegram API 调用 | 508-779 | 不动(只新增 `fetchRepo` / `createFork` / `fetchUser`) |
| `checkAllRepos` | 780-927 | 不动 |
| `handleCheckUpdates` | 929-937 | 不动 |
| `showLoginPage` | 939-1237 | Task 8 替换为 GitHub 风 |
| `showDashboard` / `generateDashboardHTML` | 1239-2308 | Task 8 全部删除,新 SPA HTML 函数替代 |

---

## Task 1: 新增 JSON API 路由分发与基础设施

**目标:** 为 `/api/*` 添加分发逻辑、`jsonResponse` 与 `requireAuth` 辅助,但不实现任何端点。所有 `/api/*` 暂返回 404。

**Files:**
- Modify: `worker.js` 顶部 `fetch` 分发(第 4-37 行附近)
- Modify: `worker.js` 文件末尾追加新函数

- [ ] **Step 1:** 修改 `worker.js` 顶部 fetch 分发,在 `if (path === '/health')` 之前插入 `/api/*` 分发

找到 worker.js 中(约第 22-34 行):

```javascript
    // 处理API端点
    if (path === '/check-updates') {
      return handleCheckUpdates(env);
    }

    if (path === '/health') {
      return new Response(JSON.stringify({
        status: 'ok',
        timestamp: new Date().toISOString()
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response('Not Found', { status: 404 });
```

替换为:

```javascript
    // JSON API 分发
    if (path.startsWith('/api/')) {
      return handleApi(request, env, url);
    }

    // 兼容旧路径
    if (path === '/check-updates') {
      return handleCheckUpdates(env);
    }

    if (path === '/health') {
      return new Response(JSON.stringify({
        status: 'ok',
        timestamp: new Date().toISOString()
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response('Not Found', { status: 404 });
```

- [ ] **Step 2:** 在 worker.js 末尾追加 `handleApi` / `jsonResponse` / `jsonError` / `requireAuth` / `readJsonBody` 这 5 个辅助函数

```javascript
// ==================== JSON API 路由 ====================
async function handleApi(request, env, url) {
  const path = url.pathname;
  const method = request.method;

  // 所有 API 端点都要求会话(除非未来加白名单)
  const auth = await checkAuth(request, env);
  if (!auth.authenticated) {
    return jsonError('Not authenticated', 'UNAUTHORIZED', 401);
  }

  try {
    // 占位:所有具体端点在后续 Task 添加
    return jsonError(`No route for ${method} ${path}`, 'NOT_FOUND', 404);
  } catch (err) {
    console.error('API handler error:', err);
    return jsonError(err.message || 'Internal error', 'INTERNAL', 500);
  }
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify({ ok: true, data }), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' }
  });
}

function jsonError(message, code = 'INTERNAL', status = 500) {
  return new Response(JSON.stringify({ ok: false, error: message, code }), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' }
  });
}

async function readJsonBody(request) {
  try {
    return await request.json();
  } catch {
    return null;
  }
}
```

- [ ] **Step 3:** 本地启动验证

```bash
cd /root/github-monitor
npx wrangler dev --local
```

另开终端:

```bash
curl -i http://localhost:8787/api/foo
```

预期:`401 Unauthorized`,body `{"ok":false,"error":"Not authenticated","code":"UNAUTHORIZED"}`

```bash
curl -i http://localhost:8787/health
```

预期:`200 OK`,沿用原本响应。Ctrl-C 停 wrangler dev。

- [ ] **Step 4:** 提交

```bash
git add worker.js
git commit -m "$(cat <<'EOF'
feat(api): add JSON API route dispatch and helpers

新增 /api/* 路由分发与 jsonResponse / jsonError / requireAuth /
readJsonBody 辅助函数。本提交只搭框架,具体端点在后续 Task 实现,
所有 /api/* 暂返回 401(未认证)或 404(未实现)。

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: 实现只读 API 端点(`GET /api/repos`、`/api/activity`、`/api/settings`)

**目标:** 实现 3 个只读端点,沿用现有的 `getRepoList` / `getSettings` / `getLastCheckTime` / `getLastCronLog`,**暂不**改数据模型(fork 字段下一 task 加)。

**Files:**
- Modify: `worker.js` 中 `handleApi` 函数(刚加的)

- [ ] **Step 1:** 替换 `handleApi` 主体,把占位的 NOT_FOUND 换成实际路由 switch

找到刚加的 `handleApi` 函数体,把 `try { ... }` 块替换为:

```javascript
  try {
    // GET /api/repos
    if (path === '/api/repos' && method === 'GET') {
      const list = await getRepoList(env);
      return jsonResponse({ repos: list });
    }

    // GET /api/activity
    if (path === '/api/activity' && method === 'GET') {
      const lastCheckTime = await getLastCheckTime(env);
      const lastCronLog = await getLastCronLog(env);
      return jsonResponse({ lastCheckTime, lastCronLog });
    }

    // GET /api/settings
    if (path === '/api/settings' && method === 'GET') {
      const settings = await getSettings(env);
      // 不回传 password,token 直接回传(管理员只读自己的)
      return jsonResponse({ settings });
    }

    return jsonError(`No route for ${method} ${path}`, 'NOT_FOUND', 404);
  } catch (err) {
    console.error('API handler error:', err);
    return jsonError(err.message || 'Internal error', 'INTERNAL', 500);
  }
```

- [ ] **Step 2:** 本地验证(需要先登录拿到 cookie)

启动:

```bash
npx wrangler dev --local
```

另开终端,先登录拿 cookie:

```bash
curl -i -c /tmp/cm.cookies -X POST -d "password=admin123" http://localhost:8787/login
```

预期:`302 Found`,Location 是首页。然后调三个端点:

```bash
curl -b /tmp/cm.cookies http://localhost:8787/api/repos
curl -b /tmp/cm.cookies http://localhost:8787/api/activity
curl -b /tmp/cm.cookies http://localhost:8787/api/settings
```

预期:每个都返回 `{"ok":true,"data":{...}}`,`/api/repos` 的 repos 为空数组(全新 KV)。无 cookie 时:

```bash
curl -i http://localhost:8787/api/repos
```

预期:401。停 wrangler dev。

- [ ] **Step 3:** 提交

```bash
git add worker.js
git commit -m "$(cat <<'EOF'
feat(api): implement read-only endpoints

新增 GET /api/repos / GET /api/activity / GET /api/settings 三个
只读端点,复用现有的 getRepoList / getSettings / getLastCheckTime
/ getLastCronLog,不改数据模型。

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: 实现写操作 API(添加/删除仓库、手动检查)

**目标:** 增加 `POST /api/repos`、`DELETE /api/repos`、`POST /api/check`。FORK 检测放在 Task 6,此处只做最小可用版本(仅校验仓库存在性,沿用旧逻辑)。

**Files:**
- Modify: `worker.js` 中 `handleApi` 函数

- [ ] **Step 1:** 在 `handleApi` 的 try 块中,`return jsonError('No route...')` **之前**追加 3 个分支

```javascript
    // POST /api/repos
    if (path === '/api/repos' && method === 'POST') {
      const body = await readJsonBody(request);
      if (!body || typeof body.repo !== 'string') {
        return jsonError('Missing repo field', 'VALIDATION_ERROR', 400);
      }

      const repoFullName = (body.repo || '').trim();
      const branch = (body.branch || 'main').trim() || 'main';
      const parts = repoFullName.split('/');
      if (parts.length !== 2 || !parts[0] || !parts[1]) {
        return jsonError('Format must be owner/repo', 'VALIDATION_ERROR', 400);
      }
      const owner = parts[0].trim();
      const repo = parts[1].trim();

      const repoList = await getRepoList(env);
      const exists = repoList.some(r => r.owner === owner && r.repo === repo && r.branch === branch);
      if (exists) {
        return jsonError('Repository already monitored', 'REPO_DUPLICATE', 409);
      }

      const settings = await getSettings(env);
      try {
        await fetchLatestCommit(owner, repo, branch, settings.github_token);
      } catch (e) {
        const msg = String(e.message || e);
        if (msg.includes('频率限制')) return jsonError(msg, 'RATE_LIMITED', 429);
        if (msg.includes('仓库不存在')) return jsonError(msg, 'REPO_NOT_FOUND', 404);
        return jsonError(msg, 'GITHUB_ERROR', 502);
      }

      const item = { owner, repo, branch, fork: null, addedAt: new Date().toISOString() };
      repoList.push(item);
      await saveRepoList(repoList, env);
      return jsonResponse({ repo: item });
    }

    // DELETE /api/repos
    if (path === '/api/repos' && method === 'DELETE') {
      const body = await readJsonBody(request);
      if (!body || !body.owner || !body.repo || !body.branch) {
        return jsonError('Missing owner / repo / branch', 'VALIDATION_ERROR', 400);
      }
      const { owner, repo, branch } = body;
      const repoList = await getRepoList(env);
      const filtered = repoList.filter(r => !(r.owner === owner && r.repo === repo && r.branch === branch));
      if (filtered.length === repoList.length) {
        return jsonError('Repository not found', 'REPO_NOT_FOUND', 404);
      }
      await saveRepoList(filtered, env);
      const commitKey = `${STORAGE_KEYS.LAST_COMMITS}${owner}:${repo}:${branch}`;
      await env.STORAGE.delete(commitKey);
      return jsonResponse({ deleted: true });
    }

    // POST /api/check
    if (path === '/api/check' && method === 'POST') {
      const result = await checkAllRepos(env);
      if (!result.success) {
        return jsonError(result.error || 'Check failed', 'CHECK_FAILED', 500);
      }
      return jsonResponse({ result });
    }
```

- [ ] **Step 2:** 本地验证

```bash
npx wrangler dev --local
```

另开终端:

```bash
# 登录
curl -c /tmp/cm.cookies -X POST -d "password=admin123" http://localhost:8787/login

# 添加(用 GitHub 上一定存在的小仓库)
curl -b /tmp/cm.cookies -X POST \
  -H "Content-Type: application/json" \
  -d '{"repo":"github/gitignore","branch":"main"}' \
  http://localhost:8787/api/repos

# 列表
curl -b /tmp/cm.cookies http://localhost:8787/api/repos

# 重复添加(预期 409 REPO_DUPLICATE)
curl -i -b /tmp/cm.cookies -X POST \
  -H "Content-Type: application/json" \
  -d '{"repo":"github/gitignore","branch":"main"}' \
  http://localhost:8787/api/repos

# 不存在的仓库(预期 404 REPO_NOT_FOUND)
curl -i -b /tmp/cm.cookies -X POST \
  -H "Content-Type: application/json" \
  -d '{"repo":"nonexistent-user-xyz/nope-repo","branch":"main"}' \
  http://localhost:8787/api/repos

# 格式错(预期 400)
curl -i -b /tmp/cm.cookies -X POST \
  -H "Content-Type: application/json" \
  -d '{"repo":"justonepart","branch":"main"}' \
  http://localhost:8787/api/repos

# 删除
curl -b /tmp/cm.cookies -X DELETE \
  -H "Content-Type: application/json" \
  -d '{"owner":"github","repo":"gitignore","branch":"main"}' \
  http://localhost:8787/api/repos

# 手动检查(列表已空,预期 success: true, checkedCount: 0)
curl -b /tmp/cm.cookies -X POST http://localhost:8787/api/check
```

每条预期都对得上再继续。停 wrangler dev。

- [ ] **Step 3:** 提交

```bash
git add worker.js
git commit -m "$(cat <<'EOF'
feat(api): add repo CRUD and manual check endpoints

新增 POST /api/repos / DELETE /api/repos / POST /api/check 三个
写操作端点。POST /api/repos 暂未做 FORK 检测,只校验仓库存在性,
并把新条目以 { owner, repo, branch, fork: null, addedAt } 形式
存入。FORK 检测在后续 Task 加。

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: 实现设置类 API(读/写/测试)与改密码

**目标:** 增加 `PUT /api/settings`、`POST /api/settings/test-telegram`、`POST /api/settings/test-github`、`PUT /api/password`。`test-github` 还要更新 `github_username` 缓存(为 Task 6 的 FORK 检测做准备)。

**Files:**
- Modify: `worker.js` 中 `STORAGE_KEYS` 常量(加 `GITHUB_USERNAME`)
- Modify: `worker.js` 中 `handleApi`
- Modify: `worker.js` 新增 `fetchGithubUser` 函数

- [ ] **Step 1:** 找到 `STORAGE_KEYS` 常量(约第 45-56 行),在最后一项后加一行

```javascript
const STORAGE_KEYS = {
  PASSWORD_HASH: 'admin_password_hash',
  REPO_LIST: 'monitored_repositories',
  LAST_COMMITS: 'last_commit_',
  TG_BOT_TOKEN: 'telegram_bot_token',
  TG_CHAT_ID: 'telegram_chat_id',
  GITHUB_TOKEN: 'github_token',
  LAST_CHECK_TIME: 'last_check_time',
  LAST_CRON_LOG: 'last_cron_log',
  CRON_NOTIFICATION_ENABLED: 'cron_notification_enabled',
  GITHUB_USERNAME: 'github_username'
};
```

- [ ] **Step 2:** 在 `fetchLatestCommit` 函数定义后(约第 550 行附近,该函数 `}` 之后)追加 `fetchGithubUser` 函数

```javascript
async function fetchGithubUser(githubToken) {
  if (!githubToken) return null;
  const response = await fetch('https://api.github.com/user', {
    headers: {
      'User-Agent': 'GitHub-Monitor-Bot',
      'Accept': 'application/vnd.github.v3+json',
      'Authorization': `token ${githubToken}`
    }
  });
  if (!response.ok) {
    if (response.status === 401) throw new Error('GitHub Token 无效或已过期');
    throw new Error(`GitHub API错误: ${response.status} ${response.statusText}`);
  }
  const data = await response.json();
  return data.login || null;
}
```

- [ ] **Step 3:** 在 `handleApi` 的 try 块,`return jsonError('No route...')` 之前追加 4 个端点

```javascript
    // PUT /api/settings
    if (path === '/api/settings' && method === 'PUT') {
      const body = await readJsonBody(request);
      if (!body) return jsonError('Invalid JSON body', 'VALIDATION_ERROR', 400);

      const settings = {};
      if (typeof body.tg_bot_token === 'string') settings.tg_bot_token = body.tg_bot_token.trim();
      if (typeof body.tg_chat_id === 'string') settings.tg_chat_id = body.tg_chat_id.trim();
      if (typeof body.github_token === 'string') settings.github_token = body.github_token.trim();
      if (typeof body.cron_notification_enabled === 'boolean') settings.cron_notification_enabled = body.cron_notification_enabled;

      await saveSettings(settings, env);

      // 若 github_token 改了,清掉旧用户名缓存(下次 test-github 重建)
      if (settings.github_token !== undefined) {
        await env.STORAGE.delete(STORAGE_KEYS.GITHUB_USERNAME);
      }

      return jsonResponse({ saved: true });
    }

    // POST /api/settings/test-telegram
    if (path === '/api/settings/test-telegram' && method === 'POST') {
      const settings = await getSettings(env);
      if (!settings.tg_bot_token || !settings.tg_chat_id) {
        return jsonError('Telegram Bot Token / Chat ID not configured', 'VALIDATION_ERROR', 400);
      }
      const message = `🔔 <b>测试通知</b>\n\n✅ GitHub Monitor 运行正常\n⏰ ${new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}`;
      try {
        await sendTelegramMessage(settings.tg_bot_token, settings.tg_chat_id, message);
      } catch (e) {
        return jsonError(String(e.message || e), 'TELEGRAM_ERROR', 502);
      }
      return jsonResponse({ sent: true });
    }

    // POST /api/settings/test-github
    if (path === '/api/settings/test-github' && method === 'POST') {
      const settings = await getSettings(env);
      if (!settings.github_token) {
        return jsonError('GitHub Token not configured', 'GITHUB_TOKEN_REQUIRED', 400);
      }
      let username = null;
      try {
        username = await fetchGithubUser(settings.github_token);
      } catch (e) {
        return jsonError(String(e.message || e), 'GITHUB_ERROR', 502);
      }
      if (!username) return jsonError('Failed to resolve username from token', 'GITHUB_ERROR', 502);
      await env.STORAGE.put(STORAGE_KEYS.GITHUB_USERNAME, username);
      return jsonResponse({ username });
    }

    // PUT /api/password
    if (path === '/api/password' && method === 'PUT') {
      const body = await readJsonBody(request);
      if (!body || !body.current || !body.new || !body.confirm) {
        return jsonError('Missing current / new / confirm', 'VALIDATION_ERROR', 400);
      }
      if (body.new !== body.confirm) return jsonError('Passwords do not match', 'VALIDATION_ERROR', 400);
      if (body.new.length < 6) return jsonError('Password must be at least 6 chars', 'VALIDATION_ERROR', 400);
      const valid = await verifyPassword(body.current, env);
      if (!valid) return jsonError('Current password incorrect', 'VALIDATION_ERROR', 401);

      const encoder = new TextEncoder();
      const data = encoder.encode(body.new);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      await env.STORAGE.put(STORAGE_KEYS.PASSWORD_HASH, hashHex);
      return jsonResponse({ changed: true });
    }
```

- [ ] **Step 4:** 本地验证

```bash
npx wrangler dev --local
```

```bash
# 登录
curl -c /tmp/cm.cookies -X POST -d "password=admin123" http://localhost:8787/login

# 改设置
curl -b /tmp/cm.cookies -X PUT \
  -H "Content-Type: application/json" \
  -d '{"tg_bot_token":"dummy","tg_chat_id":"dummy","cron_notification_enabled":false}' \
  http://localhost:8787/api/settings

# 读回
curl -b /tmp/cm.cookies http://localhost:8787/api/settings

# test-github 无 token(预期 400 GITHUB_TOKEN_REQUIRED)
curl -i -b /tmp/cm.cookies -X POST http://localhost:8787/api/settings/test-github

# test-telegram 假 token(预期 502 TELEGRAM_ERROR)
curl -i -b /tmp/cm.cookies -X POST http://localhost:8787/api/settings/test-telegram

# 改密码错(预期 401 VALIDATION_ERROR)
curl -i -b /tmp/cm.cookies -X PUT \
  -H "Content-Type: application/json" \
  -d '{"current":"wrong","new":"newpass123","confirm":"newpass123"}' \
  http://localhost:8787/api/password

# 改密码对
curl -b /tmp/cm.cookies -X PUT \
  -H "Content-Type: application/json" \
  -d '{"current":"admin123","new":"newpass123","confirm":"newpass123"}' \
  http://localhost:8787/api/password

# 改回(便于后续测试)
curl -b /tmp/cm.cookies -X PUT \
  -H "Content-Type: application/json" \
  -d '{"current":"newpass123","new":"admin123","confirm":"admin123"}' \
  http://localhost:8787/api/password
```

- [ ] **Step 5:** 提交

```bash
git add worker.js
git commit -m "$(cat <<'EOF'
feat(api): add settings, telegram/github test, password endpoints

新增 PUT /api/settings、POST /api/settings/test-telegram、POST /api/settings/test-github、
PUT /api/password 四个端点。test-github 通过 GET /user 解析用户名
并缓存到 KV(github_username),为后续 FORK 检测铺垫。改 token 时
清掉旧用户名缓存。新增 STORAGE_KEYS.GITHUB_USERNAME。

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: KV 懒迁移 —— 已存仓库条目补 `fork` 和 `addedAt` 字段

**目标:** 把 `getRepoList` 改为读取时检查每条数据格式,缺字段就补默认值后写回。让旧数据不中断新代码。

**Files:**
- Modify: `worker.js` 中 `getRepoList`(约第 439-442 行)

- [ ] **Step 1:** 找到 `getRepoList` 函数:

```javascript
async function getRepoList(env) {
  const repoList = await env.STORAGE.get(STORAGE_KEYS.REPO_LIST, 'json');
  return repoList || [];
}
```

替换为:

```javascript
async function getRepoList(env) {
  const repoList = await env.STORAGE.get(STORAGE_KEYS.REPO_LIST, 'json');
  if (!repoList || !Array.isArray(repoList)) return [];

  let mutated = false;
  const normalized = repoList.map(item => {
    if (!item || typeof item !== 'object') return item;
    const next = { ...item };
    if (!Object.prototype.hasOwnProperty.call(next, 'fork')) {
      next.fork = null;
      mutated = true;
    }
    if (!Object.prototype.hasOwnProperty.call(next, 'addedAt')) {
      next.addedAt = '1970-01-01T00:00:00.000Z';
      mutated = true;
    }
    return next;
  });

  if (mutated) {
    await env.STORAGE.put(STORAGE_KEYS.REPO_LIST, JSON.stringify(normalized));
  }
  return normalized;
}
```

- [ ] **Step 2:** 本地验证

```bash
npx wrangler dev --local
```

另开终端:

```bash
# 登录
curl -c /tmp/cm.cookies -X POST -d "password=admin123" http://localhost:8787/login

# 添加一个
curl -b /tmp/cm.cookies -X POST \
  -H "Content-Type: application/json" \
  -d '{"repo":"github/gitignore","branch":"main"}' \
  http://localhost:8787/api/repos

# 读回:应当看到 fork=null, addedAt 为 ISO 时间
curl -b /tmp/cm.cookies http://localhost:8787/api/repos
```

预期:返回的 repos[0] 包含 `"fork":null` 与 `"addedAt":"2026-..."` 字段。停 wrangler dev。

模拟旧数据迁移(可选 —— 在 wrangler dev 控制台或新会话内手动测):重启 wrangler dev,如果用持久化 KV(`wrangler dev` 默认 `--local` 用内存,这步可跳过验证),只需相信代码:`Object.prototype.hasOwnProperty.call` 对旧数据缺字段就会补。

- [ ] **Step 3:** 提交

```bash
git add worker.js
git commit -m "$(cat <<'EOF'
feat(repo): lazy-migrate repo entries with fork and addedAt fields

修改 getRepoList,读取时若条目缺 fork 或 addedAt 字段就补默认值
(fork: null, addedAt: 1970-01-01)并写回。让 Task 3 引入新字段后
旧 KV 数据仍能正常工作。

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: FORK 检测 + `POST /api/repos` 使用检测结果

**目标:** 新增 `fetchRepo` 与 `detectFork`,改 `POST /api/repos` 走 FORK 检测流程:输入上游或 FORK 都自动识别,监控对象统一为上游。

**Files:**
- Modify: `worker.js` 新增 `fetchRepo`、`detectFork` 函数
- Modify: `worker.js` 中 `handleApi` 的 `POST /api/repos` 分支

- [ ] **Step 1:** 在 `fetchGithubUser` 函数后(Task 4 添加的那个)追加 `fetchRepo` 与 `detectFork`

```javascript
async function fetchRepo(owner, repo, githubToken = null) {
  const url = `https://api.github.com/repos/${owner}/${repo}`;
  const headers = {
    'User-Agent': 'GitHub-Monitor-Bot',
    'Accept': 'application/vnd.github.v3+json'
  };
  if (githubToken) headers['Authorization'] = `token ${githubToken}`;

  const response = await fetch(url, { headers });
  if (response.status === 404) return { found: false };
  if (!response.ok) {
    if (response.status === 403) {
      throw new Error(githubToken
        ? 'GitHub API 频率限制(即使使用 Token 也达到限制)'
        : 'GitHub API 频率限制(未认证请求),请配置 GitHub Token');
    }
    throw new Error(`GitHub API错误: ${response.status} ${response.statusText}`);
  }
  const data = await response.json();
  return {
    found: true,
    full_name: data.full_name,
    fork: !!data.fork,
    parent: data.parent ? { owner: data.parent.owner?.login, repo: data.parent.name, full_name: data.parent.full_name } : null,
    stars: data.stargazers_count || 0
  };
}

/**
 * 输入用户填的 X/Y,返回 { upstream: {owner,repo}, fork: {owner,repo}|null }
 * - 若 X/Y 本身是 FORK → upstream=X/Y 的 parent,fork=X/Y
 * - 若 X/Y 是上游 → 查 me/Y,若是其 FORK 则 fork=me/Y,否则 fork=null
 */
async function detectFork(owner, repo, env, githubToken) {
  const info = await fetchRepo(owner, repo, githubToken);
  if (!info.found) {
    const err = new Error('Repository not found or not accessible');
    err.code = 'REPO_NOT_FOUND';
    throw err;
  }

  // 输入的是 FORK
  if (info.fork && info.parent) {
    return {
      upstream: { owner: info.parent.owner, repo: info.parent.repo },
      fork: { owner, repo }
    };
  }

  // 输入的是上游,尝试找用户名下同名 FORK
  let me = await env.STORAGE.get(STORAGE_KEYS.GITHUB_USERNAME);
  if (!me && githubToken) {
    try {
      me = await fetchGithubUser(githubToken);
      if (me) await env.STORAGE.put(STORAGE_KEYS.GITHUB_USERNAME, me);
    } catch {
      me = null;
    }
  }

  let fork = null;
  if (me && me !== owner) {
    const myFork = await fetchRepo(me, repo, githubToken);
    if (myFork.found && myFork.fork && myFork.parent && myFork.parent.full_name === `${owner}/${repo}`) {
      fork = { owner: me, repo };
    }
  }
  return { upstream: { owner, repo }, fork };
}
```

- [ ] **Step 2:** 替换 `handleApi` 中 `POST /api/repos` 分支的内部逻辑

找到 Task 3 加的 POST /api/repos 分支,把整段替换为:

```javascript
    // POST /api/repos
    if (path === '/api/repos' && method === 'POST') {
      const body = await readJsonBody(request);
      if (!body || typeof body.repo !== 'string') {
        return jsonError('Missing repo field', 'VALIDATION_ERROR', 400);
      }

      const repoFullName = (body.repo || '').trim();
      const branch = (body.branch || 'main').trim() || 'main';
      const parts = repoFullName.split('/');
      if (parts.length !== 2 || !parts[0] || !parts[1]) {
        return jsonError('Format must be owner/repo', 'VALIDATION_ERROR', 400);
      }
      const inputOwner = parts[0].trim();
      const inputRepo = parts[1].trim();
      const settings = await getSettings(env);

      let detected;
      try {
        detected = await detectFork(inputOwner, inputRepo, env, settings.github_token);
      } catch (e) {
        if (e.code === 'REPO_NOT_FOUND') return jsonError(e.message, 'REPO_NOT_FOUND', 404);
        const msg = String(e.message || e);
        if (msg.includes('频率限制')) return jsonError(msg, 'RATE_LIMITED', 429);
        return jsonError(msg, 'GITHUB_ERROR', 502);
      }

      const owner = detected.upstream.owner;
      const repo = detected.upstream.repo;
      const fork = detected.fork;

      const repoList = await getRepoList(env);
      const exists = repoList.some(r => r.owner === owner && r.repo === repo && r.branch === branch);
      if (exists) {
        return jsonError('Repository already monitored', 'REPO_DUPLICATE', 409);
      }

      // 校验分支存在
      try {
        await fetchLatestCommit(owner, repo, branch, settings.github_token);
      } catch (e) {
        const msg = String(e.message || e);
        if (msg.includes('频率限制')) return jsonError(msg, 'RATE_LIMITED', 429);
        if (msg.includes('仓库不存在')) return jsonError(msg, 'REPO_NOT_FOUND', 404);
        return jsonError(msg, 'GITHUB_ERROR', 502);
      }

      const item = { owner, repo, branch, fork, addedAt: new Date().toISOString() };
      repoList.push(item);
      await saveRepoList(repoList, env);
      return jsonResponse({ repo: item });
    }
```

- [ ] **Step 3:** 本地验证(此步需要真实 GitHub token,可跳过 fork 字段检测部分,仅验证无 token 时仍能添加上游)

```bash
npx wrangler dev --local
```

```bash
# 登录
curl -c /tmp/cm.cookies -X POST -d "password=admin123" http://localhost:8787/login

# 添加上游(无 token,fork 应为 null)
curl -b /tmp/cm.cookies -X POST \
  -H "Content-Type: application/json" \
  -d '{"repo":"github/gitignore","branch":"main"}' \
  http://localhost:8787/api/repos
# 预期: data.repo.fork == null,owner=github, repo=gitignore

# 删除
curl -b /tmp/cm.cookies -X DELETE \
  -H "Content-Type: application/json" \
  -d '{"owner":"github","repo":"gitignore","branch":"main"}' \
  http://localhost:8787/api/repos
```

带 token 的完整验证留到部署后:在 Settings 配置 token + test-github 后,再添加一个你有 FORK 的仓库,确认 fork 字段被正确填充。

- [ ] **Step 4:** 提交

```bash
git add worker.js
git commit -m "$(cat <<'EOF'
feat(repo): detect fork relationship and store fork field

新增 fetchRepo 与 detectFork。修改 POST /api/repos:
- 输入 X/Y 若是 FORK,则监控对象切到 parent,fork = 输入值
- 输入 X/Y 若是上游,且用户 token 已知,则查 me/Y,匹配 parent
  时 fork = me/Y,否则 fork = null
- 用户名优先读 KV 缓存,缺失时从 token 解析并写入缓存

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: `GET /api/repos/.../detail` + `POST /api/repos/fork`(一键 FORK)

**目标:** 展开行 detail 端点 + 一键 FORK 端点。detail 在 fork=null 时顺手探测一次(避免 list 接口放大调用)。

**Files:**
- Modify: `worker.js` 新增 `createGithubFork` 函数
- Modify: `worker.js` 中 `handleApi`

- [ ] **Step 1:** 在 `detectFork` 函数后追加 `createGithubFork`

```javascript
async function createGithubFork(owner, repo, githubToken) {
  const response = await fetch(`https://api.github.com/repos/${owner}/${repo}/forks`, {
    method: 'POST',
    headers: {
      'User-Agent': 'GitHub-Monitor-Bot',
      'Accept': 'application/vnd.github.v3+json',
      'Authorization': `token ${githubToken}`,
      'Content-Type': 'application/json'
    }
  });
  if (response.status === 202 || response.ok) return true;
  if (response.status === 401) throw new Error('GitHub Token 无效或缺少 public_repo 权限');
  if (response.status === 403) throw new Error('权限不足:token 需要 public_repo 权限');
  const body = await response.text();
  throw new Error(`Fork 创建失败: ${response.status} ${body}`);
}
```

- [ ] **Step 2:** 在 `handleApi` 的 try 块,`return jsonError('No route...')` 之前追加 2 个分支

```javascript
    // GET /api/repos/:owner/:repo/:branch/detail
    if (method === 'GET' && path.startsWith('/api/repos/') && path.endsWith('/detail')) {
      const slug = path.slice('/api/repos/'.length, -'/detail'.length);
      const slugParts = slug.split('/');
      if (slugParts.length !== 3) return jsonError('Bad detail path', 'VALIDATION_ERROR', 400);
      const [owner, repo, branch] = slugParts.map(decodeURIComponent);

      const repoList = await getRepoList(env);
      const idx = repoList.findIndex(r => r.owner === owner && r.repo === repo && r.branch === branch);
      if (idx < 0) return jsonError('Repository not in monitor list', 'REPO_NOT_FOUND', 404);
      const item = repoList[idx];

      const settings = await getSettings(env);
      let commits = [];
      let stars = null;
      try {
        const ghUrl = `https://api.github.com/repos/${owner}/${repo}/commits?sha=${branch}&per_page=5`;
        const headers = {
          'User-Agent': 'GitHub-Monitor-Bot',
          'Accept': 'application/vnd.github.v3+json'
        };
        if (settings.github_token) headers['Authorization'] = `token ${settings.github_token}`;
        const r = await fetch(ghUrl, { headers });
        if (r.ok) commits = await r.json();
      } catch (e) {
        console.error('detail commits fetch failed:', e);
      }
      try {
        const info = await fetchRepo(owner, repo, settings.github_token);
        if (info.found) stars = info.stars;
      } catch {}

      // 若仍无 fork,且 token 已配置,顺手探测一次(覆盖 FORK_IN_PROGRESS 的延迟到位场景)
      if (item.fork === null && settings.github_token) {
        try {
          let me = await env.STORAGE.get(STORAGE_KEYS.GITHUB_USERNAME);
          if (!me) {
            me = await fetchGithubUser(settings.github_token);
            if (me) await env.STORAGE.put(STORAGE_KEYS.GITHUB_USERNAME, me);
          }
          if (me && me !== owner) {
            const myFork = await fetchRepo(me, repo, settings.github_token);
            if (myFork.found && myFork.fork && myFork.parent && myFork.parent.full_name === `${owner}/${repo}`) {
              repoList[idx] = { ...item, fork: { owner: me, repo } };
              await saveRepoList(repoList, env);
              item.fork = { owner: me, repo };
            }
          }
        } catch (e) {
          console.error('detail fork retry failed:', e);
        }
      }

      const lastCommit = await getLastCommit(owner, repo, branch, env);
      return jsonResponse({
        repo: item,
        commits: commits.map(c => ({
          sha: c.sha,
          short: (c.sha || '').substring(0, 7),
          message: (c.commit?.message || '').split('\n')[0],
          author: c.commit?.author?.name || 'unknown',
          date: c.commit?.author?.date || null,
          url: c.html_url
        })),
        stars,
        lastKnownCommit: lastCommit
      });
    }

    // POST /api/repos/fork
    if (path === '/api/repos/fork' && method === 'POST') {
      const body = await readJsonBody(request);
      if (!body || !body.owner || !body.repo || !body.branch) {
        return jsonError('Missing owner / repo / branch', 'VALIDATION_ERROR', 400);
      }
      const { owner, repo, branch } = body;
      const settings = await getSettings(env);
      if (!settings.github_token) {
        return jsonError('GitHub Token not configured', 'GITHUB_TOKEN_REQUIRED', 400);
      }

      let me = await env.STORAGE.get(STORAGE_KEYS.GITHUB_USERNAME);
      if (!me) {
        try {
          me = await fetchGithubUser(settings.github_token);
          if (me) await env.STORAGE.put(STORAGE_KEYS.GITHUB_USERNAME, me);
        } catch (e) {
          return jsonError(String(e.message || e), 'GITHUB_ERROR', 502);
        }
      }
      if (!me) return jsonError('Cannot resolve GitHub username from token', 'GITHUB_TOKEN_REQUIRED', 400);

      try {
        await createGithubFork(owner, repo, settings.github_token);
      } catch (e) {
        const msg = String(e.message || e);
        if (msg.includes('权限')) return jsonError(msg, 'FORK_PERMISSION_DENIED', 403);
        return jsonError(msg, 'GITHUB_ERROR', 502);
      }

      // 轮询 me/repo,最多 10 次,每次 1s
      let forkOk = false;
      for (let i = 0; i < 10; i++) {
        await new Promise(r => setTimeout(r, 1000));
        try {
          const info = await fetchRepo(me, repo, settings.github_token);
          if (info.found && info.fork && info.parent && info.parent.full_name === `${owner}/${repo}`) {
            forkOk = true;
            break;
          }
        } catch {}
      }

      const repoList = await getRepoList(env);
      const idx = repoList.findIndex(r => r.owner === owner && r.repo === repo && r.branch === branch);

      if (forkOk) {
        if (idx >= 0) {
          repoList[idx] = { ...repoList[idx], fork: { owner: me, repo } };
          await saveRepoList(repoList, env);
        }
        return jsonResponse({ fork: { owner: me, repo }, complete: true });
      }
      return jsonError('Fork created but not yet visible. Refresh in a moment.', 'FORK_IN_PROGRESS', 202);
    }
```

- [ ] **Step 3:** 本地验证(仅验证不需 token 的部分;一键 FORK 与 detail 完整流程留到部署后用真实 token 测)

```bash
npx wrangler dev --local
```

```bash
# 登录
curl -c /tmp/cm.cookies -X POST -d "password=admin123" http://localhost:8787/login

# 添加
curl -b /tmp/cm.cookies -X POST \
  -H "Content-Type: application/json" \
  -d '{"repo":"github/gitignore","branch":"main"}' \
  http://localhost:8787/api/repos

# 拉详情
curl -b /tmp/cm.cookies http://localhost:8787/api/repos/github/gitignore/main/detail
# 预期: commits 数组非空,lastKnownCommit 可能为 null(首次)

# fork 端点 无 token(预期 400 GITHUB_TOKEN_REQUIRED)
curl -i -b /tmp/cm.cookies -X POST \
  -H "Content-Type: application/json" \
  -d '{"owner":"github","repo":"gitignore","branch":"main"}' \
  http://localhost:8787/api/repos/fork
```

- [ ] **Step 4:** 提交

```bash
git add worker.js
git commit -m "$(cat <<'EOF'
feat(api): add repo detail endpoint and one-click fork

新增:
- GET /api/repos/:owner/:repo/:branch/detail —— 拉最近 5 条提交、stars、
  上次记录的 SHA;若 fork=null 且 token 已配置,顺手探测一次
  (覆盖 FORK_IN_PROGRESS 后的延迟到位场景)
- POST /api/repos/fork —— 通过 POST /repos/{owner}/{repo}/forks 触发
  GitHub 创建 FORK,然后轮询 me/repo(最多 10 次/每秒)直到可见,
  把 fork 字段写入对应条目。超时返回 FORK_IN_PROGRESS 202。

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: 替换 SPA 外壳 + 主题切换 + 旧 UI / POST 处理函数删除

**目标:** 这是最大的一次提交。删除全部旧 dashboard HTML 与 POST 处理函数,把 `handleDashboard` 改为简单返回新 SPA 外壳(只含 layout、CSS、theme 切换、AJAX runtime,具体页内容由 JS 渲染),同时更新 `showLoginPage` 视觉到 GitHub 风。

**Files:**
- Modify: `worker.js` 中 `handleDashboard`(替换)
- Modify: `worker.js` 中 `showLoginPage`(替换样式)
- Delete: `worker.js` 中 `handleAddRepo` / `handleDeleteRepo` / `handleManualCheck` / `handleClearRepos` / `handleUpdateSettings` / `handleTestTelegram` / `handleTestGithub` / `handleChangePassword`(8 个函数)
- Delete: `worker.js` 中 `showDashboard` / `generateDashboardHTML`(2 个函数)
- Add: `worker.js` 末尾新增 `renderApp()` 返回新 SPA HTML(将 CSS / JS 字符串常量包在内)

- [ ] **Step 1:** 替换 `handleDashboard`(约第 213-252 行)

```javascript
async function handleDashboard(request, env, url) {
  await initAdminPassword(env);
  const auth = await checkAuth(request, env);
  if (!auth.authenticated) {
    const headers = new Headers();
    headers.set('Location', new URL('/login', request.url).toString());
    return new Response(null, { status: 302, headers });
  }
  return new Response(renderApp(), {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}
```

- [ ] **Step 2:** 删除以下 10 个函数(连同函数体)

按当前 worker.js 位置删除:

- `handleAddRepo`(255-298)
- `handleDeleteRepo`(300-317)
- `handleManualCheck`(319-326)
- `handleClearRepos`(328-331)
- `handleUpdateSettings`(334-350)
- `handleTestTelegram`(352-376)
- `handleTestGithub`(378-398)
- `handleChangePassword`(400-436)
- `showDashboard`(1239-1253)
- `generateDashboardHTML`(1255-2308,即从 `function generateDashboardHTML` 到文件最末尾、`renderApp` 之前的所有原 dashboard 函数体)

注意:`generateDashboardHTML` 是 worker.js 当前的最末函数,其结束 `}` 是文件中最后一行(2308 行的 `\`}`)。删完后,文件下一步追加 `renderApp` 与新 SPA 资源。

- [ ] **Step 3:** 替换 `showLoginPage`(约第 939-1237 行,即 `function showLoginPage(errorMessage = '') { ... }` 整段)

```javascript
function showLoginPage(errorMessage = '') {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign in · GitHub Monitor</title>
<script>
(function(){
  try {
    var t = localStorage.getItem('theme');
    if (t === 'dark') document.documentElement.setAttribute('data-theme','dark');
    else if (t === 'auto' || !t) {
      var dark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
      document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
    } else document.documentElement.setAttribute('data-theme','light');
  } catch(e) { document.documentElement.setAttribute('data-theme','light'); }
})();
</script>
<style>
${PRIMER_CSS_VARS}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;background:var(--bg-subtle);color:var(--fg);display:flex;align-items:center;justify-content:center;padding:24px;font-size:14px;line-height:1.5}
.card{width:100%;max-width:360px;background:var(--bg);border:1px solid var(--border);border-radius:6px;padding:24px;box-shadow:var(--shadow-md)}
.logo{text-align:center;margin-bottom:20px}
.logo-mark{width:48px;height:48px;border-radius:8px;background:var(--bg-emphasis);display:inline-flex;align-items:center;justify-content:center;color:var(--accent);font-size:24px;font-weight:700;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
h1{font-size:20px;font-weight:600;margin-top:12px}
.subtitle{color:var(--fg-muted);font-size:13px;margin-top:4px}
label{display:block;font-size:13px;font-weight:600;margin-bottom:6px}
input[type=password]{width:100%;padding:6px 12px;height:32px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--fg);font-size:14px;font-family:inherit}
input[type=password]:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(9,105,218,0.3)}
.btn{display:inline-flex;align-items:center;justify-content:center;width:100%;height:32px;padding:0 16px;border:1px solid rgba(31,35,40,0.15);border-radius:6px;font-size:14px;font-weight:500;cursor:pointer;background:var(--success);color:#fff}
.btn:hover{filter:brightness(0.95)}
.alert{padding:8px 12px;border-radius:6px;background:var(--danger-bg);color:var(--danger);border:1px solid var(--danger);font-size:13px;margin-bottom:16px}
.hint{margin-top:16px;padding:12px;background:var(--bg-subtle);border-radius:6px;font-size:12px;color:var(--fg-muted);border:1px solid var(--border-muted)}
</style>
</head>
<body>
<div class="card">
  <div class="logo">
    <div class="logo-mark">⌥</div>
    <h1>GitHub Monitor</h1>
    <div class="subtitle">Sign in to manage monitored repositories</div>
  </div>
  ${errorMessage ? `<div class="alert">${errorMessage}</div>` : ''}
  <form method="post">
    <div style="margin-bottom:16px">
      <label for="password">Password</label>
      <input type="password" id="password" name="password" autofocus required>
    </div>
    <button type="submit" class="btn">Sign in</button>
  </form>
  <div class="hint"><b>Default password:</b> admin123 · Change it after first login.</div>
</div>
</body>
</html>`;
  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}
```

- [ ] **Step 4:** 在 worker.js 末尾(`showLoginPage` 之后,即文件最后)追加 4 个新常量与 `renderApp` 函数。先追加 CSS 变量与外壳 CSS 常量:

```javascript
// ==================== 新 SPA 视觉资源 ====================
const PRIMER_CSS_VARS = `
:root{color-scheme:light}
[data-theme=light]{
  --bg:#ffffff; --bg-subtle:#f6f8fa; --bg-emphasis:#eaeef2;
  --border:#d0d7de; --border-muted:#eaeef2;
  --fg:#1f2328; --fg-muted:#656d76; --fg-subtle:#6e7781;
  --accent:#0969da; --accent-emphasis:#0550ae;
  --success:#1f883d; --success-bg:#dafbe1;
  --danger:#cf222e; --danger-bg:#ffebe9;
  --attention:#9a6700; --attention-bg:#fff8c5;
  --done:#8250df;
  --sidebar-active-bg:#ddf4ff; --sidebar-active-border:#fd7e14;
  --shadow:0 1px 0 rgba(31,35,40,0.04);
  --shadow-md:0 3px 6px rgba(140,149,159,0.15);
}
[data-theme=dark]{
  --bg:#0d1117; --bg-subtle:#161b22; --bg-emphasis:#21262d;
  --border:#30363d; --border-muted:#21262d;
  --fg:#e6edf3; --fg-muted:#7d8590; --fg-subtle:#6e7681;
  --accent:#2f81f7; --accent-emphasis:#388bfd;
  --success:#3fb950; --success-bg:#0f3017;
  --danger:#f85149; --danger-bg:#481620;
  --attention:#d29922; --attention-bg:#3b2300;
  --done:#a371f7;
  --sidebar-active-bg:#0d419d33; --sidebar-active-border:#fd7e14;
  --shadow:0 0 0 1px rgba(240,246,252,0.05);
  --shadow-md:0 8px 24px rgba(1,4,9,0.85);
  color-scheme:dark;
}
`;

const APP_CSS = `
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;background:var(--bg-subtle);color:var(--fg);font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased}
code,kbd,pre{font-family:ui-monospace,SFMono-Regular,SF Mono,Menlo,Consolas,Liberation Mono,monospace;font-size:12px}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
button{font-family:inherit;font-size:inherit;cursor:pointer;color:inherit}

.app{display:grid;grid-template-rows:auto 1fr;height:100vh}
.app-header{display:flex;align-items:center;gap:12px;padding:0 16px;height:48px;background:var(--bg);border-bottom:1px solid var(--border)}
.app-header .brand{font-weight:600;display:flex;align-items:center;gap:8px}
.app-header .brand-mark{width:24px;height:24px;border-radius:5px;background:var(--bg-emphasis);display:inline-flex;align-items:center;justify-content:center;color:var(--accent);font-family:ui-monospace,monospace;font-weight:700}
.app-header .spacer{flex:1}
.theme-switcher{display:inline-flex;background:var(--bg-subtle);border:1px solid var(--border);border-radius:6px;padding:2px}
.theme-switcher button{background:transparent;border:none;padding:4px 10px;border-radius:4px;color:var(--fg-muted);font-size:12px}
.theme-switcher button.active{background:var(--bg);color:var(--fg);box-shadow:var(--shadow)}
.icon-btn{background:transparent;border:1px solid transparent;padding:4px 8px;border-radius:6px;color:var(--fg-muted);font-size:12px}
.icon-btn:hover{background:var(--bg-subtle);color:var(--fg)}

.app-body{display:grid;grid-template-columns:240px 1fr;min-height:0}
.app.sidebar-collapsed .app-body{grid-template-columns:56px 1fr}
.sidebar{background:var(--bg);border-right:1px solid var(--border);overflow-y:auto;padding:12px 0}
.sidebar-group{padding:8px 12px}
.sidebar-group-label{font-size:11px;font-weight:600;color:var(--fg-muted);letter-spacing:0.5px;text-transform:uppercase;padding:4px 8px;margin-bottom:4px}
.app.sidebar-collapsed .sidebar-group-label{display:none}
.sidebar-item{display:flex;align-items:center;gap:8px;padding:6px 12px;border-radius:6px;color:var(--fg);font-size:13px;cursor:pointer;border-left:2px solid transparent;text-decoration:none}
.sidebar-item:hover{background:var(--bg-subtle);text-decoration:none}
.sidebar-item.active{background:var(--sidebar-active-bg);border-left-color:var(--sidebar-active-border);color:var(--fg);font-weight:600}
.sidebar-item .icon{width:16px;display:inline-flex;justify-content:center;font-size:14px}
.app.sidebar-collapsed .sidebar-item .label{display:none}

.main{overflow-y:auto;padding:24px;min-width:0}
.page{max-width:960px;margin:0 auto}
.page-header{display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap}
.page-header h2{font-size:20px;font-weight:600}
.page-header .count{color:var(--fg-muted);font-weight:400}
.page-header .actions{margin-left:auto;display:flex;gap:8px}

.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;height:32px;padding:0 12px;border:1px solid rgba(31,35,40,0.15);border-radius:6px;font-size:14px;font-weight:500;background:var(--bg-subtle);color:var(--fg);transition:filter 0.1s}
.btn:hover{filter:brightness(0.97)}
.btn-primary{background:var(--success);color:#fff;border-color:rgba(31,35,40,0.15)}
.btn-secondary{background:var(--bg);color:var(--fg);border-color:var(--border)}
.btn-danger{background:var(--bg);color:var(--danger);border-color:var(--border)}
.btn-danger:hover{background:var(--danger);color:#fff;border-color:var(--danger)}
.btn-sm{height:26px;padding:0 8px;font-size:12px}
.btn[disabled]{opacity:0.5;cursor:not-allowed}

.card{background:var(--bg);border:1px solid var(--border);border-radius:6px;overflow:hidden}
.card-head{padding:12px 16px;background:var(--bg-subtle);border-bottom:1px solid var(--border);font-weight:600;font-size:14px}
.card-body{padding:16px}

.list{background:var(--bg);border:1px solid var(--border);border-radius:6px;overflow:hidden}
.list-row{display:flex;align-items:center;gap:12px;padding:10px 16px;border-bottom:1px solid var(--border)}
.list-row:last-child{border-bottom:none}
.list-row .toggle{background:transparent;border:none;color:var(--fg-muted);padding:4px;font-size:12px;transition:transform 0.15s}
.list-row.expanded .toggle{transform:rotate(90deg)}
.list-row .title{font-weight:600;color:var(--accent);min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.list-row .branch{background:var(--bg-subtle);border:1px solid var(--border);border-radius:20px;padding:0 8px;font-size:11px;color:var(--fg-muted);font-family:ui-monospace,monospace}
.list-row .fork{color:var(--fg-muted);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.list-row .fork a{color:var(--accent)}
.list-row .right{margin-left:auto;display:flex;align-items:center;gap:8px}
.list-row .meta{color:var(--fg-muted);font-size:12px;display:flex;align-items:center;gap:6px}
.dot{width:6px;height:6px;border-radius:50%}
.dot-ok{background:var(--success)}
.dot-warn{background:var(--attention)}
.dot-err{background:var(--danger)}
.dot-muted{background:var(--fg-muted)}

.expand-body{padding:12px 16px 16px 44px;background:var(--bg-subtle);border-bottom:1px solid var(--border);font-size:13px}
.expand-body .commit-row{padding:6px 0;border-bottom:1px dashed var(--border-muted);font-size:13px}
.expand-body .commit-row:last-child{border-bottom:none}
.expand-body .commit-row code{color:var(--accent);margin-right:6px}
.expand-body .commit-row .commit-author{color:var(--fg-muted);font-size:11px;margin-top:2px}

.empty{padding:48px 16px;text-align:center;color:var(--fg-muted)}
.empty .icon{font-size:32px;margin-bottom:12px}

.field{margin-bottom:16px}
.field label{display:block;font-weight:600;font-size:13px;margin-bottom:4px}
.field .hint{font-size:12px;color:var(--fg-muted);margin-top:4px}
.field input[type=text],.field input[type=password]{width:100%;height:32px;padding:6px 12px;border:1px solid var(--border);border-radius:6px;background:var(--bg);color:var(--fg);font-size:14px;font-family:inherit}
.field input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(9,105,218,0.3)}
.field-inline{display:flex;gap:8px;align-items:center}
.field-inline input{flex:1}

.switch{position:relative;display:inline-block;width:40px;height:22px}
.switch input{opacity:0;width:0;height:0}
.switch .slider{position:absolute;cursor:pointer;inset:0;background:var(--border);border-radius:22px;transition:0.2s}
.switch .slider::before{position:absolute;content:"";width:18px;height:18px;left:2px;top:2px;background:#fff;border-radius:50%;transition:0.2s}
.switch input:checked + .slider{background:var(--success)}
.switch input:checked + .slider::before{transform:translateX(18px)}

.modal-backdrop{position:fixed;inset:0;background:rgba(0,0,0,0.5);display:flex;align-items:center;justify-content:center;padding:24px;z-index:100}
.modal{background:var(--bg);border:1px solid var(--border);border-radius:6px;width:100%;max-width:480px;max-height:90vh;overflow:auto;box-shadow:var(--shadow-md)}
.modal-head{display:flex;align-items:center;padding:12px 16px;background:var(--bg-subtle);border-bottom:1px solid var(--border);font-weight:600}
.modal-head .close{margin-left:auto;background:transparent;border:none;color:var(--fg-muted);font-size:18px;cursor:pointer}
.modal-body{padding:16px}
.modal-foot{padding:12px 16px;background:var(--bg-subtle);border-top:1px solid var(--border);display:flex;justify-content:flex-end;gap:8px}
.inline-error{margin-top:8px;padding:8px 12px;border-radius:6px;background:var(--danger-bg);color:var(--danger);font-size:13px}

.toasts{position:fixed;right:16px;bottom:16px;display:flex;flex-direction:column;gap:8px;z-index:200}
.toast{background:var(--bg);border:1px solid var(--border);border-left-width:4px;border-radius:6px;padding:10px 16px;min-width:240px;font-size:13px;box-shadow:var(--shadow-md);color:var(--fg)}
.toast.toast-ok{border-left-color:var(--success)}
.toast.toast-err{border-left-color:var(--danger)}
.toast.toast-warn{border-left-color:var(--attention)}

@media (max-width: 768px){
  .app-body{grid-template-columns:0 1fr}
  .sidebar{position:fixed;top:48px;left:-240px;bottom:0;width:240px;z-index:50;transition:left 0.2s}
  .app.sidebar-open .sidebar{left:0}
  .app.sidebar-open::before{content:"";position:fixed;inset:48px 0 0;background:rgba(0,0,0,0.5);z-index:40}
}
`;
```

紧接其后,继续追加 `APP_JS` 常量(SPA 前端 JS,包含路由 / fetch wrappers / 各页渲染):

```javascript
const APP_JS = `
(function(){
  // ---------- 主题 ----------
  function applyTheme(t){
    if (t === 'auto') {
      var dark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
      document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
    } else {
      document.documentElement.setAttribute('data-theme', t);
    }
  }
  function initTheme(){
    var t = localStorage.getItem('theme') || 'auto';
    applyTheme(t);
    document.querySelectorAll('.theme-switcher button').forEach(function(b){
      b.classList.toggle('active', b.dataset.theme === t);
      b.onclick = function(){
        localStorage.setItem('theme', b.dataset.theme);
        document.querySelectorAll('.theme-switcher button').forEach(function(x){
          x.classList.toggle('active', x.dataset.theme === b.dataset.theme);
        });
        applyTheme(b.dataset.theme);
      };
    });
    if (window.matchMedia) {
      window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function(){
        if ((localStorage.getItem('theme') || 'auto') === 'auto') applyTheme('auto');
      });
    }
  }

  // ---------- 侧边栏折叠 ----------
  function initSidebar(){
    var app = document.querySelector('.app');
    if (localStorage.getItem('sidebar_collapsed') === '1') app.classList.add('sidebar-collapsed');
    document.getElementById('sidebar-toggle').onclick = function(){
      if (window.innerWidth <= 768) {
        app.classList.toggle('sidebar-open');
      } else {
        app.classList.toggle('sidebar-collapsed');
        localStorage.setItem('sidebar_collapsed', app.classList.contains('sidebar-collapsed') ? '1' : '0');
      }
    };
  }

  // ---------- Toast ----------
  var toastBox;
  function toast(msg, kind){
    if (!toastBox) toastBox = document.querySelector('.toasts');
    var el = document.createElement('div');
    el.className = 'toast toast-' + (kind || 'ok');
    el.textContent = msg;
    toastBox.appendChild(el);
    setTimeout(function(){ el.remove(); }, 3000);
  }

  // ---------- API ----------
  async function api(method, path, body){
    var opts = { method: method, headers: { 'Content-Type': 'application/json' } };
    if (body !== undefined) opts.body = JSON.stringify(body);
    var r = await fetch(path, opts);
    var data;
    try { data = await r.json(); } catch(_) { data = { ok:false, error:'Bad response', code:'INTERNAL' }; }
    if (r.status === 401) { location.href = '/login'; throw new Error('Unauthorized'); }
    if (!data.ok) {
      var e = new Error(data.error || 'Request failed');
      e.code = data.code || 'INTERNAL';
      e.status = r.status;
      throw e;
    }
    return data.data;
  }

  // ---------- 路由 ----------
  var routes = ['repos', 'activity', 'telegram', 'github', 'schedule', 'security'];
  function navigateTo(page){
    if (routes.indexOf(page) < 0) page = 'repos';
    document.querySelectorAll('.sidebar-item').forEach(function(el){
      el.classList.toggle('active', el.dataset.page === page);
    });
    history.replaceState(null, '', '#/' + page);
    document.querySelector('.app').classList.remove('sidebar-open');
    var view = document.getElementById('view');
    view.innerHTML = '<div class="empty">Loading...</div>';
    var renderer = window.__pages__[page];
    if (renderer) renderer(view).catch(function(e){
      view.innerHTML = '<div class="empty">Failed: ' + (e.message || e) + '</div>';
    });
  }
  function bindNav(){
    document.querySelectorAll('.sidebar-item').forEach(function(el){
      el.onclick = function(e){ e.preventDefault(); navigateTo(el.dataset.page); };
    });
    window.addEventListener('hashchange', function(){
      var p = (location.hash || '#/repos').replace(/^#\\//, '');
      navigateTo(p);
    });
  }

  // ---------- 工具 ----------
  function escapeHtml(s){
    if (s == null) return '';
    return String(s).replace(/[&<>"']/g, function(c){
      return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
    });
  }
  function timeAgo(iso){
    if (!iso) return '—';
    var d = new Date(iso).getTime();
    if (!d) return '—';
    var diff = (Date.now() - d) / 1000;
    if (diff < 60) return Math.floor(diff) + 's ago';
    if (diff < 3600) return Math.floor(diff/60) + 'm ago';
    if (diff < 86400) return Math.floor(diff/3600) + 'h ago';
    return Math.floor(diff/86400) + 'd ago';
  }
  function ghUrl(owner, repo){ return 'https://github.com/' + owner + '/' + repo; }

  // 页渲染器在 Task 9 内填充
  window.__pages__ = {};
  window.__app__ = { api: api, toast: toast, escapeHtml: escapeHtml, timeAgo: timeAgo, ghUrl: ghUrl, navigateTo: navigateTo };

  // ---------- 启动 ----------
  function start(){
    initTheme();
    initSidebar();
    bindNav();
    var p = (location.hash || '#/repos').replace(/^#\\//, '');
    navigateTo(p);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();

  // 登出
  document.addEventListener('click', function(e){
    if (e.target && e.target.matches('[data-action=logout]')) {
      e.preventDefault();
      fetch('/logout').then(function(){ location.href = '/login'; });
    }
  });
})();
`;
```

紧接其后追加 `renderApp` 函数:

```javascript
function renderApp(){
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>GitHub Monitor</title>
<script>
(function(){
  try {
    var t = localStorage.getItem('theme') || 'auto';
    if (t === 'auto') {
      var dark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
      document.documentElement.setAttribute('data-theme', dark ? 'dark' : 'light');
    } else document.documentElement.setAttribute('data-theme', t);
  } catch(e) { document.documentElement.setAttribute('data-theme','light'); }
})();
</script>
<style>${PRIMER_CSS_VARS}${APP_CSS}</style>
</head>
<body>
<div class="app">
  <header class="app-header">
    <button class="icon-btn" id="sidebar-toggle" title="Toggle sidebar">☰</button>
    <div class="brand">
      <span class="brand-mark">⌥</span>
      <span>GitHub Monitor</span>
    </div>
    <div class="spacer"></div>
    <div class="theme-switcher">
      <button data-theme="light" title="Light">☀</button>
      <button data-theme="dark" title="Dark">☾</button>
      <button data-theme="auto" title="Auto">⚙</button>
    </div>
    <button class="icon-btn" data-action="logout" title="Sign out">↩ Sign out</button>
  </header>
  <div class="app-body">
    <nav class="sidebar">
      <div class="sidebar-group">
        <div class="sidebar-group-label">Monitor</div>
        <a class="sidebar-item active" data-page="repos" href="#/repos"><span class="icon">📦</span><span class="label">Repositories</span></a>
        <a class="sidebar-item" data-page="activity" href="#/activity"><span class="icon">📊</span><span class="label">Activity</span></a>
      </div>
      <div class="sidebar-group">
        <div class="sidebar-group-label">Settings</div>
        <a class="sidebar-item" data-page="telegram" href="#/telegram"><span class="icon">💬</span><span class="label">Telegram</span></a>
        <a class="sidebar-item" data-page="github" href="#/github"><span class="icon">🔑</span><span class="label">GitHub Token</span></a>
        <a class="sidebar-item" data-page="schedule" href="#/schedule"><span class="icon">⏰</span><span class="label">Schedule</span></a>
        <a class="sidebar-item" data-page="security" href="#/security"><span class="icon">🔒</span><span class="label">Security</span></a>
      </div>
    </nav>
    <main class="main">
      <div id="view" class="page"></div>
    </main>
  </div>
  <div class="toasts"></div>
</div>
<script>${APP_JS}</script>
</body>
</html>`;
}
```

- [ ] **Step 4:** 本地验证

```bash
npx wrangler dev --local
```

浏览器打开 http://localhost:8787,登录(admin123)。预期:
- 看到 GitHub 风的新 layout(header + 左侧栏 + 主区)
- 侧边栏列出 Repositories / Activity / Telegram / GitHub Token / Schedule / Security
- 点击任一项,主区显示 `Failed: ...` 或 `Loading...`(因为 Task 9 还没实现页渲染器,这是预期)
- 右上角主题切换可点(light / dark / auto)切换后立即换色
- 侧边栏汉堡按钮可折叠 / 展开,刷新后保持
- 登录页样式切到新主题(`/login` 访问)

也可 curl 验证旧 POST 路径不再处理:

```bash
curl -i -b /tmp/cm.cookies -X POST -d "action=add&repo_full_name=foo/bar&branch=main" http://localhost:8787/
```

预期:返回 SPA HTML(因为 handleDashboard 现在不处理 POST,只返回 renderApp);或者返回 404(取决于实现细节)。停 wrangler dev。

- [ ] **Step 5:** 提交

```bash
git add worker.js
git commit -m "$(cat <<'EOF'
feat(ui): new SPA shell with sidebar and theme switcher

替换 handleDashboard 返回新 SPA 外壳(header + sidebar + main),
含 Primer light/dark CSS 变量、theme switcher、sidebar 折叠状态
持久化、AJAX runtime(api/toast/路由/工具函数)。删除 10 个旧
表单 POST 处理函数与旧 generateDashboardHTML / showDashboard。
showLoginPage 也切到 GitHub 风。

后续 Task 9 在 window.__pages__ 上注册具体页渲染器。

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: 注册各页渲染器(Repositories / Activity / Settings 4 子页)

**目标:** 在 `APP_JS` 中扩展 `window.__pages__`,让 6 个路由都能渲染。Repositories 页含列表 + 展开 + Add 模态框 + Fork it;Activity 页含 last check / cron log + Run check;Settings 4 个子页各自的表单 + Save / Test。

**Files:**
- Modify: `worker.js` 中 `APP_JS` 常量(替换为完整版,在 IIFE 末尾添加所有页渲染器)

- [ ] **Step 1:** 把 `APP_JS` 常量中 `window.__pages__ = {};` 一行替换为完整页渲染器集。

找到现有的:

```javascript
  // 页渲染器在 Task 9 内填充
  window.__pages__ = {};
  window.__app__ = { api: api, toast: toast, escapeHtml: escapeHtml, timeAgo: timeAgo, ghUrl: ghUrl, navigateTo: navigateTo };
```

替换为(替换 `window.__pages__ = {};` 一行,保留后面 `window.__app__ = ...`):

```javascript
  // ---------- Repositories 页 ----------
  async function renderRepos(view){
    var data = await api('GET', '/api/repos');
    var repos = (data.repos || []).slice().sort(function(a,b){
      return (b.addedAt||'').localeCompare(a.addedAt||'');
    });

    view.innerHTML =
      '<div class="page-header">' +
        '<h2>Repositories <span class="count">· ' + repos.length + ' monitored</span></h2>' +
        '<div class="actions">' +
          '<button class="btn btn-secondary btn-sm" id="check-now">Check now</button>' +
          '<button class="btn btn-primary btn-sm" id="add-repo">+ Add repository</button>' +
        '</div>' +
      '</div>' +
      (repos.length === 0
        ? '<div class="empty"><div class="icon">📦</div>No repositories monitored. Click <b>+ Add repository</b> to start.</div>'
        : '<div class="list" id="repo-list">' + repos.map(rowHtml).join('') + '</div>');

    document.getElementById('add-repo').onclick = openAddModal;
    document.getElementById('check-now').onclick = async function(){
      this.disabled = true; this.textContent = 'Checking...';
      try {
        var r = await api('POST', '/api/check');
        toast('Check complete: ' + (r.result && r.result.message ? r.result.message : 'OK'), 'ok');
      } catch(e) { toast(e.message, 'err'); }
      this.disabled = false; this.textContent = 'Check now';
    };

    document.querySelectorAll('.list-row').forEach(function(row){
      row.querySelector('.toggle').onclick = function(){ toggleExpand(row); };
      var fk = row.querySelector('[data-action=fork-it]');
      if (fk) fk.onclick = function(){ doForkIt(row); };
      var rm = row.querySelector('[data-action=remove]');
      if (rm) rm.onclick = function(){ doRemove(row); };
    });
  }

  function rowHtml(r){
    var slug = r.owner + '/' + r.repo + '/' + r.branch;
    var fork = r.fork
      ? '<span class="fork">↳ <a href="' + window.__app__.ghUrl(r.fork.owner, r.fork.repo) + '" target="_blank">' + escapeHtml(r.fork.owner) + '/' + escapeHtml(r.fork.repo) + '</a></span>'
      : '<button class="btn btn-secondary btn-sm" data-action="fork-it">Fork it</button>';
    return '<div class="list-row" data-slug="' + escapeHtml(slug) + '" data-owner="' + escapeHtml(r.owner) + '" data-repo="' + escapeHtml(r.repo) + '" data-branch="' + escapeHtml(r.branch) + '">' +
      '<button class="toggle">▸</button>' +
      '<a class="title" href="' + window.__app__.ghUrl(r.owner, r.repo) + '" target="_blank">' + escapeHtml(r.owner) + '/' + escapeHtml(r.repo) + '</a>' +
      '<span class="branch">' + escapeHtml(r.branch) + '</span>' +
      fork +
      '<div class="right">' +
        '<span class="meta">Added ' + timeAgo(r.addedAt) + '</span>' +
        '<button class="btn btn-danger btn-sm" data-action="remove">Remove</button>' +
      '</div>' +
    '</div>';
  }

  async function toggleExpand(row){
    if (row.classList.contains('expanded')) {
      row.classList.remove('expanded');
      var body = row.nextElementSibling;
      if (body && body.classList.contains('expand-body')) body.remove();
      return;
    }
    row.classList.add('expanded');
    var owner = row.dataset.owner, repo = row.dataset.repo, branch = row.dataset.branch;
    var body = document.createElement('div');
    body.className = 'expand-body';
    body.innerHTML = '<div>Loading...</div>';
    row.parentNode.insertBefore(body, row.nextSibling);
    try {
      var d = await api('GET', '/api/repos/' + encodeURIComponent(owner) + '/' + encodeURIComponent(repo) + '/' + encodeURIComponent(branch) + '/detail');
      var commitsHtml = (d.commits || []).map(function(c){
        return '<div class="commit-row"><div><code>' + escapeHtml(c.short) + '</code>' + escapeHtml(c.message) + '</div><div class="commit-author">' + escapeHtml(c.author) + ' · ' + timeAgo(c.date) + '</div></div>';
      }).join('') || '<div class="commit-row">No recent commits</div>';
      var lastKnown = d.lastKnownCommit ? '<code>' + escapeHtml(d.lastKnownCommit.substring(0,7)) + '</code>' : '<i>never checked</i>';
      var stars = (d.stars != null) ? (' · ★ ' + d.stars) : '';
      body.innerHTML = commitsHtml + '<div style="margin-top:8px;color:var(--fg-muted);font-size:12px">Last known: ' + lastKnown + stars + '</div>';
    } catch(e) {
      body.innerHTML = '<div style="color:var(--danger)">Failed: ' + escapeHtml(e.message) + ' <button class="btn btn-sm" id="retry-detail">Retry</button></div>';
      var rb = body.querySelector('#retry-detail');
      if (rb) rb.onclick = function(){ row.classList.remove('expanded'); body.remove(); toggleExpand(row); };
    }
  }

  async function doForkIt(row){
    var btn = row.querySelector('[data-action=fork-it]');
    btn.disabled = true; btn.textContent = 'Forking...';
    try {
      var r = await api('POST', '/api/repos/fork', { owner: row.dataset.owner, repo: row.dataset.repo, branch: row.dataset.branch });
      toast('Fork ready: ' + r.fork.owner + '/' + r.fork.repo, 'ok');
      window.__app__.navigateTo('repos');
    } catch(e) {
      if (e.code === 'GITHUB_TOKEN_REQUIRED') {
        toast('Configure GitHub token first', 'warn');
        window.__app__.navigateTo('github');
      } else if (e.code === 'FORK_PERMISSION_DENIED') {
        toast('Token lacks public_repo permission', 'err');
      } else if (e.code === 'FORK_IN_PROGRESS') {
        toast('Fork in progress on GitHub. Refresh shortly.', 'warn');
      } else {
        toast(e.message, 'err');
      }
      btn.disabled = false; btn.textContent = 'Fork it';
    }
  }

  async function doRemove(row){
    if (!confirm('Remove ' + row.dataset.owner + '/' + row.dataset.repo + ' (' + row.dataset.branch + ')?')) return;
    try {
      await api('DELETE', '/api/repos', { owner: row.dataset.owner, repo: row.dataset.repo, branch: row.dataset.branch });
      toast('Removed', 'ok');
      window.__app__.navigateTo('repos');
    } catch(e) { toast(e.message, 'err'); }
  }

  function openAddModal(){
    var wrap = document.createElement('div');
    wrap.className = 'modal-backdrop';
    wrap.innerHTML =
      '<div class="modal">' +
        '<div class="modal-head">Add repository<button class="close">×</button></div>' +
        '<div class="modal-body">' +
          '<div class="field"><label>Repository</label>' +
            '<input type="text" id="add-repo-input" placeholder="facebook/react" autofocus>' +
            '<div class="hint">Either upstream or your fork — we will detect and link them.</div></div>' +
          '<div class="field"><label>Branch</label>' +
            '<input type="text" id="add-branch-input" value="main">' +
          '</div>' +
          '<div id="add-error" class="inline-error" style="display:none"></div>' +
        '</div>' +
        '<div class="modal-foot">' +
          '<button class="btn btn-secondary" id="add-cancel">Cancel</button>' +
          '<button class="btn btn-primary" id="add-submit">Add</button>' +
        '</div>' +
      '</div>';
    document.body.appendChild(wrap);
    function close(){ wrap.remove(); }
    wrap.querySelector('.close').onclick = close;
    wrap.querySelector('#add-cancel').onclick = close;
    wrap.addEventListener('click', function(e){ if (e.target === wrap) close(); });
    wrap.querySelector('#add-submit').onclick = async function(){
      var btn = this;
      var input = wrap.querySelector('#add-repo-input').value.trim();
      var branch = wrap.querySelector('#add-branch-input').value.trim() || 'main';
      var err = wrap.querySelector('#add-error');
      err.style.display = 'none';
      if (input.indexOf('/') < 0) { err.textContent = 'Format: owner/repo'; err.style.display = 'block'; return; }
      btn.disabled = true; btn.textContent = 'Adding...';
      try {
        await api('POST', '/api/repos', { repo: input, branch: branch });
        close();
        toast('Added', 'ok');
        window.__app__.navigateTo('repos');
      } catch(e){
        err.textContent = e.message + (e.code ? ' (' + e.code + ')' : '');
        err.style.display = 'block';
        btn.disabled = false; btn.textContent = 'Add';
      }
    };
  }

  // ---------- Activity 页 ----------
  async function renderActivity(view){
    var d = await api('GET', '/api/activity');
    var log = d.lastCronLog;
    var logHtml = log
      ? '<div class="card"><div class="card-head">Latest cron run <span style="float:right;color:var(--fg-muted);font-weight:400">' + escapeHtml(log.startTime) + '</span></div>' +
        '<div class="card-body">' +
          '<div><b>Status:</b> ' + (log.success ? '<span class="dot dot-ok"></span> Success' : '<span class="dot dot-err"></span> Failed') + '</div>' +
          '<div><b>Duration:</b> ' + escapeHtml(log.duration || '') + '</div>' +
          (log.result && log.result.message ? '<div><b>Result:</b> ' + escapeHtml(log.result.message) + '</div>' : '') +
          (log.error ? '<div style="color:var(--danger)"><b>Error:</b> <code>' + escapeHtml(log.error) + '</code></div>' : '') +
        '</div></div>'
      : '<div class="card"><div class="card-head">Latest cron run</div><div class="card-body"><i>No cron run yet</i></div></div>';

    view.innerHTML =
      '<div class="page-header"><h2>Activity</h2>' +
        '<div class="actions"><button class="btn btn-primary btn-sm" id="run-check">Run check now</button></div>' +
      '</div>' +
      '<div class="card" style="margin-bottom:16px"><div class="card-head">Last check</div>' +
        '<div class="card-body">' + escapeHtml(d.lastCheckTime || '从未检查') + '</div></div>' +
      logHtml;

    document.getElementById('run-check').onclick = async function(){
      this.disabled = true; this.textContent = 'Checking...';
      try {
        var r = await api('POST', '/api/check');
        toast(r.result && r.result.message ? r.result.message : 'Check complete', 'ok');
        window.__app__.navigateTo('activity');
      } catch(e){ toast(e.message, 'err'); this.disabled = false; this.textContent = 'Run check now'; }
    };
  }

  // ---------- Settings 子页 ----------
  async function renderTelegram(view){
    var s = (await api('GET', '/api/settings')).settings;
    view.innerHTML =
      '<div class="page-header"><h2>Telegram</h2></div>' +
      '<div class="card"><div class="card-head">Bot configuration</div><div class="card-body">' +
        '<div class="field"><label>Bot Token</label>' +
          '<input type="password" id="tg-token" value="' + escapeHtml(s.tg_bot_token || '') + '">' +
          '<div class="hint">Create via <a href="https://t.me/BotFather" target="_blank">@BotFather</a></div></div>' +
        '<div class="field"><label>Chat ID</label>' +
          '<input type="text" id="tg-chat" value="' + escapeHtml(s.tg_chat_id || '') + '"></div>' +
        '<div style="display:flex;gap:8px">' +
          '<button class="btn btn-primary btn-sm" id="tg-save">Save</button>' +
          '<button class="btn btn-secondary btn-sm" id="tg-test">Test</button>' +
        '</div>' +
      '</div></div>';
    document.getElementById('tg-save').onclick = async function(){
      this.disabled = true;
      try {
        await api('PUT', '/api/settings', {
          tg_bot_token: document.getElementById('tg-token').value,
          tg_chat_id: document.getElementById('tg-chat').value
        });
        toast('Saved', 'ok');
      } catch(e){ toast(e.message, 'err'); }
      this.disabled = false;
    };
    document.getElementById('tg-test').onclick = async function(){
      this.disabled = true;
      try { await api('POST', '/api/settings/test-telegram'); toast('Test message sent', 'ok'); }
      catch(e){ toast(e.message, 'err'); }
      this.disabled = false;
    };
  }

  async function renderGithub(view){
    var s = (await api('GET', '/api/settings')).settings;
    view.innerHTML =
      '<div class="page-header"><h2>GitHub Token</h2></div>' +
      '<div class="card"><div class="card-head">Personal access token</div><div class="card-body">' +
        '<div class="field"><label>Token <span style="color:var(--fg-muted);font-weight:400">(scope: public_repo)</span></label>' +
          '<div class="field-inline">' +
            '<input type="password" id="gh-token" value="' + escapeHtml(s.github_token || '') + '">' +
            '<button class="btn btn-sm" id="gh-show">Show</button>' +
          '</div>' +
          '<div class="hint">Generate via <a href="https://github.com/settings/tokens" target="_blank">GitHub Developer Settings</a>. Required for one-click Fork it.</div>' +
        '</div>' +
        '<div style="display:flex;gap:8px">' +
          '<button class="btn btn-primary btn-sm" id="gh-save">Save</button>' +
          '<button class="btn btn-secondary btn-sm" id="gh-test">Test</button>' +
        '</div>' +
        '<div id="gh-user" style="margin-top:12px;color:var(--fg-muted);font-size:12px"></div>' +
      '</div></div>';
    document.getElementById('gh-show').onclick = function(){
      var i = document.getElementById('gh-token');
      i.type = i.type === 'password' ? 'text' : 'password';
    };
    document.getElementById('gh-save').onclick = async function(){
      this.disabled = true;
      try {
        await api('PUT', '/api/settings', { github_token: document.getElementById('gh-token').value });
        toast('Saved', 'ok');
      } catch(e){ toast(e.message, 'err'); }
      this.disabled = false;
    };
    document.getElementById('gh-test').onclick = async function(){
      this.disabled = true;
      try {
        var r = await api('POST', '/api/settings/test-github');
        document.getElementById('gh-user').textContent = 'Authenticated as: ' + r.username;
        toast('Token OK · ' + r.username, 'ok');
      } catch(e){ toast(e.message, 'err'); }
      this.disabled = false;
    };
  }

  async function renderSchedule(view){
    var s = (await api('GET', '/api/settings')).settings;
    view.innerHTML =
      '<div class="page-header"><h2>Schedule</h2></div>' +
      '<div class="card"><div class="card-head">Cron notification</div><div class="card-body">' +
        '<div style="display:flex;align-items:center;gap:12px">' +
          '<label class="switch"><input type="checkbox" id="cron-toggle"' + (s.cron_notification_enabled ? ' checked' : '') + '><span class="slider"></span></label>' +
          '<div><b>Send Telegram log after each cron run</b><div class="hint">Cron schedule itself is configured in wrangler.toml / Cloudflare dashboard.</div></div>' +
        '</div>' +
      '</div></div>';
    document.getElementById('cron-toggle').onchange = async function(){
      try {
        await api('PUT', '/api/settings', { cron_notification_enabled: this.checked });
        toast('Saved', 'ok');
      } catch(e){ toast(e.message, 'err'); this.checked = !this.checked; }
    };
  }

  async function renderSecurity(view){
    view.innerHTML =
      '<div class="page-header"><h2>Security</h2></div>' +
      '<div class="card"><div class="card-head">Change password</div><div class="card-body">' +
        '<div class="field"><label>Current password</label><input type="password" id="pw-cur"></div>' +
        '<div class="field"><label>New password</label><input type="password" id="pw-new"></div>' +
        '<div class="field"><label>Confirm new password</label><input type="password" id="pw-cfm"></div>' +
        '<button class="btn btn-primary btn-sm" id="pw-save">Update password</button>' +
      '</div></div>';
    document.getElementById('pw-save').onclick = async function(){
      this.disabled = true;
      try {
        await api('PUT', '/api/password', {
          current: document.getElementById('pw-cur').value,
          new: document.getElementById('pw-new').value,
          confirm: document.getElementById('pw-cfm').value
        });
        toast('Password updated', 'ok');
        ['pw-cur','pw-new','pw-cfm'].forEach(function(id){ document.getElementById(id).value = ''; });
      } catch(e){ toast(e.message, 'err'); }
      this.disabled = false;
    };
  }

  window.__pages__ = {
    repos: renderRepos,
    activity: renderActivity,
    telegram: renderTelegram,
    github: renderGithub,
    schedule: renderSchedule,
    security: renderSecurity
  };
  window.__app__ = { api: api, toast: toast, escapeHtml: escapeHtml, timeAgo: timeAgo, ghUrl: ghUrl, navigateTo: navigateTo };
```

注意:这一整段替换的是原 `window.__pages__ = {};` 那一行,后面的 `window.__app__` 一并替换为新版本。

- [ ] **Step 2:** 本地完整手动验证(关键步骤)

```bash
npx wrangler dev --local
```

浏览器打开 http://localhost:8787,跑完手动测试清单全部 21 项(见 spec 第 10.1 节)。重点确认:

- [ ] 登录 / 登出 / 401 自动跳登录
- [ ] 添加仓库(github/gitignore + main):成功后列表出现
- [ ] 重复添加:模态框红字
- [ ] 输入 `justonepart`:模态框拦截「Format: owner/repo」
- [ ] 点列表行 `▸`:展开,看到最近 5 条提交
- [ ] 点 `Remove`:确认弹窗 + 移除
- [ ] 主题切到 dark / light / auto:即时换色,刷新无 FOUC
- [ ] 侧边栏汉堡:桌面折叠成图标,移动端覆盖式
- [ ] Settings · Telegram / GitHub / Schedule / Security 都能加载并保存
- [ ] Test Telegram(填错 token):toast 显示错误
- [ ] Test GitHub(填真实 token):toast 显示 username
- [ ] 改密码 → 登出 → 用新密码登录 → 改回 admin123
- [ ] Activity 页加载、Run check now 工作

带真实 token 跑(可选,需用户提供):

- [ ] 添加一个你有 FORK 的上游(比如 `facebook/react`):列表显示 ↳ `你的用户名/react`
- [ ] 添加一个你无 FORK 的上游:显示 `[Fork it]`
- [ ] 点 `Fork it`:GitHub 真创建 FORK,数秒内列表补出 ↳ 链接

Cron 验证:

```bash
npx wrangler dev --local --test-scheduled
# 另开终端:
curl "http://localhost:8787/__scheduled?cron=*/30+*+*+*+*"
```

预期:cron 流程跑完,Activity 页能看到 lastCronLog。

- [ ] **Step 3:** 提交

```bash
git add worker.js
git commit -m "$(cat <<'EOF'
feat(ui): render repositories, activity, settings pages

在 APP_JS 中注册 6 个页面渲染器:
- Repositories: 列表 + 展开 detail + Add modal + Fork it + Remove
- Activity: last check / cron log + Run check now
- Telegram / GitHub Token / Schedule / Security: 各自表单 + Save / Test

完成 spec 描述的全部 UI 交互。

Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: 收尾 —— `wrangler.toml` cron 触发 + 死代码扫描 + 部署烟测

**目标:** 检查 wrangler.toml 是否有 cron 触发定义(spec 提及),扫一遍 worker.js 确认没有遗留死代码,然后部署到 Cloudflare 跑生产烟测。

**Files:**
- Inspect: `wrangler.toml`(只读)
- Inspect: `worker.js`(只读)

- [ ] **Step 1:** 检查 wrangler.toml 是否有 cron 触发

```bash
cat /root/github-monitor/wrangler.toml
```

若没有 `[triggers]` 段,问用户是否要补(默认不改,因为 spec 明确「不改 cron 触发逻辑」)。若现状没 cron 也能在 Cloudflare Dashboard 单独配,不阻塞。

- [ ] **Step 2:** 死代码扫描

```bash
cd /root/github-monitor

# 应当不再出现的旧函数名
grep -n "generateDashboardHTML\|showDashboard\|handleAddRepo\|handleDeleteRepo\|handleManualCheck\|handleClearRepos\|handleUpdateSettings\|handleTestTelegram\|handleTestGithub\|handleChangePassword" worker.js
```

预期:无输出(或仅 commit 注释里)。若有任何活引用,删除。

```bash
# 检查 worker.js 行数
wc -l worker.js
```

预期:大致 1800-2500 行(Task 8/9 增的 SPA 代码会让总量变大但旧 dashboard 删除补偿了一部分)。

- [ ] **Step 3:** 部署到 Cloudflare 跑生产烟测

```bash
npx wrangler deploy
```

部署后访问你的 worker 域名,跑 spec 10.1 节的 21 项手动测试 中需要真实 GitHub / Telegram 的项目:

- [ ] 真实添加上游 + FORK 关联显示
- [ ] 一键 Fork it 真创建 FORK
- [ ] Telegram 测试消息真的收到
- [ ] Cron 触发(在 Cloudflare Dashboard `Triggers` 配 `*/30 * * * *` 或手动 `Send` 触发)、Telegram 收到 cron 日志

- [ ] **Step 4:** 若发现任何遗漏(死代码、未删的旧路径、文档过时),修复后单独提交。否则,这一 Task 不产生提交,标记完成。

---

## 自审清单(执行前再过一遍)

| spec 要求 | 对应 Task |
|----------|----------|
| 数据模型扩展 fork / addedAt | Task 5 + 6 |
| 懒迁移 | Task 5 |
| FORK 检测流程(4.) | Task 6 |
| 一键 FORK + 轮询 | Task 7 |
| `/api/*` 端点表(5.2) | Task 1-4, 6, 7 |
| 错误码集合 | 全部 Task |
| 401 / 跳 login | Task 1 + Task 8(APP_JS) |
| 左侧栏可折叠 | Task 8 |
| 主题切换无 FOUC | Task 8 |
| 仓库列表 + 展开 + Modal + Fork it | Task 9 |
| Activity + 4 个 Settings 子页 | Task 9 |
| Toast | Task 8 |
| 移动端 | Task 8 |
| 旧函数删除 | Task 8 + Task 10 死代码扫描 |
| 手动测试清单 21 项 | Task 9 Step 2 + Task 10 Step 3 |
| `.superpowers/` 入 gitignore | 已在 spec 提交里完成 |

无遗漏。
