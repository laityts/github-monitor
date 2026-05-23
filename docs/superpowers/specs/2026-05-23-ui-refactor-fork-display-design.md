# UI 重构 + FORK 仓库关联显示 · 设计文档

**日期**:2026-05-23
**作者**:与 Claude Code 协作
**状态**:待实现

## 1. 目标

1. 完整重构 GitHub Monitor 的 Web 管理界面,从「紫色渐变 + 毛玻璃」(2022 风)切换到 **GitHub 原生风**(白底、克制、信息密度高、Primer 配色)
2. 引入 **FORK 关联**概念:监控对象仍是上游仓库,UI 同时展示用户自己账号下对应的 FORK,并提供「一键 FORK」入口

## 2. 关键决策(已确认)

| 维度 | 选择 |
|------|------|
| 视觉风格 | GitHub 原生风(Primer light + dark) |
| 信息架构 | 左侧栏(可折叠),分 MONITOR / SETTINGS 两组 |
| 仓库展示 | 紧凑列表行,点击可展开看详情(GitHub Actions 风) |
| 暗色模式 | 手动切换(Light / Dark / Auto) |
| FORK 不存在时 | 允许添加,UI 显示「Fork it」按钮一键创建 |
| 添加入口 | 模态框 |
| 交互模式 | AJAX 局部刷新(JSON API + 原生 JS) |
| GitHub 用户名 | 不需手动配置,从 token 通过 `GET /user` 推断并缓存 |
| FORK 输入方式 | 上游或 FORK 任意一边输入皆可,系统自动检测并补另一边 |

## 3. 数据模型

### 3.1 仓库对象(`monitored_repositories` 数组元素)

```js
{
  owner: string,          // 监控对象(上游)的 owner
  repo: string,           // 监控对象(上游)的 repo
  branch: string,         // 监控的分支
  fork: {                 // 用户名下对应的 FORK,可为 null
    owner: string,
    repo: string
  } | null,
  addedAt: string         // ISO 时间戳,用于排序与展示
}
```

### 3.2 新增 KV 键

| 键 | 内容 | 用途 |
|----|------|------|
| `github_username` | 字符串 | 从 token `GET /user` 推断并缓存;test-github 时刷新 |
| `repo_meta_<owner>:<repo>` | JSON | 仓库元数据快照(parent / fork / stars),24h TTL |

### 3.3 向后兼容

启动时无主动迁移。在 `getRepoList()` 读取时若发现条目缺 `fork` / `addedAt`,在返回前补默认值(`fork: null`,`addedAt: "1970-01-01T00:00:00Z"`)并写回一次。

## 4. FORK 检测流程(添加仓库时)

```
输入 X/Y (分支默认 main)
  ↓
GET /repos/X/Y
  ├─ 404 → 报错 REPO_NOT_FOUND,模态框红字
  ├─ fork == true →
  │     upstream = parent.full_name (= U/V)
  │     fork = { owner: X, repo: Y }
  │     存储条目 { owner: U, repo: V, branch, fork, addedAt: now }
  └─ fork == false (上游) →
        若已知 me(github_username 缓存):
          GET /repos/me/Y
            ├─ 200 且 parent.full_name == "X/Y" → fork = { owner: me, repo: Y }
            ├─ 200 但 parent 不匹配     → fork = null(同名但不是 FORK)
            └─ 404                       → fork = null
        若未知 me(token 未配置或失效):
          fork = null
        存储条目 { owner: X, repo: Y, branch, fork, addedAt: now }
```

### 4.1 一键 FORK 流程(`POST /api/repos/fork`)

请求体:`{ owner, repo, branch }`(标识哪一行)

1. 校验 `github_username` 已知;否则返回 `GITHUB_TOKEN_REQUIRED`
2. `POST /repos/{owner}/{repo}/forks`(GitHub API,异步)
3. 轮询 `GET /repos/{me}/{repo}`,最多 10 次、每 1 秒
4. 第一个 200 返回 → 更新该条目 `fork = { owner: me, repo }`,持久化,返回成功
5. 超时 → 返回 `FORK_IN_PROGRESS`(前端 toast「Fork in progress on GitHub. Refresh shortly.」),条目 fork 字段保持 null。**仅在用户主动展开该行调用 detail 接口时**(`GET /api/repos/:owner/:repo/:branch/detail`),若 fork=null 且 `github_username` 已知,顺手做一次 `GET /repos/{me}/{repo}` 探测;若返回 200 且 parent 匹配,更新条目 fork 字段并返回。`GET /api/repos` 列表接口**不做**这种探测,避免 N 个仓库放大 API 调用。

### 4.2 Token 权限要求

`public_repo`(私有库 FORK 需 `repo`)。Settings · GitHub Token 页要写清。

## 5. 路由与 API

### 5.1 HTML 路由

| 路径 | 方法 | 说明 |
|------|------|------|
| `/login` | GET / POST | 登录页(沿用现状结构,视觉切到新主题) |
| `/` | GET | SPA 外壳(返回 layout + 资源) |
| `/logout` | POST | 登出 |
| `/check-updates` | GET | 兼容别名,内部转发到 `/api/check` |
| `/health` | GET | 健康检查(沿用现状) |

### 5.2 JSON API(均需会话,401 返回时前端跳 `/login`)

| 端点 | 方法 | 用途 |
|------|------|------|
| `/api/repos` | GET | 仓库列表(含 fork 信息) |
| `/api/repos` | POST | 添加(执行 FORK 检测) |
| `/api/repos` | DELETE | 删除(body: `{owner, repo, branch}`) |
| `/api/repos/fork` | POST | 一键 FORK |
| `/api/repos/:owner/:repo/:branch/detail` | GET | 展开行时拉:最近 5 条 commit、stars、上次检查、最新 SHA |
| `/api/check` | POST | 手动触发全量检查 |
| `/api/settings` | GET / PUT | 读写 Telegram / GitHub Token / Cron 开关 |
| `/api/settings/test-telegram` | POST | 发测试消息 |
| `/api/settings/test-github` | POST | 测 token + 更新 `github_username` 缓存 |
| `/api/password` | PUT | 改密码 |
| `/api/activity` | GET | cron 日志 + 上次检查时间 |

### 5.3 响应约定

- 成功 → `{ok: true, data: ...}`,2xx
- 失败 → `{ok: false, error: "...", code: "..."}`,4xx/5xx
- 错误码集合:`UNAUTHORIZED`、`REPO_NOT_FOUND`、`REPO_DUPLICATE`、`RATE_LIMITED`、`GITHUB_TOKEN_REQUIRED`、`FORK_PERMISSION_DENIED`、`FORK_IN_PROGRESS`、`VALIDATION_ERROR`、`INTERNAL`

## 6. 页面结构与组件

### 6.1 骨架

```
┌───────────────────────────────────────────────────┐
│ Header  ⚙ GitHub Monitor   ☀☾⚙ theme   ↩ Sign out│
├──────────┬────────────────────────────────────────┤
│ Sidebar  │  Main                                  │
│ ▸MONITOR │                                        │
│  Repos   │   <动态内容,按当前路由渲染>             │
│  Activity│                                        │
│ ▸SETTINGS│                                        │
│  Telegram│                                        │
│  GitHub  │                                        │
│  Schedule│                                        │
│  Security│                                        │
└──────────┴────────────────────────────────────────┘
```

### 6.2 Sidebar

- 桌面:宽 `240px`,可折叠到 `56px`(只剩图标)
- 折叠状态写 localStorage(`sidebar_collapsed`)
- 移动端(<768px)默认覆盖式(隐藏 + 汉堡按钮)
- 当前项:橙色左 2px 边框 + 浅蓝底(`#ddf4ff` / dark: `#0d419d33`)
- 分组标签 `MONITOR` / `SETTINGS` 用小写灰色字

### 6.3 Repositories 页

- 头部:`Repositories · N monitored` + 右侧 `[+ Add repository]`(绿)+ `[Check now]`(边框)
- **列表排序**:按 `addedAt` 倒序(最新添加在最上),前端排序,无需后端排序参数
- 列表行(默认折叠):
  ```
  [▸] facebook/react  [main]   ↳ myname/react      ● 2h ago   [⋯]
  ```
  - `▸` 旋转 90° 表示展开
  - 展开行内容:最近 5 条提交(SHA · message · author · 相对时间)、最新 SHA、上次检查时间、新增提交数
  - `fork == null` 时右侧不显示 `↳ ...`,而是灰色 `[Fork it]` 按钮
  - `⋯` 菜单:Open on GitHub / Open fork on GitHub(if any) / Remove
- 空状态:中央灰图标 + 「No repositories monitored. Add one to start.」 + 主按钮

### 6.4 Add Repository 模态框

- 覆盖层 `rgba(0,0,0,0.5)`,中央白卡(dark: `--bg-subtle`)
- 标题栏:`Add repository` + 右上关闭 `×`
- 字段:
  - `Repository`(必填),placeholder `facebook/react`,副文本「Either upstream or your fork — we'll detect and link them.」
  - `Branch`,默认 `main`
- 按钮:`Cancel` / `Add`(主)
- 提交时按钮变 spinner,后端跑 FORK 检测
- 失败:模态框内联红字;成功:关闭并把新行插入列表顶部(浅黄高亮 1 秒淡出)
- `max-height: 90vh; overflow:auto`(移动端兼容)

### 6.5 Activity 页

- 卡片 1:Last check 时间 + 耗时 + 检查仓库数
- 卡片 2:Latest cron run(成功/失败标记 + 时间 + 错误消息 if any)
- 底部按钮:`Run check now` → 调 `/api/check` → 完成后刷新页

### 6.6 Settings 子页

每个子页一张表单卡(GitHub Settings 风,白卡 + 边框 + 灰头):

- **Telegram**:Bot Token / Chat ID + `[Save]` + `[Test]`
- **GitHub Token**:Token(masked,旁边 `Show` 切换) + `[Save]` + `[Test]`;test 成功时下方显示 `Authenticated as: <username>`(灰色行内)
- **Schedule**:`Cron notification` 开关 + 说明
- **Security**:Current password / New password / Confirm + `[Update password]`

### 6.7 Toast

- 右下角,固定定位,3 秒自动消失
- 成功绿(`--success`)/ 失败红(`--danger`)
- 多个 toast 纵向堆叠

### 6.8 主题切换

- Header 右侧 segmented 控件:`☀ Light | ☾ Dark | ⚙ Auto`
- 选择写 localStorage(`theme`);Auto 跟随 `prefers-color-scheme` 并监听变化
- 首屏 inline `<script>` 在 body 渲染前应用 `data-theme`,避免 FOUC

## 7. CSS 变量(Primer)

```css
[data-theme="light"] {
  --bg:#ffffff;  --bg-subtle:#f6f8fa;  --bg-emphasis:#eaeef2;
  --border:#d0d7de;  --border-muted:#eaeef2;
  --fg:#1f2328;  --fg-muted:#656d76;  --fg-subtle:#6e7781;
  --accent:#0969da;  --accent-emphasis:#0550ae;
  --success:#1f883d; --success-bg:#dafbe1;
  --danger:#cf222e;  --danger-bg:#ffebe9;
  --attention:#9a6700; --attention-bg:#fff8c5;
  --done:#8250df;
  --sidebar-active-bg:#ddf4ff; --sidebar-active-border:#fd7e14;
  --shadow:0 1px 0 rgba(31,35,40,0.04);
  --shadow-md:0 3px 6px rgba(140,149,159,0.15);
}
[data-theme="dark"] {
  --bg:#0d1117;  --bg-subtle:#161b22;  --bg-emphasis:#21262d;
  --border:#30363d;  --border-muted:#21262d;
  --fg:#e6edf3;  --fg-muted:#7d8590;  --fg-subtle:#6e7681;
  --accent:#2f81f7;  --accent-emphasis:#388bfd;
  --success:#3fb950; --success-bg:#0f3017;
  --danger:#f85149;  --danger-bg:#481620;
  --attention:#d29922; --attention-bg:#3b2300;
  --done:#a371f7;
  --sidebar-active-bg:#0d419d33; --sidebar-active-border:#fd7e14;
  --shadow:0 0 0 1px rgba(240,246,252,0.05);
  --shadow-md:0 8px 24px rgba(1,4,9,0.85);
}
```

## 8. 错误处理与边界

| 场景 | 处理 |
|------|------|
| GitHub API 403(频率限制) | `RATE_LIMITED`,toast「Configure GitHub token to increase rate limit」+ 高亮 Settings · GitHub Token |
| GitHub API 404 | `REPO_NOT_FOUND`,模态框内联红字 |
| 一键 FORK 时 token 无 `public_repo` | `FORK_PERMISSION_DENIED`,toast 附 GitHub token 设置页链接 |
| token 未配置点 Fork it | 前端拦截,toast「Configure GitHub token first」+ 跳 Settings |
| 一键 FORK 异步未完成 | 10s 轮询,超时返回 `FORK_IN_PROGRESS`;仅在用户展开行调用 detail 时若 fork=null 静默探测一次 |
| 重复添加 | `REPO_DUPLICATE`,模态框红字 |
| 输入格式不对(无 `/`) | 模态框拦截,「Format: owner/repo」,不发请求 |
| KV 旧格式条目 | `getRepoList()` 内懒迁移补字段 |
| 切 token 后用户名变 | test-github 成功时刷新 `github_username` 缓存;已存条目 fork 字段不自动重算 |
| detail API 失败 | 展开行内显示「Failed to load details. Retry?」按钮 |
| 移动端模态框过高 | `max-height:90vh;overflow:auto` |
| 未登录访问 `/api/*` | 401 + `{code:"UNAUTHORIZED"}`,前端拦截统一跳 `/login` |
| 未登录访问 `/` | 服务端 302 → `/login`(同现状) |
| 长 owner/repo 名 | `text-overflow:ellipsis`,hover tooltip 完整名 |

所有用户输入(含 fork.owner / fork.repo)走 `escapeHtml`,防 XSS。

## 9. 不做的事(明确划界)

- ❌ 用户管理 / 多账号(单管理员密码)
- ❌ 仓库分组 / 标签
- ❌ 引入前端框架(原生 JS,~300 行)
- ❌ 抽包 / 分文件(仍单 worker.js,字符串常量分段)
- ❌ 修改 cron 触发逻辑
- ❌ 修改 Telegram 消息格式
- ❌ 修改密码哈希方式
- ❌ 支持私有库 FORK 检测(仅 public,因 token 默认 `public_repo`)

## 10. 验证方式

无单元测试基建,主要依靠**手动测试**:

1. 本地 `npx wrangler dev`(KV `--local` 内存模拟)
2. 部署后用真实 GitHub token / Telegram 烟测

### 10.1 手动测试清单

| # | 场景 | 预期 |
|---|------|------|
| 1 | 未登录访问 `/` | 跳 `/login` |
| 2 | 密码错误 / 正确登录 | 错误提示 / 进入主页 |
| 3 | 列表为空 | 显示 empty state |
| 4 | 添加上游(已有用户 FORK) | 列表显示 ↳ FORK 链接 |
| 5 | 添加上游(无用户 FORK) | 显示「Fork it」按钮 |
| 6 | 点「Fork it」 | GitHub 创建 FORK,数秒内列表补链接 |
| 7 | 添加自己的 FORK 路径 | 监控对象切到上游,fork 填用户输入 |
| 8 | 添加不存在的仓库 | 模态框红字 |
| 9 | 重复添加 | 模态框提示已存在 |
| 10 | 删除条目 | 列表消失 + `last_commit_*` 同步清理 |
| 11 | 展开行 | 显示最近 5 条 commit 摘要 |
| 12 | 点 Check now | 走完检查,新增提交推 Telegram |
| 13 | Telegram 测试按钮 | 收到测试消息 + toast |
| 14 | GitHub token 测试 | toast + 显示 `Authenticated as: <username>` |
| 15 | 改密码 | 登出后新密码登录成功 |
| 16 | 侧边栏折叠 | 状态持久化,刷新仍保持 |
| 17 | 主题切到 Dark / Auto | 即时生效,刷新无 FOUC |
| 18 | 移动端 375px | 侧边栏覆盖式,模态框可滚 |
| 19 | 401 中间态(删 Cookie 后操作) | 自动跳 `/login` |
| 20 | 旧 KV 数据 | 懒迁移正常 |
| 21 | Cron 触发 | Telegram 收到 |

## 11. 实现顺序与提交粒度

按原子提交拆分,每个独立可回滚:

1. `feat(api): add JSON API layer alongside existing routes` —— 仅新增 `/api/*`,不动旧 HTML 页面;curl 验证
2. `feat(repo): detect fork and store fork field` —— 数据模型扩展、懒迁移、FORK 检测、`github_username` 缓存
3. `feat(api): one-click fork endpoint` —— `/api/repos/fork` + 轮询补全
4. `feat(ui): new SPA shell with sidebar layout` —— 替换 `/` 的 HTML;接入主题切换、AJAX 调度;移除旧 `generateDashboardHTML` / `showDashboard` 及其表单 POST 处理
5. `feat(ui): repository list with expand and add modal` —— 列表、模态框、Fork it
6. `feat(ui): activity and settings sub-pages` —— Activity + Telegram / GitHub / Schedule / Security 子页
7. `chore: add .superpowers/ to .gitignore`
8. `docs: update README with fork behavior` —— 可选

每提交后跑相关测试项,通过再继续。

## 12. 风险与缓解

| 风险 | 缓解 |
|------|------|
| 单文件 worker.js 体积膨胀至 ~3500 行 | Worker 限额内可接受;字符串常量分段提高可读性 |
| 一键 FORK 异步等待 | 10s 轮询 + 静默重试机制 |
| GitHub API 频率限制(添加仓库时多花 1 次 `/repos/me/Y`) | token 已配置时 5000/小时,可忽略 |
| 暗色模式初次加载 FOUC | 首屏 inline script 在 body 之前应用 theme |
| 旧 KV 数据无 fork 字段 | `getRepoList()` 懒迁移,首次读时补齐 |

## 13. 完成定义(DoD)

- 所有 21 项手动测试通过
- 旧 KV 数据(无 fork 字段)能正常加载
- 旧表单 POST 处理函数(`handleAddRepo` / `handleDeleteRepo` 等)已删除,无死代码
- worker.js 单文件大小未超 Worker 限额
- README 中 FORK 行为说明已更新(如选择更新)
