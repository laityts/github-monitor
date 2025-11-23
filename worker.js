// 使用原生 Worker API
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // 处理根路径 - 显示管理面板
    if (path === '/') {
      return handleDashboard(request, env, url);
    }

    // 处理登录页面
    if (path === '/login') {
      return handleLogin(request, env, url);
    }

    // 处理登出
    if (path === '/logout') {
      return handleLogout(request, env);
    }

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
  },

  async scheduled(event, env, ctx) {
    // 使用新的cron处理函数
    await handleCronExecution(event, env, ctx);
  }
}

// ==================== 存储键名常量 ====================
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
  SYNC_CONFIGS: 'sync_configs' // 新增：同步配置
};

// ==================== CRON 执行处理 ====================
async function handleCronExecution(event, env, ctx) {
  console.log('🕒 开始执行定时检查任务:', new Date().toISOString());
  
  const startTime = Date.now();
  let result;
  let error = null;
  
  try {
    const response = await handleCheckUpdates(env);
    result = await response.json();
    console.log('✅ 定时检查任务完成:', result);
  } catch (err) {
    console.error('❌ 定时检查任务失败:', err);
    error = err;
    result = { success: false, error: err.message };
  }
  
  const endTime = Date.now();
  const duration = endTime - startTime;
  
  // 构建cron执行日志
  const cronLog = {
    timestamp: new Date().toISOString(),
    startTime: new Date(startTime).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' }),
    endTime: new Date(endTime).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' }),
    duration: `${duration}ms`,
    success: !error,
    result: result,
    error: error ? error.message : null
  };
  
  // 保存日志到存储
  await env.STORAGE.put(STORAGE_KEYS.LAST_CRON_LOG, JSON.stringify(cronLog));
  
  // 发送Telegram通知（根据开关状态）
  await sendCronLogToTelegram(cronLog, env);
  
  return cronLog;
}

// ==================== 认证相关函数 ====================
async function checkAuth(request, env) {
  const cookieHeader = request.headers.get('Cookie');
  if (cookieHeader && cookieHeader.includes('authenticated=true')) {
    const cookies = cookieHeader.split(';').map(c => c.trim());
    const sessionCookie = cookies.find(c => c.startsWith('session_created='));
    if (sessionCookie) {
      const sessionTime = parseInt(sessionCookie.split('=')[1]);
      if (Date.now() - sessionTime < 24 * 60 * 60 * 1000) {
        return { authenticated: true };
      }
    }
  }
  return { authenticated: false };
}

async function initAdminPassword(env) {
  const existingHash = await env.STORAGE.get(STORAGE_KEYS.PASSWORD_HASH);
  if (!existingHash) {
    console.log('初始化默认管理员密码...');
    const defaultPassword = 'admin123';
    const encoder = new TextEncoder();
    const data = encoder.encode(defaultPassword);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    await env.STORAGE.put(STORAGE_KEYS.PASSWORD_HASH, hashHex);
    console.log('默认密码已设置:', defaultPassword);
  }
}

async function verifyPassword(password, env) {
  try {
    const storedHash = await env.STORAGE.get(STORAGE_KEYS.PASSWORD_HASH);
    if (!storedHash) {
      console.log('未找到存储的密码哈希');
      return false;
    }
    
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    const isValid = hashHex === storedHash;
    console.log('密码验证结果:', isValid ? '成功' : '失败');
    return isValid;
  } catch (error) {
    console.error('密码验证错误:', error);
    return false;
  }
}

// ==================== 页面处理函数 ====================
async function handleLogin(request, env, url) {
  await initAdminPassword(env);

  // 如果已经登录，重定向到首页
  const auth = await checkAuth(request, env);
  if (auth.authenticated) {
    return Response.redirect(url.origin, 302);
  }

  // 处理 POST 登录请求
  if (request.method === 'POST') {
    try {
      const formData = await request.formData();
      const password = formData.get('password');
      
      console.log('收到登录请求，密码长度:', password ? password.length : 0);
      
      if (!password) {
        return showLoginPage('错误：请输入密码');
      }
      
      const isValid = await verifyPassword(password, env);
      if (isValid) {
        console.log('登录成功，设置认证cookie');
        const sessionTime = Date.now();
        const headers = new Headers();
        headers.set('Location', url.origin);
        headers.set('Set-Cookie', `authenticated=true; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400`);
        headers.append('Set-Cookie', `session_created=${sessionTime}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400`);
        return new Response(null, {
          status: 302,
          headers: headers
        });
      } else {
        console.log('密码验证失败');
        return showLoginPage('密码错误，请重试');
      }
    } catch (error) {
      console.error('登录处理错误:', error);
      return showLoginPage('登录时发生错误，请重试');
    }
  }

  // 显示登录页面
  return showLoginPage();
}

async function handleLogout(request, env) {
  const headers = new Headers();
  headers.set('Location', new URL('/', request.url).toString());
  headers.set('Set-Cookie', 'authenticated=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0');
  headers.append('Set-Cookie', 'session_created=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0');
  
  return new Response(null, {
    status: 302,
    headers: headers
  });
}

async function handleDashboard(request, env, url) {
  await initAdminPassword(env);

  // 检查认证
  const auth = await checkAuth(request, env);
  if (!auth.authenticated) {
    const headers = new Headers();
    headers.set('Location', new URL('/login', request.url).toString());
    return new Response(null, { status: 302, headers: headers });
  }

  // 处理 POST 请求
  if (request.method === 'POST') {
    try {
      const formData = await request.formData();
      const action = formData.get('action');

      const actionHandlers = {
        'add': () => handleAddRepo(formData, env),
        'delete': () => handleDeleteRepo(formData, env),
        'check': () => handleManualCheck(env),
        'clear': () => handleClearRepos(env),
        'update_settings': () => handleUpdateSettings(formData, env),
        'test_telegram': () => handleTestTelegram(env),
        'test_github': () => handleTestGithub(env),
        'change_password': () => handleChangePassword(formData, env),
        'add_sync': () => handleAddSyncConfig(formData, env), // 新增：添加同步配置
        'delete_sync': () => handleDeleteSyncConfig(formData, env), // 新增：删除同步配置
        'test_sync': () => handleTestSync(formData, env) // 新增：测试同步
      };

      if (actionHandlers[action]) {
        return await actionHandlers[action]();
      }
    } catch (error) {
      console.error('处理POST请求错误:', error);
      return showDashboard(env, `处理请求时发生错误: ${error.message}`);
    }
  }

  // 显示仪表板
  return showDashboard(env);
}

// ==================== 仓库管理函数 ====================
async function handleAddRepo(formData, env) {
  const owner = formData.get('owner')?.trim();
  const repo = formData.get('repo')?.trim();
  let branch = formData.get('branch')?.trim();
  
  if (!owner || !repo) {
    return showDashboard(env, '错误：仓库所有者和仓库名称不能为空');
  }
  
  if (!branch) branch = 'main';
  
  try {
    const repoList = await getRepoList(env);
    const settings = await getSettings(env);
    
    // 检查是否已存在
    const exists = repoList.some(r => 
      r.owner === owner && r.repo === repo && r.branch === branch
    );
    
    if (exists) {
      return showDashboard(env, '错误：该仓库和分支组合已存在');
    }
    
    // 验证仓库是否存在
    await fetchLatestCommit(owner, repo, branch, settings.github_token);
    
    // 添加到列表
    repoList.push({ owner, repo, branch });
    await saveRepoList(repoList, env);
    
    return showDashboard(env, `成功：已添加仓库 ${owner}/${repo} (${branch})`);
  } catch (error) {
    return showDashboard(env, `错误：无法添加仓库 - ${error.message}`);
  }
}

async function handleDeleteRepo(formData, env) {
  const owner = formData.get('owner');
  const repo = formData.get('repo');
  const branch = formData.get('branch');
  
  const repoList = await getRepoList(env);
  const filteredList = repoList.filter(r => 
    !(r.owner === owner && r.repo === repo && r.branch === branch)
  );
  
  await saveRepoList(filteredList, env);
  
  // 删除对应的提交记录
  const commitKey = `${STORAGE_KEYS.LAST_COMMITS}${owner}:${repo}:${branch}`;
  await env.STORAGE.delete(commitKey);
  
  return showDashboard(env, `成功：已删除仓库 ${owner}/${repo} (${branch})`);
}

async function handleManualCheck(env) {
  const result = await checkAllRepos(env);
  if (result.success) {
    return showDashboard(env, result.message);
  } else {
    return showDashboard(env, `检查更新时出错: ${result.error}`);
  }
}

async function handleClearRepos(env) {
  await saveRepoList([], env);
  return showDashboard(env, '已清空所有监控的仓库');
}

// ==================== 同步配置管理函数 ====================
async function handleAddSyncConfig(formData, env) {
  const sourceOwner = formData.get('source_owner')?.trim();
  const sourceRepo = formData.get('source_repo')?.trim();
  let sourceBranch = formData.get('source_branch')?.trim();
  const targetOwner = formData.get('target_owner')?.trim();
  const targetRepo = formData.get('target_repo')?.trim();
  let targetBranch = formData.get('target_branch')?.trim();
  const syncEnabled = formData.get('sync_enabled') === 'on';
  
  if (!sourceOwner || !sourceRepo || !targetOwner || !targetRepo) {
    return showDashboard(env, '错误：源仓库和目标仓库的所有者和名称不能为空');
  }
  
  // 验证仓库所有者格式
  if (sourceOwner.includes('/') || targetOwner.includes('/')) {
    return showDashboard(env, '错误：仓库所有者不能包含斜杠 (/)');
  }
  
  // 验证仓库名称格式
  if (sourceRepo.includes(' ') || targetRepo.includes(' ')) {
    return showDashboard(env, '错误：仓库名称不能包含空格');
  }
  
  if (!sourceBranch) sourceBranch = 'main';
  if (!targetBranch) targetBranch = 'main';
  
  try {
    const syncConfigs = await getSyncConfigs(env);
    const settings = await getSettings(env);
    
    if (!settings.github_token) {
      return showDashboard(env, '错误：请先配置 GitHub Token');
    }
    
    // 检查是否已存在
    const exists = syncConfigs.some(config => 
      config.sourceOwner === sourceOwner && 
      config.sourceRepo === sourceRepo && 
      config.sourceBranch === sourceBranch &&
      config.targetOwner === targetOwner && 
      config.targetRepo === targetRepo && 
      config.targetBranch === targetBranch
    );
    
    if (exists) {
      return showDashboard(env, '错误：该同步配置已存在');
    }
    
    // 逐步验证配置 - 源仓库只需要读取权限
    const validationSteps = [
      { step: '验证源仓库', action: () => testRepositoryAccess(sourceOwner, sourceRepo, settings.github_token, false) },
      { step: '验证源分支', action: () => testBranchExistence(sourceOwner, sourceRepo, sourceBranch, settings.github_token) },
      { step: '验证目标仓库', action: () => testRepositoryAccess(targetOwner, targetRepo, settings.github_token, true) },
      { step: '验证目标分支', action: () => testBranchExistence(targetOwner, targetRepo, targetBranch, settings.github_token) }
    ];
    
    for (const validation of validationSteps) {
      try {
        console.log(`🔍 ${validation.step}...`);
        await validation.action();
      } catch (error) {
        return showDashboard(env, `配置验证失败 - ${validation.step}: ${error.message}`);
      }
    }
    
    // 添加到同步配置列表
    syncConfigs.push({
      sourceOwner,
      sourceRepo,
      sourceBranch,
      targetOwner,
      targetRepo,
      targetBranch,
      enabled: syncEnabled,
      lastSync: null,
      lastError: null
    });
    
    await saveSyncConfigs(syncConfigs, env);
    
    return showDashboard(env, `✅ 成功：已添加同步配置\n${sourceOwner}/${sourceRepo}:${sourceBranch} → ${targetOwner}/${targetRepo}:${targetBranch}`);
  } catch (error) {
    return showDashboard(env, `❌ 错误：无法添加同步配置 - ${error.message}`);
  }
}

async function handleDeleteSyncConfig(formData, env) {
  const sourceOwner = formData.get('source_owner');
  const sourceRepo = formData.get('source_repo');
  const sourceBranch = formData.get('source_branch');
  const targetOwner = formData.get('target_owner');
  const targetRepo = formData.get('target_repo');
  const targetBranch = formData.get('target_branch');
  
  const syncConfigs = await getSyncConfigs(env);
  const filteredConfigs = syncConfigs.filter(config => 
    !(config.sourceOwner === sourceOwner && 
      config.sourceRepo === sourceRepo && 
      config.sourceBranch === sourceBranch &&
      config.targetOwner === targetOwner && 
      config.targetRepo === targetRepo && 
      config.targetBranch === targetBranch)
  );
  
  await saveSyncConfigs(filteredConfigs, env);
  
  return showDashboard(env, `成功：已删除同步配置 ${sourceOwner}/${sourceRepo}:${sourceBranch} → ${targetOwner}/${targetRepo}:${targetBranch}`);
}

async function handleTestSync(formData, env) {
  const sourceOwner = formData.get('source_owner');
  const sourceRepo = formData.get('source_repo');
  const sourceBranch = formData.get('source_branch');
  const targetOwner = formData.get('target_owner');
  const targetRepo = formData.get('target_repo');
  const targetBranch = formData.get('target_branch');
  
  try {
    const settings = await getSettings(env);
    
    if (!settings.github_token) {
      return showDashboard(env, '❌ 错误：请先配置 GitHub Token');
    }
    
    // 详细验证步骤 - 源仓库只需要读取权限
    const validationSteps = [
      { 
        name: '源仓库访问', 
        action: () => testRepositoryAccess(sourceOwner, sourceRepo, settings.github_token, false),
        error: '无法访问源仓库'
      },
      { 
        name: '源分支存在', 
        action: () => testBranchExistence(sourceOwner, sourceRepo, sourceBranch, settings.github_token),
        error: '源分支不存在'
      },
      { 
        name: '目标仓库访问', 
        action: () => testRepositoryAccess(targetOwner, targetRepo, settings.github_token, true),
        error: '无法访问目标仓库或没有写入权限'
      },
      { 
        name: '目标分支存在', 
        action: () => testBranchExistence(targetOwner, targetRepo, targetBranch, settings.github_token),
        error: '目标分支不存在'
      }
    ];
    
    for (const step of validationSteps) {
      try {
        console.log(`✅ 验证 ${step.name}...`);
        await step.action();
      } catch (error) {
        return showDashboard(env, `❌ 验证失败 - ${step.error}:\n${error.message}`);
      }
    }
    
    // 测试同步功能
    const result = await performSync({
      sourceOwner,
      sourceRepo,
      sourceBranch,
      targetOwner,
      targetRepo,
      targetBranch
    }, settings.github_token, env);
    
    if (result.success) {
      if (result.synced) {
        return showDashboard(env, '✅ 同步测试成功！配置正确，已成功执行同步操作。');
      } else {
        return showDashboard(env, '✅ 同步测试成功！配置正确，但无需同步（仓库已是最新）。');
      }
    } else {
      return showDashboard(env, `❌ 同步测试失败:\n${result.error}`);
    }
  } catch (error) {
    return showDashboard(env, `❌ 同步测试失败:\n${error.message}`);
  }
}

// ==================== 设置管理函数 ====================
async function handleUpdateSettings(formData, env) {
  const tg_bot_token = formData.get('tg_bot_token')?.trim();
  const tg_chat_id = formData.get('tg_chat_id')?.trim();
  const github_token = formData.get('github_token')?.trim();
  const cron_notification_enabled = formData.get('cron_notification_enabled') === 'on';
  
  const settings = {
    tg_bot_token,
    tg_chat_id,
    github_token,
    cron_notification_enabled
  };
  
  await saveSettings(settings, env);
  
  return showDashboard(env, '设置已保存成功');
}

async function handleTestTelegram(env) {
  try {
    const settings = await getSettings(env);
    
    if (!settings.tg_bot_token || !settings.tg_chat_id) {
      return showDashboard(env, '错误：请先配置Telegram Bot Token和Chat ID');
    }
    
    const message = `
🔔 <b>测试通知</b>

✅ GitHub监控系统运行正常！
📊 系统已成功连接到Telegram
⏰ 测试时间: ${new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}

<i>这是一条测试消息，用于验证Telegram通知功能是否正常工作。</i>
    `.trim();
    
    await sendTelegramMessage(settings.tg_bot_token, settings.tg_chat_id, message);
    
    return showDashboard(env, '测试通知已发送，请检查Telegram是否收到消息');
  } catch (error) {
    return showDashboard(env, `错误：发送测试通知失败 - ${error.message}`);
  }
}

async function handleTestGithub(env) {
  try {
    const settings = await getSettings(env);
    
    if (!settings.github_token) {
      return showDashboard(env, '错误：请先配置GitHub Token');
    }
    
    // 测试GitHub API连接
    const testRepo = { owner: 'github', repo: 'gitignore', branch: 'main' };
    const commit = await fetchLatestCommit(testRepo.owner, testRepo.repo, testRepo.branch, settings.github_token);
    
    if (commit && commit.sha) {
      return showDashboard(env, 'GitHub API连接测试成功！Token配置正确。');
    } else {
      return showDashboard(env, 'GitHub API连接测试失败，请检查Token是否正确。');
    }
  } catch (error) {
    return showDashboard(env, `GitHub API连接测试失败: ${error.message}`);
  }
}

async function handleChangePassword(formData, env) {
  const currentPassword = formData.get('current_password');
  const newPassword = formData.get('new_password');
  const confirmPassword = formData.get('confirm_password');
  
  if (!currentPassword || !newPassword || !confirmPassword) {
    return showDashboard(env, '错误：请填写所有密码字段');
  }
  
  if (newPassword !== confirmPassword) {
    return showDashboard(env, '错误：新密码和确认密码不匹配');
  }
  
  if (newPassword.length < 6) {
    return showDashboard(env, '错误：新密码至少需要6个字符');
  }
  
  const isValid = await verifyPassword(currentPassword, env);
  if (!isValid) {
    return showDashboard(env, '错误：当前密码不正确');
  }
  
  // 更新密码
  try {
    const encoder = new TextEncoder();
    const data = encoder.encode(newPassword);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    await env.STORAGE.put(STORAGE_KEYS.PASSWORD_HASH, hashHex);
    
    return showDashboard(env, '成功：密码已更新');
  } catch (error) {
    console.error('更新密码错误:', error);
    return showDashboard(env, `错误：更新密码失败 - ${error.message}`);
  }
}

// ==================== 数据存储函数 ====================
async function getRepoList(env) {
  const repoList = await env.STORAGE.get(STORAGE_KEYS.REPO_LIST, 'json');
  return repoList || [];
}

async function saveRepoList(repoList, env) {
  await env.STORAGE.put(STORAGE_KEYS.REPO_LIST, JSON.stringify(repoList));
}

async function getSettings(env) {
  const tg_bot_token = await env.STORAGE.get(STORAGE_KEYS.TG_BOT_TOKEN);
  const tg_chat_id = await env.STORAGE.get(STORAGE_KEYS.TG_CHAT_ID);
  const github_token = await env.STORAGE.get(STORAGE_KEYS.GITHUB_TOKEN);
  const cron_notification_enabled_str = await env.STORAGE.get(STORAGE_KEYS.CRON_NOTIFICATION_ENABLED);
  
  // 处理开关状态，默认为true（开启）
  let cron_notification_enabled = true;
  if (cron_notification_enabled_str !== null) {
    cron_notification_enabled = cron_notification_enabled_str === 'true';
  }
  
  return {
    tg_bot_token: tg_bot_token || '',
    tg_chat_id: tg_chat_id || '',
    github_token: github_token || '',
    cron_notification_enabled: cron_notification_enabled
  };
}

async function saveSettings(settings, env) {
  if (settings.tg_bot_token !== undefined) {
    await env.STORAGE.put(STORAGE_KEYS.TG_BOT_TOKEN, settings.tg_bot_token);
  }
  if (settings.tg_chat_id !== undefined) {
    await env.STORAGE.put(STORAGE_KEYS.TG_CHAT_ID, settings.tg_chat_id);
  }
  if (settings.github_token !== undefined) {
    await env.STORAGE.put(STORAGE_KEYS.GITHUB_TOKEN, settings.github_token);
  }
  // 保存定时任务通知开关状态
  if (settings.cron_notification_enabled !== undefined) {
    await env.STORAGE.put(STORAGE_KEYS.CRON_NOTIFICATION_ENABLED, settings.cron_notification_enabled.toString());
  }
}

async function getLastCommit(owner, repo, branch, env) {
  const key = `${STORAGE_KEYS.LAST_COMMITS}${owner}:${repo}:${branch}`;
  return await env.STORAGE.get(key);
}

async function saveLastCommit(owner, repo, branch, sha, env) {
  const key = `${STORAGE_KEYS.LAST_COMMITS}${owner}:${repo}:${branch}`;
  await env.STORAGE.put(key, sha);
}

async function getLastCheckTime(env) {
  return await env.STORAGE.get(STORAGE_KEYS.LAST_CHECK_TIME) || '从未检查';
}

async function getLastCronLog(env) {
  const logData = await env.STORAGE.get(STORAGE_KEYS.LAST_CRON_LOG);
  if (!logData) return null;
  try {
    return JSON.parse(logData);
  } catch {
    return null;
  }
}

// ==================== 同步配置存储函数 ====================
async function getSyncConfigs(env) {
  const syncConfigs = await env.STORAGE.get(STORAGE_KEYS.SYNC_CONFIGS, 'json');
  return syncConfigs || [];
}

async function saveSyncConfigs(syncConfigs, env) {
  await env.STORAGE.put(STORAGE_KEYS.SYNC_CONFIGS, JSON.stringify(syncConfigs));
}

// ==================== GitHub API 函数 ====================
async function fetchLatestCommit(owner, repo, branch, githubToken = null) {
  const url = `https://api.github.com/repos/${owner}/${repo}/commits?sha=${branch}&per_page=1`;
  
  const headers = {
    'User-Agent': 'GitHub-Monitor-Bot',
    'Accept': 'application/vnd.github.v3+json'
  };
  
  // 如果提供了GitHub Token，添加到请求头中
  if (githubToken) {
    headers['Authorization'] = `token ${githubToken}`;
  }
  
  const response = await fetch(url, { headers });
  
  if (!response.ok) {
    if (response.status === 403) {
      if (githubToken) {
        throw new Error('GitHub API 频率限制（即使使用Token也达到限制），请稍后重试');
      } else {
        throw new Error('GitHub API 频率限制（未认证请求），请配置GitHub Token以提高限制');
      }
    } else if (response.status === 404) {
      throw new Error('仓库不存在或没有访问权限');
    } else {
      throw new Error(`GitHub API错误: ${response.status} ${response.statusText}`);
    }
  }
  
  // 检查剩余的API限制
  const remaining = response.headers.get('X-RateLimit-Remaining');
  const limit = response.headers.get('X-RateLimit-Limit');
  console.log(`GitHub API 限制: ${remaining}/${limit}`);
  
  const commits = await response.json();
  
  if (!commits || commits.length === 0) {
    throw new Error('该分支没有提交记录');
  }
  
  return commits[0];
}

async function fetchCommitsBetween(owner, repo, branch, sinceCommit, githubToken = null) {
  const url = `https://api.github.com/repos/${owner}/${repo}/commits?sha=${branch}&per_page=100`;
  
  const headers = {
    'User-Agent': 'GitHub-Monitor-Bot',
    'Accept': 'application/vnd.github.v3+json'
  };
  
  if (githubToken) {
    headers['Authorization'] = `token ${githubToken}`;
  }
  
  const response = await fetch(url, { headers });
  
  if (!response.ok) {
    if (response.status === 403) {
      if (githubToken) {
        throw new Error('GitHub API 频率限制（即使使用Token也达到限制），请稍后重试');
      } else {
        throw new Error('GitHub API 频率限制（未认证请求），请配置GitHub Token以提高限制');
      }
    } else if (response.status === 404) {
      throw new Error('仓库不存在或没有访问权限');
    } else {
      throw new Error(`GitHub API错误: ${response.status} ${response.statusText}`);
    }
  }
  
  const commits = await response.json();
  
  if (!commits || commits.length === 0) {
    throw new Error('该分支没有提交记录');
  }
  
  // 找到 sinceCommit 的位置
  let sinceIndex = -1;
  if (sinceCommit) {
    sinceIndex = commits.findIndex(commit => commit.sha === sinceCommit);
  }
  
  // 如果找到了 sinceCommit，则返回从最新提交到 sinceCommit 之间的所有提交
  // 如果没找到 sinceCommit，则返回所有获取到的提交
  if (sinceIndex > 0) {
    return commits.slice(0, sinceIndex);
  } else if (sinceIndex === -1 && sinceCommit) {
    // 如果没找到 sinceCommit，但 sinceCommit 存在，说明可能历史记录很深
    // 返回所有获取到的提交，并在消息中说明可能不完整
    return commits;
  } else {
    // 如果没有 sinceCommit（首次检查），只返回最新提交
    return [commits[0]];
  }
}

// ==================== 同步功能函数 ====================
async function testRepositoryAccess(owner, repo, githubToken, requireWrite = false) {
  const url = `https://api.github.com/repos/${owner}/${repo}`;
  
  const headers = {
    'User-Agent': 'GitHub-Monitor-Bot',
    'Accept': 'application/vnd.github.v3+json',
  };
  
  if (githubToken) {
    headers['Authorization'] = `token ${githubToken}`;
  }
  
  const response = await fetch(url, { headers });
  
  if (!response.ok) {
    if (response.status === 404) {
      let errorDetails = `仓库 ${owner}/${repo} 不存在`;
      
      // 检查是否是组织仓库
      if (owner.includes('-') || owner.includes('.')) {
        errorDetails += '\n⚠️ 注意：组织名称可能包含特殊字符，请确认拼写正确';
      }
      
      throw new Error(errorDetails);
    } else if (response.status === 403) {
      // 处理权限问题
      const remaining = response.headers.get('X-RateLimit-Remaining');
      if (remaining === '0') {
        throw new Error('GitHub API 速率限制已用完，请稍后重试');
      }
      
      if (requireWrite) {
        throw new Error(`没有 ${owner}/${repo} 的写入权限。请确保：\n1. Token 有写入权限\n2. 仓库允许外部贡献者`);
      } else {
        throw new Error(`没有 ${owner}/${repo} 的读取权限。请确保：\n1. 仓库是公开的\n2. 或者 Token 有访问私有仓库的权限`);
      }
    } else {
      throw new Error(`GitHub API 错误: ${response.status} ${response.statusText}`);
    }
  }
  
  const repoData = await response.json();
  
  // 检查仓库信息
  if (repoData.private && !githubToken) {
    throw new Error(`仓库 ${owner}/${repo} 是私有的，需要提供 GitHub Token`);
  }
  
  // 如果有 Token 且需要写入权限，检查权限
  if (githubToken && repoData.permissions && requireWrite) {
    console.log(`仓库权限:`, repoData.permissions);
    
    if (!repoData.permissions.push && !repoData.permissions.admin) {
      throw new Error(`对仓库 ${owner}/${repo} 没有写入权限`);
    }
  }
  
  // 对于只读访问，只要有仓库信息就认为成功
  return repoData;
}

async function testBranchExistence(owner, repo, branch, githubToken) {
  const url = `https://api.github.com/repos/${owner}/${repo}/branches/${branch}`;
  
  const headers = {
    'User-Agent': 'GitHub-Monitor-Bot',
    'Accept': 'application/vnd.github.v3+json',
  };
  
  if (githubToken) {
    headers['Authorization'] = `token ${githubToken}`;
  }
  
  const response = await fetch(url, { headers });
  
  if (!response.ok) {
    if (response.status === 404) {
      // 获取仓库的所有分支来帮助用户诊断
      const branchesUrl = `https://api.github.com/repos/${owner}/${repo}/branches`;
      const branchesResponse = await fetch(branchesUrl, { headers });
      
      let availableBranches = [];
      if (branchesResponse.ok) {
        const branchesData = await branchesResponse.json();
        availableBranches = branchesData.map(b => b.name);
      }
      
      throw new Error(`分支 "${branch}" 在仓库 ${owner}/${repo} 中不存在。可用分支: ${availableBranches.join(', ') || '无法获取分支列表'}`);
    } else {
      throw new Error(`检查分支失败: ${response.status} ${response.statusText}`);
    }
  }
  
  return await response.json();
}

async function performSync(syncConfig, githubToken, env) {
  try {
    console.log(`🔄 开始同步: ${syncConfig.sourceOwner}/${syncConfig.sourceRepo}:${syncConfig.sourceBranch} → ${syncConfig.targetOwner}/${syncConfig.targetRepo}:${syncConfig.targetBranch}`);
    
    // 1. 验证源仓库存在性
    console.log(`🔍 验证源仓库: ${syncConfig.sourceOwner}/${syncConfig.sourceRepo}`);
    await testRepositoryAccess(syncConfig.sourceOwner, syncConfig.sourceRepo, githubToken, false);
    
    // 2. 验证源仓库分支存在性
    console.log(`🔍 验证源分支: ${syncConfig.sourceBranch}`);
    await testBranchExistence(syncConfig.sourceOwner, syncConfig.sourceRepo, syncConfig.sourceBranch, githubToken);
    
    // 3. 验证目标仓库存在性
    console.log(`🔍 验证目标仓库: ${syncConfig.targetOwner}/${syncConfig.targetRepo}`);
    await testRepositoryAccess(syncConfig.targetOwner, syncConfig.targetRepo, githubToken, true);
    
    // 4. 验证目标仓库分支存在性 - 这里需要特别注意
    console.log(`🔍 验证目标分支: ${syncConfig.targetBranch}`);
    try {
      await testBranchExistence(syncConfig.targetOwner, syncConfig.targetRepo, syncConfig.targetBranch, githubToken);
    } catch (error) {
      // 如果目标分支不存在，提供更明确的错误信息
      throw new Error(`目标分支 "${syncConfig.targetBranch}" 不存在于仓库 ${syncConfig.targetOwner}/${syncConfig.targetRepo} 中。请先创建该分支。\n错误详情: ${error.message}`);
    }
    
    // 5. 获取源仓库的最新提交
    console.log(`📥 获取源仓库提交...`);
    const sourceCommit = await fetchLatestCommit(
      syncConfig.sourceOwner, 
      syncConfig.sourceRepo, 
      syncConfig.sourceBranch, 
      githubToken
    );
    
    // 6. 获取目标仓库的最新提交
    console.log(`📥 获取目标仓库提交...`);
    const targetCommit = await fetchLatestCommit(
      syncConfig.targetOwner, 
      syncConfig.targetRepo, 
      syncConfig.targetBranch, 
      githubToken
    );
    
    // 7. 检查是否需要同步
    if (sourceCommit.sha === targetCommit.sha) {
      return { 
        success: true, 
        synced: false, 
        message: '源仓库和目标仓库已经同步，无需更新'
      };
    }
    
    // 8. 创建合并提交
    console.log(`🔀 创建合并提交...`);
    const mergeUrl = `https://api.github.com/repos/${syncConfig.targetOwner}/${syncConfig.targetRepo}/merges`;
    
    // 使用正确的 head 格式
    const head = syncConfig.sourceOwner === syncConfig.targetOwner 
      ? syncConfig.sourceBranch 
      : `${syncConfig.sourceOwner}:${syncConfig.sourceBranch}`;
    
    const mergeData = {
      base: syncConfig.targetBranch,
      head: head,
      commit_message: `🔀 自动同步: ${syncConfig.sourceOwner}/${syncConfig.sourceRepo}@${syncConfig.sourceBranch}\n\n源提交: ${sourceCommit.sha.substring(0, 7)}\n源消息: ${sourceCommit.commit.message.split('\n')[0]}`
    };
    
    const headers = {
      'User-Agent': 'GitHub-Monitor-Bot',
      'Accept': 'application/vnd.github.v3+json',
      'Content-Type': 'application/json'
    };
    
    if (githubToken) {
      headers['Authorization'] = `token ${githubToken}`;
    }
    
    console.log('合并请求数据:', JSON.stringify(mergeData, null, 2));
    
    const mergeResponse = await fetch(mergeUrl, {
      method: 'POST',
      headers: headers,
      body: JSON.stringify(mergeData)
    });
    
    if (mergeResponse.status === 201) {
      // 合并成功
      const mergeResult = await mergeResponse.json();
      console.log(`✅ 同步成功: 创建合并提交 ${mergeResult.sha}`);
      
      // 更新同步配置的最后同步时间
      const syncConfigs = await getSyncConfigs(env);
      const configIndex = syncConfigs.findIndex(config => 
        config.sourceOwner === syncConfig.sourceOwner && 
        config.sourceRepo === syncConfig.sourceRepo && 
        config.sourceBranch === syncConfig.sourceBranch &&
        config.targetOwner === syncConfig.targetOwner && 
        config.targetRepo === syncConfig.targetRepo && 
        config.targetBranch === syncConfig.targetBranch
      );
      
      if (configIndex !== -1) {
        syncConfigs[configIndex].lastSync = new Date().toISOString();
        syncConfigs[configIndex].lastError = null;
        await saveSyncConfigs(syncConfigs, env);
      }
      
      return { 
        success: true, 
        synced: true, 
        message: '同步成功',
        mergeSha: mergeResult.sha,
        sourceCommit: sourceCommit.sha,
        targetCommit: targetCommit.sha
      };
    } else {
      let errorMessage = `GitHub API错误: ${mergeResponse.status}`;
      try {
        const errorData = await mergeResponse.json();
        if (errorData.message) {
          errorMessage = errorData.message;
        }
        console.error('合并错误详情:', errorData);
      } catch (e) {
        // 如果无法解析错误信息，使用状态码
      }
      
      // 根据不同的状态码提供更具体的错误信息
      if (mergeResponse.status === 404) {
        errorMessage = `合并失败: ${errorMessage}\n\n可能的原因：\n1. 目标分支 "${syncConfig.targetBranch}" 不存在\n2. 源分支 "${syncConfig.sourceBranch}" 不存在\n3. 仓库权限不足\n4. 仓库不存在或拼写错误`;
      } else if (mergeResponse.status === 409) {
        errorMessage = `合并冲突: ${errorMessage}\n\n需要手动解决合并冲突`;
      } else if (mergeResponse.status === 403) {
        errorMessage = `权限不足: ${errorMessage}\n\n请确保：\n1. GitHub Token 有写入目标仓库的权限\n2. 对源仓库至少有读取权限\n3. 没有触发API速率限制`;
      }
      
      console.error(`❌ 同步失败: ${mergeResponse.status}`, errorMessage);
      
      return { 
        success: false, 
        synced: false, 
        error: errorMessage
      };
    }
  } catch (error) {
    console.error(`❌ 同步异常:`, error);
    return { 
      success: false, 
      synced: false, 
      error: error.message
    };
  }
}

async function handleRepositorySync(repoInfo, latestCommit, env) {
  try {
    const syncConfigs = await getSyncConfigs(env);
    const settings = await getSettings(env);
    
    if (!settings.github_token) {
      console.log('⚠️ GitHub Token未配置，跳过同步');
      return;
    }
    
    // 查找与此仓库相关的同步配置
    const relevantConfigs = syncConfigs.filter(config => 
      config.enabled &&
      config.sourceOwner === repoInfo.owner && 
      config.sourceRepo === repoInfo.repo && 
      config.sourceBranch === repoInfo.branch
    );
    
    if (relevantConfigs.length === 0) {
      return;
    }
    
    console.log(`🔄 发现 ${relevantConfigs.length} 个同步配置需要处理`);
    
    for (const config of relevantConfigs) {
      try {
        const syncResult = await performSync(config, settings.github_token, env);
        
        // 发送同步结果通知
        if (settings.tg_bot_token && settings.tg_chat_id) {
          let message;
          
          if (syncResult.success && syncResult.synced) {
            message = `✅ <b>同步成功</b>\n\n` +
              `📦 <b>源仓库:</b> ${config.sourceOwner}/${config.sourceRepo}:${config.sourceBranch}\n` +
              `🎯 <b>目标仓库:</b> ${config.targetOwner}/${config.targetRepo}:${config.targetBranch}\n` +
              `🔀 <b>合并提交:</b> ${syncResult.mergeSha.substring(0, 7)}\n` +
              `⏰ <b>同步时间:</b> ${new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}\n\n` +
              `<i>源仓库的更新已成功同步到目标仓库</i>`;
          } else if (syncResult.success && !syncResult.synced) {
            // 无需同步的情况，不发送通知
            continue;
          } else {
            message = `❌ <b>同步失败</b>\n\n` +
              `📦 <b>源仓库:</b> ${config.sourceOwner}/${config.sourceRepo}:${config.sourceBranch}\n` +
              `🎯 <b>目标仓库:</b> ${config.targetOwner}/${config.targetRepo}:${config.targetBranch}\n` +
              `🚨 <b>错误原因:</b> ${syncResult.error}\n` +
              `⏰ <b>同步时间:</b> ${new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}\n\n` +
              `<i>请检查仓库权限或解决合并冲突</i>`;
          }
          
          await sendTelegramMessage(settings.tg_bot_token, settings.tg_chat_id, message);
        }
        
        // 添加延迟以避免触发GitHub API限制
        await new Promise(resolve => setTimeout(resolve, 1000));
      } catch (syncError) {
        console.error(`❌ 同步配置处理失败:`, syncError);
      }
    }
  } catch (error) {
    console.error('❌ 处理仓库同步时出错:', error);
  }
}

// ==================== Telegram 函数 ====================
async function sendCronLogToTelegram(cronLog, env) {
  try {
    const settings = await getSettings(env);
    
    if (!settings.tg_bot_token || !settings.tg_chat_id) {
      console.log('⚠️ Telegram未配置，跳过cron日志发送');
      return;
    }
    
    // 检查定时任务通知开关
    if (!settings.cron_notification_enabled) {
      console.log('🔇 定时任务通知已关闭，跳过cron日志发送');
      return;
    }
    
    const message = buildCronLogMessage(cronLog, env);
    await sendTelegramMessage(settings.tg_bot_token, settings.tg_chat_id, message);
    console.log('📨 Cron执行日志已发送到Telegram');
  } catch (error) {
    console.error('❌ 发送cron日志到Telegram失败:', error);
  }
}

function buildCronLogMessage(cronLog, env) {
  const statusIcon = cronLog.success ? '✅' : '❌';
  const statusText = cronLog.success ? '执行成功' : '执行失败';
  const title = `${statusIcon} <b>GitHub Monitor 定时任务报告</b>`;
  
  // 基础信息
  const basicInfo = `
📅 <b>执行时间:</b> ${cronLog.startTime}
⏱️ <b>执行时长:</b> ${cronLog.duration}
🔄 <b>执行状态:</b> ${statusText}
  `.trim();
  
  // 结果详情
  let resultDetails = '';
  if (cronLog.success && cronLog.result) {
    const result = cronLog.result;
    const checkedCount = (result.checkedCount !== undefined && result.checkedCount !== null) ? result.checkedCount : 0;
    const updatedCount = (result.updatedCount !== undefined && result.updatedCount !== null) ? result.updatedCount : 0;
    const errorCount = (result.errorCount !== undefined && result.errorCount !== null) ? result.errorCount : 0;
    const syncCount = (result.syncCount !== undefined && result.syncCount !== null) ? result.syncCount : 0;
    
    resultDetails = `
📊 <b>检查结果:</b>
   • 已检查仓库: ${checkedCount}
   • 发现更新: ${updatedCount}
   • 错误数量: ${errorCount}
   • 同步操作: ${syncCount}
💬 <b>总结:</b> ${result.message || '检查完成'}
    `.trim();
  } else if (cronLog.error) {
    resultDetails = `
🚨 <b>错误信息:</b>
<code>${cronLog.error}</code>
    `.trim();
  }
  
  // 系统状态
  const systemInfo = `
💻 <b>系统状态:</b> ${cronLog.success ? '正常运行' : '遇到问题'}
🔔 <b>通知渠道:</b> Telegram
  `.trim();
  
  // 组合所有部分
  const message = `
${title}

${basicInfo}

${resultDetails}

${systemInfo}

<i>此消息由GitHub Monitor定时任务自动发送</i>
  `.trim();
  
  return message;
}

// ==================== Telegram 函数 ====================
function buildTelegramMessage(repoInfo, commits, isCompleteHistory = true) {
  const repoUrl = `https://github.com/${repoInfo.owner}/${repoInfo.repo}`;
  const branchUrl = `${repoUrl}/tree/${repoInfo.branch}`;
  
  let message = `🚀 <b>代码仓库已更新！</b>\n\n`;
  message += `📦 <b>仓库:</b> <a href="${repoUrl}">${repoInfo.owner}/${repoInfo.repo}</a>\n`;
  message += `🌿 <b>分支:</b> <code>${repoInfo.branch}</code>\n\n`;
  
  if (commits.length === 1) {
    // 单个提交的情况（保持不变）
    const commit = commits[0];
    const commitUrl = commit.html_url;
    const shortSha = commit.sha.substring(0, 7);
    const commitMessage = commit.commit.message.split('\n')[0];
    
    const commitDate = new Date(commit.commit.author.date);
    const formattedTime = commitDate.toLocaleString('zh-CN', { 
      timeZone: 'Asia/Shanghai',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
    
    message += `📝 <b>最新提交:</b> <a href="${commitUrl}">${shortSha}</a>\n`;
    message += `👤 <b>作者:</b> ${commit.commit.author.name}\n`;
    message += `💬 <b>提交信息:</b> ${commitMessage}\n`;
    message += `⏰ <b>时间:</b> ${formattedTime}\n\n`;
  } else {
    // 多个提交的情况 - 限制最多显示10个
    const displayCommits = commits.slice(0, 10); // 只取前10个提交
    const remainingCount = commits.length - displayCommits.length; // 计算剩余的提交数量
    
    message += `📋 <b>发现 ${commits.length} 个新提交</b>\n\n`;
    
    displayCommits.forEach((commit, index) => {
      const commitUrl = commit.html_url;
      const shortSha = commit.sha.substring(0, 7);
      const commitMessage = commit.commit.message.split('\n')[0];
      
      const commitDate = new Date(commit.commit.author.date);
      const formattedTime = commitDate.toLocaleString('zh-CN', { 
        timeZone: 'Asia/Shanghai',
        hour: '2-digit',
        minute: '2-digit'
      });
      
      message += `${index + 1}. <a href="${commitUrl}">${shortSha}</a> - ${commitMessage}\n`;
      message += `   👤 ${commit.commit.author.name} • ⏰ ${formattedTime}\n\n`;
    });
    
    // 添加限制提示
    if (remainingCount > 0) {
      message += `📝 <i>由于提交数量较多，只显示最新的10个提交（还有${remainingCount}个提交未显示）</i>\n\n`;
    }
    
    if (!isCompleteHistory) {
      message += `⚠️ <i>注意：由于提交历史较长，可能未显示所有提交</i>\n\n`;
    }
  }
  
  message += `<a href="${repoUrl}/commits/${repoInfo.branch}">查看完整提交历史</a>`;
  
  return message;
}

async function sendTelegramMessage(botToken, chatId, message) {
  const url = `https://api.telegram.org/bot${botToken}/sendMessage`;
  
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      chat_id: chatId,
      text: message,
      parse_mode: 'HTML',
      disable_web_page_preview: false,
    }),
  });
  
  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(`Telegram API错误: ${response.status} - ${errorData.description || '未知错误'}`);
  }
  
  return await response.json();
}

// ==================== 检查更新函数 ====================
async function checkAllRepos(env) {
  try {
    console.log('🔍 开始检查所有仓库更新...');
    
    // 记录检查开始时间
    const checkTime = new Date().toLocaleString('zh-CN', { 
      timeZone: 'Asia/Shanghai',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });
    
    // 保存检查时间
    await env.STORAGE.put(STORAGE_KEYS.LAST_CHECK_TIME, checkTime);
    
    const repoList = await getRepoList(env);
    const settings = await getSettings(env);
    
    if (repoList.length === 0) {
      console.log('ℹ️ 没有监控的仓库需要检查');
      return { 
        success: true, 
        message: '没有监控的仓库需要检查',
        checkedCount: 0,
        updatedCount: 0,
        errorCount: 0,
        syncCount: 0
      };
    }
    
    console.log(`📊 共有 ${repoList.length} 个仓库需要检查`);
    
    // 检查Telegram配置
    const hasTelegramConfig = settings.tg_bot_token && settings.tg_chat_id;
    if (!hasTelegramConfig) {
      console.log('⚠️ Telegram未配置，跳过通知发送');
    } else {
      console.log('✅ Telegram已配置，将发送通知');
    }
    
    let checkedCount = 0;
    let updatedCount = 0;
    let errorCount = 0;
    let syncCount = 0;
    
    for (const repo of repoList) {
      try {
        console.log(`🔎 检查仓库: ${repo.owner}/${repo.repo} (${repo.branch})`);
        
        const latestCommit = await fetchLatestCommit(repo.owner, repo.repo, repo.branch, settings.github_token);
        const lastKnownCommit = await getLastCommit(repo.owner, repo.repo, repo.branch, env);
        
        checkedCount++;
        
        if (!lastKnownCommit) {
          console.log(`📝 首次检查，记录提交: ${latestCommit.sha}`);
          await saveLastCommit(repo.owner, repo.repo, repo.branch, latestCommit.sha, env);
          continue;
        }
        
        if (latestCommit.sha !== lastKnownCommit) {
          console.log(`🆕 检测到新提交: ${latestCommit.sha}`);
          updatedCount++;
          
          // 获取从上次记录提交到最新提交之间的所有提交
          let newCommits = [];
          let isCompleteHistory = true;
          
          try {
            newCommits = await fetchCommitsBetween(
              repo.owner, 
              repo.repo, 
              repo.branch, 
              lastKnownCommit, 
              settings.github_token
            );
            
            // 检查是否获取到了完整的提交历史
            if (newCommits.length > 0) {
              const lastFetchedCommit = newCommits[newCommits.length - 1];
              isCompleteHistory = lastFetchedCommit.sha === lastKnownCommit;
              
              if (!isCompleteHistory) {
                console.log(`⚠️ 可能未获取到完整的提交历史，最新获取的提交: ${lastFetchedCommit.sha}，期望找到: ${lastKnownCommit}`);
              }
            }
            
            console.log(`📋 获取到 ${newCommits.length} 个新提交`);
          } catch (fetchError) {
            console.error(`❌ 获取提交历史失败:`, fetchError);
            // 如果获取完整提交历史失败，回退到只发送最新提交
            newCommits = [latestCommit];
            isCompleteHistory = false;
          }
          
          if (hasTelegramConfig && newCommits.length > 0) {
            console.log(`📨 发送Telegram通知...`);
            const message = buildTelegramMessage(repo, newCommits, isCompleteHistory);
            await sendTelegramMessage(settings.tg_bot_token, settings.tg_chat_id, message);
            console.log(`✅ Telegram通知发送成功`);
          }
          
          // 处理仓库同步
          try {
            await handleRepositorySync(repo, latestCommit, env);
            syncCount++;
          } catch (syncError) {
            console.error(`❌ 处理仓库同步失败:`, syncError);
          }
          
          await saveLastCommit(repo.owner, repo.repo, repo.branch, latestCommit.sha, env);
        } else {
          console.log(`✅ 没有新提交`);
        }
      } catch (error) {
        console.error(`❌ 检查仓库 ${repo.owner}/${repo.repo} 时出错:`, error);
        errorCount++;
        
        if (hasTelegramConfig) {
          const errorMessage = `❌ <b>监控错误</b>\n\n检查仓库 ${repo.owner}/${repo.repo} (${repo.branch}) 时出错:\n<code>${error.message}</code>`;
          try {
            console.log(`📨 发送错误通知...`);
            await sendTelegramMessage(settings.tg_bot_token, settings.tg_chat_id, errorMessage);
          } catch (telegramError) {
            console.error('❌ 发送错误通知失败:', telegramError);
          }
        }
      }
      
      // 添加延迟以避免触发GitHub API限制
      const delay = settings.github_token ? 500 : 2000;
      console.log(`⏳ 等待 ${delay}ms 后继续...`);
      await new Promise(resolve => setTimeout(resolve, delay));
    }
    
    const message = `检查完成: 已检查 ${checkedCount} 个仓库，发现 ${updatedCount} 个更新，${errorCount} 个错误，处理 ${syncCount} 个同步`;
    console.log(`✅ ${message}`);
    return { 
      success: true, 
      message,
      checkedCount: checkedCount || 0,
      updatedCount: updatedCount || 0,
      errorCount: errorCount || 0,
      syncCount: syncCount || 0
    };
  } catch (error) {
    console.error('❌ 检查更新时出错:', error);
    return { 
      success: false, 
      error: error.message,
      checkedCount: 0,
      updatedCount: 0,
      errorCount: 1,
      syncCount: 0
    };
  }
}

async function handleCheckUpdates(env) {
  console.log('🔄 手动触发检查更新...');
  const result = await checkAllRepos(env);
  console.log('📋 检查更新结果:', result);
  return new Response(JSON.stringify(result), {
    headers: { 'Content-Type': 'application/json' }
  });
}

// ==================== 页面渲染函数 ====================
function showLoginPage(errorMessage = '') {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录 - GitHub Monitor</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        /* 优化后的CSS样式 - 更现代化的设计 */
        :root {
            --primary: #6366f1;
            --primary-light: #818cf8;
            --primary-dark: #4f46e5;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --dark: #1e293b;
            --light: #f8fafc;
            --gray: #64748b;
            --border: #e2e8f0;
            --radius: 16px;
            --shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
            --shadow-lg: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .login-container {
            width: 100%;
            max-width: 440px;
        }
        
        .login-card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: var(--radius);
            padding: 48px 40px;
            box-shadow: var(--shadow-lg);
            border: 1px solid rgba(255, 255, 255, 0.2);
            text-align: center;
        }
        
        .logo {
            margin-bottom: 32px;
        }
        
        .logo-icon {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            border-radius: 20px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 2.5rem;
            margin-bottom: 16px;
            box-shadow: 0 10px 20px rgba(99, 102, 241, 0.3);
        }
        
        .logo h1 {
            color: var(--dark);
            font-size: 2rem;
            font-weight: 800;
            margin-bottom: 8px;
        }
        
        .logo p {
            color: var(--gray);
            font-size: 1.1rem;
        }
        
        .login-form {
            text-align: left;
        }
        
        .form-group {
            margin-bottom: 24px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: var(--dark);
            font-size: 0.95rem;
        }
        
        .input-wrapper {
            position: relative;
        }
        
        .input-icon {
            position: absolute;
            left: 16px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--gray);
            font-size: 1.1rem;
        }
        
        input[type="password"] {
            width: 100%;
            padding: 16px 16px 16px 48px;
            border: 2px solid var(--border);
            border-radius: 12px;
            font-size: 16px;
            transition: all 0.3s;
            background: white;
            font-family: inherit;
        }
        
        input[type="password"]:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
        }
        
        .btn {
            width: 100%;
            padding: 16px;
            border: none;
            border-radius: 12px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: all 0.3s;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            color: white;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(99, 102, 241, 0.3);
        }
        
        .alert {
            padding: 16px;
            border-radius: 12px;
            margin-bottom: 24px;
            background: linear-gradient(135deg, #fef2f2, #fee2e2);
            color: #991b1b;
            border-left: 4px solid var(--danger);
            text-align: left;
        }
        
        .features {
            margin-top: 32px;
            padding-top: 32px;
            border-top: 1px solid var(--border);
        }
        
        .features h3 {
            color: var(--dark);
            margin-bottom: 16px;
            font-size: 1.1rem;
        }
        
        .feature-list {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 12px;
            text-align: left;
        }
        
        .feature-item {
            display: flex;
            align-items: center;
            gap: 8px;
            color: var(--gray);
            font-size: 0.9rem;
        }
        
        .feature-item i {
            color: var(--primary);
            font-size: 0.8rem;
        }
        
        .password-note {
            margin-top: 16px;
            padding: 12px;
            background: #f8fafc;
            border-radius: 8px;
            font-size: 0.875rem;
            color: var(--gray);
            text-align: left;
        }
        
        @media (max-width: 480px) {
            .login-card {
                padding: 32px 24px;
            }
            
            .logo-icon {
                width: 64px;
                height: 64px;
                font-size: 2rem;
            }
            
            .logo h1 {
                font-size: 1.75rem;
            }
            
            .feature-list {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-card">
            <div class="logo">
                <div class="logo-icon">
                    <i class="fas fa-code-branch"></i>
                </div>
                <h1>GitHub Monitor</h1>
                <p>代码仓库监控系统</p>
            </div>
            
            ${errorMessage ? `
                <div class="alert">
                    <i class="fas fa-exclamation-circle"></i>
                    ${errorMessage}
                </div>
            ` : ''}
            
            <form method="post" class="login-form">
                <div class="form-group">
                    <label for="password">管理员密码</label>
                    <div class="input-wrapper">
                        <i class="fas fa-lock input-icon"></i>
                        <input type="password" id="password" name="password" placeholder="请输入管理员密码" required autofocus>
                    </div>
                </div>
                
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-sign-in-alt"></i>
                    登录系统
                </button>
            </form>
            
            <div class="password-note">
                <strong>默认密码:</strong> admin123<br>
                首次登录后建议在设置中修改密码
            </div>
            
            <div class="features">
                <h3>系统功能</h3>
                <div class="feature-list">
                    <div class="feature-item">
                        <i class="fas fa-check"></i>
                        GitHub仓库监控
                    </div>
                    <div class="feature-item">
                        <i class="fas fa-check"></i>
                        实时提交检测
                    </div>
                    <div class="feature-item">
                        <i class="fas fa-check"></i>
                        Telegram通知
                    </div>
                    <div class="feature-item">
                        <i class="fas fa-check"></i>
                        多仓库支持
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>`;
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

async function showDashboard(env, message = '') {
  try {
    const repoList = await getRepoList(env);
    const settings = await getSettings(env);
    const lastCheckTime = await getLastCheckTime(env);
    const lastCronLog = await getLastCronLog(env);
    const syncConfigs = await getSyncConfigs(env);
    const html = generateDashboardHTML(repoList, settings, message, lastCheckTime, lastCronLog, syncConfigs);
    return new Response(html, {
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    });
  } catch (error) {
    console.error('显示仪表板时出错:', error);
    return new Response(`显示仪表板时出错: ${error.message}`, { status: 500 });
  }
}

function generateDashboardHTML(repoList, settings, message, lastCheckTime, lastCronLog, syncConfigs) {
  // 辅助函数：转义HTML特殊字符
  function escapeHtml(text) {
    if (!text) return '';
    const map = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, function(m) { return map[m]; });
  }

  // 生成仓库卡片
  const repoCards = repoList.map(repo => `
    <div class="repo-card">
      <div class="repo-info">
        <div class="repo-icon">
          <i class="fab fa-github"></i>
        </div>
        <div class="repo-details">
          <h3>${escapeHtml(repo.owner)}/${escapeHtml(repo.repo)}</h3>
          <p class="repo-branch">
            <i class="fas fa-code-branch"></i>
            ${escapeHtml(repo.branch)}
          </p>
        </div>
      </div>
      <div class="repo-actions">
        <form method="post" class="inline-form">
          <input type="hidden" name="action" value="delete">
          <input type="hidden" name="owner" value="${escapeHtml(repo.owner)}">
          <input type="hidden" name="repo" value="${escapeHtml(repo.repo)}">
          <input type="hidden" name="branch" value="${escapeHtml(repo.branch)}">
          <button type="submit" class="btn btn-danger btn-sm" onclick="return confirm('确定要删除这个仓库吗？')">
            <i class="fas fa-trash"></i>
          </button>
        </form>
      </div>
    </div>
  `).join('');

  // 生成同步配置卡片
  const syncCards = syncConfigs.map(config => `
    <div class="repo-card">
      <div class="repo-info">
        <div class="repo-icon" style="background: linear-gradient(135deg, #8b5cf6, #a855f7);">
          <i class="fas fa-sync-alt"></i>
        </div>
        <div class="repo-details">
          <h3>${escapeHtml(config.sourceOwner)}/${escapeHtml(config.sourceRepo)}:${escapeHtml(config.sourceBranch)}</h3>
          <p class="repo-branch">
            <i class="fas fa-arrow-right"></i>
            ${escapeHtml(config.targetOwner)}/${escapeHtml(config.targetRepo)}:${escapeHtml(config.targetBranch)}
          </p>
          <div class="sync-status">
            ${config.lastSync ? `<span class="status-success"><i class="fas fa-check"></i> 最后同步: ${new Date(config.lastSync).toLocaleString('zh-CN')}</span>` : ''}
            ${config.lastError ? `<span class="status-error"><i class="fas fa-exclamation-triangle"></i> ${escapeHtml(config.lastError)}</span>` : ''}
            ${config.enabled ? '<span class="status-enabled"><i class="fas fa-toggle-on"></i> 已启用</span>' : '<span class="status-disabled"><i class="fas fa-toggle-off"></i> 已禁用</span>'}
          </div>
        </div>
      </div>
      <div class="repo-actions">
        <form method="post" class="inline-form">
          <input type="hidden" name="action" value="test_sync">
          <input type="hidden" name="source_owner" value="${escapeHtml(config.sourceOwner)}">
          <input type="hidden" name="source_repo" value="${escapeHtml(config.sourceRepo)}">
          <input type="hidden" name="source_branch" value="${escapeHtml(config.sourceBranch)}">
          <input type="hidden" name="target_owner" value="${escapeHtml(config.targetOwner)}">
          <input type="hidden" name="target_repo" value="${escapeHtml(config.targetRepo)}">
          <input type="hidden" name="target_branch" value="${escapeHtml(config.targetBranch)}">
          <button type="submit" class="btn btn-info btn-sm">
            <i class="fas fa-play"></i>
          </button>
        </form>
        <form method="post" class="inline-form">
          <input type="hidden" name="action" value="delete_sync">
          <input type="hidden" name="source_owner" value="${escapeHtml(config.sourceOwner)}">
          <input type="hidden" name="source_repo" value="${escapeHtml(config.sourceRepo)}">
          <input type="hidden" name="source_branch" value="${escapeHtml(config.sourceBranch)}">
          <input type="hidden" name="target_owner" value="${escapeHtml(config.targetOwner)}">
          <input type="hidden" name="target_repo" value="${escapeHtml(config.targetRepo)}">
          <input type="hidden" name="target_branch" value="${escapeHtml(config.targetBranch)}">
          <button type="submit" class="btn btn-danger btn-sm" onclick="return confirm('确定要删除这个同步配置吗？')">
            <i class="fas fa-trash"></i>
          </button>
        </form>
      </div>
    </div>
  `).join('');

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GitHub Monitor - 代码仓库监控系统</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        /* 优化后的仪表板样式 */
        :root {
            --primary: #6366f1;
            --primary-light: #818cf8;
            --primary-dark: #4f46e5;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --info: #06b6d4;
            --dark: #1e293b;
            --darker: #0f172a;
            --light: #f8fafc;
            --gray: #64748b;
            --border: #e2e8f0;
            --radius: 16px;
            --radius-sm: 8px;
            --shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
            --shadow-lg: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: var(--dark);
            line-height: 1.6;
        }
        
        .dashboard {
            max-width: 1400px;
            margin: 0 auto;
            padding: 24px;
        }
        
        .header {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: var(--radius);
            padding: 32px;
            margin-bottom: 24px;
            box-shadow: var(--shadow);
            display: flex;
            justify-content: space-between;
            align-items: center;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        .header-content h1 {
            color: var(--darker);
            margin-bottom: 8px;
            font-size: 2.5rem;
            font-weight: 800;
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .header-content p {
            color: var(--gray);
            font-size: 1.1rem;
            font-weight: 500;
        }
        
        .user-menu {
            display: flex;
            align-items: center;
            gap: 16px;
        }
        
        .logout-btn {
            background: var(--light);
            color: var(--gray);
            border: 1px solid var(--border);
            padding: 10px 16px;
            border-radius: var(--radius-sm);
            text-decoration: none;
            font-size: 0.875rem;
            font-weight: 500;
            transition: all 0.3s;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        
        .logout-btn:hover {
            background: var(--danger);
            color: white;
            border-color: var(--danger);
        }
        
        .container {
            display: grid;
            grid-template-columns: 1fr 400px;
            gap: 24px;
            margin-bottom: 24px;
        }
        
        .main-content {
            display: flex;
            flex-direction: column;
            gap: 24px;
        }
        
        .card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: var(--radius);
            padding: 28px;
            box-shadow: var(--shadow);
            border: 1px solid rgba(255, 255, 255, 0.2);
            transition: transform 0.3s, box-shadow 0.3s;
        }
        
        .card:hover {
            transform: translateY(-5px);
            box-shadow: var(--shadow-lg);
        }
        
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
            padding-bottom: 20px;
            border-bottom: 2px solid var(--border);
        }
        
        .card-header h2 {
            color: var(--darker);
            font-size: 1.5rem;
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .card-header h2 i {
            color: var(--primary);
        }
        
        .form-group {
            margin-bottom: 24px;
            position: relative;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: var(--darker);
            font-size: 0.95rem;
        }
        
        .form-input {
            position: relative;
        }
        
        .form-input i {
            position: absolute;
            left: 16px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--gray);
            z-index: 2;
        }
        
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 14px 16px 14px 48px;
            border: 2px solid var(--border);
            border-radius: var(--radius-sm);
            font-size: 16px;
            transition: all 0.3s;
            background: white;
            font-family: inherit;
        }
        
        input[type="text"]:focus, input[type="password"]:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
        }
        
        .form-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
        }
        
        .btn {
            padding: 14px 28px;
            border: none;
            border-radius: var(--radius-sm);
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: all 0.3s;
            display: inline-flex;
            align-items: center;
            gap: 10px;
            font-family: inherit;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            color: white;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(99, 102, 241, 0.3);
        }
        
        .btn-success {
            background: linear-gradient(135deg, var(--success), #059669);
            color: white;
        }
        
        .btn-danger {
            background: linear-gradient(135deg, var(--danger), #dc2626);
            color: white;
        }
        
        .btn-warning {
            background: linear-gradient(135deg, var(--warning), #d97706);
            color: white;
        }
        
        .btn-info {
            background: linear-gradient(135deg, var(--info), #0891b2);
            color: white;
        }
        
        .btn-sm {
            padding: 10px 16px;
            font-size: 14px;
        }
        
        .repo-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
            gap: 20px;
        }
        
        .repo-card {
            background: white;
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
            border: 1px solid var(--border);
            transition: all 0.3s;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .repo-card:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 15px rgba(0, 0, 0, 0.1);
            border-color: var(--primary-light);
        }
        
        .repo-info {
            display: flex;
            align-items: center;
            gap: 16px;
        }
        
        .repo-icon {
            width: 48px;
            height: 48px;
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 1.5rem;
        }
        
        .repo-details h3 {
            color: var(--darker);
            font-size: 1.1rem;
            font-weight: 700;
            margin-bottom: 4px;
        }
        
        .repo-branch {
            color: var(--gray);
            font-size: 0.9rem;
            display: flex;
            align-items: center;
            gap: 6px;
        }
        
        .sync-status {
            margin-top: 8px;
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }
        
        .status-success, .status-error, .status-enabled, .status-disabled {
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 0.8rem;
            font-weight: 500;
        }
        
        .status-success {
            background: #f0fdf4;
            color: #166534;
            border: 1px solid #bbf7d0;
        }
        
        .status-error {
            background: #fef2f2;
            color: #991b1b;
            border: 1px solid #fecaca;
        }
        
        .status-enabled {
            background: #f0f9ff;
            color: #0369a1;
            border: 1px solid #bae6fd;
        }
        
        .status-disabled {
            background: #f8fafc;
            color: #64748b;
            border: 1px solid #e2e8f0;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 16px;
            margin-top: 20px;
        }
        
        .stat-card {
            background: linear-gradient(135deg, var(--primary-light), var(--primary));
            color: white;
            padding: 20px;
            border-radius: 12px;
            text-align: center;
        }
        
        .stat-card .stat-number {
            font-size: 1.8rem;
            color: white;
        }
        
        .alert {
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 24px;
            border-left: 5px solid;
            background: white;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .alert-success {
            border-left-color: var(--success);
            background: linear-gradient(135deg, #f0fdf4, #dcfce7);
            color: #166534;
        }
        
        .alert-error {
            border-left-color: var(--danger);
            background: linear-gradient(135deg, #fef2f2, #fee2e2);
            color: #991b1b;
        }
        
        .alert-warning {
            border-left-color: var(--warning);
            background: linear-gradient(135deg, #fffbeb, #fef3c7);
            color: #92400e;
        }
        
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: var(--gray);
        }
        
        .empty-state i {
            font-size: 4rem;
            margin-bottom: 20px;
            color: var(--gray);
        }
        
        .action-buttons {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }
        
        .tab-container {
            margin-top: 24px;
        }
        
        .tabs {
            display: flex;
            border-bottom: 2px solid var(--border);
            margin-bottom: 24px;
        }
        
        .tab {
            padding: 12px 24px;
            background: none;
            border: none;
            font-size: 1rem;
            font-weight: 600;
            color: var(--gray);
            cursor: pointer;
            border-bottom: 3px solid transparent;
            transition: all 0.3s;
            font-family: inherit;
        }
        
        .tab.active {
            color: var(--primary);
            border-bottom-color: var(--primary);
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .form-actions {
            display: flex;
            gap: 12px;
            margin-top: 24px;
            flex-wrap: wrap;
        }
        
        .form-section {
            margin-bottom: 32px;
            padding-bottom: 24px;
            border-bottom: 1px solid var(--border);
        }
        
        .form-section-title {
            font-size: 1.2rem;
            font-weight: 700;
            color: var(--darker);
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .form-section-title i {
            color: var(--primary);
        }
        
        .status-item {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-top: 10px;
            padding: 12px;
            border-radius: 8px;
            background: #f8fafc;
        }
        
        .status-dot {
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }
        
        .status-connected {
            background: var(--success);
        }
        
        .status-disconnected {
            background: var(--danger);
        }
        
        .status-warning {
            background: var(--warning);
        }
        
        .help-text {
            font-size: 0.875rem;
            color: var(--gray);
            margin-top: 6px;
            line-height: 1.5;
        }
        
        .cron-log {
            margin-top: 10px;
            padding: 12px;
            background: #f8fafc;
            border-radius: 8px;
            border-left: 4px solid ${lastCronLog ? (lastCronLog.success ? '#10b981' : '#ef4444') : '#cbd5e1'};
        }
        
        .cron-log-title {
            margin: 0 0 8px 0;
            font-weight: 600;
            font-size: 0.95rem;
        }
        
        .cron-log-detail {
            margin: 4px 0;
            font-size: 0.9em;
        }
        
        /* 新增：开关样式 */
        .toggle-switch {
            position: relative;
            display: inline-block;
            width: 60px;
            height: 34px;
        }
        
        .toggle-switch input {
            opacity: 0;
            width: 0;
            height: 0;
        }
        
        .toggle-slider {
            position: absolute;
            cursor: pointer;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: #ccc;
            transition: .4s;
            border-radius: 34px;
        }
        
        .toggle-slider:before {
            position: absolute;
            content: "";
            height: 26px;
            width: 26px;
            left: 4px;
            bottom: 4px;
            background-color: white;
            transition: .4s;
            border-radius: 50%;
        }
        
        input:checked + .toggle-slider {
            background-color: var(--success);
        }
        
        input:checked + .toggle-slider:before {
            transform: translateX(26px);
        }
        
        .toggle-label {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 16px;
        }
        
        .toggle-text {
            font-weight: 600;
            color: var(--darker);
        }
        
        .toggle-description {
            font-size: 0.875rem;
            color: var(--gray);
            margin-top: 4px;
            margin-left: 72px;
        }
        
        /* 移动端优化 */
        @media (max-width: 1024px) {
            .container {
                grid-template-columns: 1fr;
            }
            
            .header {
                flex-direction: column;
                gap: 20px;
                text-align: center;
            }
            
            .user-menu {
                flex-direction: column;
                gap: 12px;
            }
        }
    
        @media (max-width: 768px) {
            .dashboard {
                padding: 16px;
            }
            
            .repo-grid {
                grid-template-columns: 1fr;
            }
            
            .form-row {
                grid-template-columns: 1fr;
            }
            
            .header-content h1 {
                font-size: 2rem;
            }
            
            .tabs {
                flex-direction: column;
            }
            
            .tab {
                text-align: left;
                border-bottom: 1px solid var(--border);
                border-left: 3px solid transparent;
            }
            
            .tab.active {
                border-left-color: var(--primary);
                border-bottom-color: var(--border);
            }
            
            .form-actions, .action-buttons {
                flex-direction: column;
            }
            
            .form-actions .btn, .action-buttons .btn {
                width: 100%;
                justify-content: center;
            }
            
            .card-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 16px;
            }
            
            /* 新增的移动端按钮优化 */
            .action-buttons {
                flex-direction: column;
                width: 100%;
                gap: 12px;
            }
            
            .action-buttons .inline-form {
                width: 100%;
            }
            
            .action-buttons .btn {
                width: 100%;
                justify-content: center;
                padding: 14px 20px;
                font-size: 16px;
            }
            
            .action-buttons .btn-sm {
                padding: 14px 20px;
                font-size: 16px;
            }
            
            .repo-actions {
                margin-top: 12px;
                width: 100%;
                display: flex;
                justify-content: center;
            }
            
            .repo-card {
                flex-direction: column;
                align-items: flex-start;
                gap: 16px;
            }
            
            .repo-info {
                width: 100%;
            }
            
            .repo-actions .btn {
                width: 100%;
                justify-content: center;
            }
        }
    </style>
</head>
<body>
    <div class="dashboard">
        <div class="header">
            <div class="header-content">
                <h1><i class="fas fa-code-branch"></i> GitHub Monitor</h1>
                <p>实时监控GitHub仓库更新，第一时间获取代码变更通知</p>
            </div>
            <div class="user-menu">
                <div class="user-info">
                    <div class="user-name">管理员</div>
                    <div class="user-role">系统管理员</div>
                </div>
                <a href="/logout" class="logout-btn">
                    <i class="fas fa-sign-out-alt"></i>
                    退出登录
                </a>
            </div>
        </div>
        
        ${message ? `
            <div class="alert ${message.includes('成功') ? 'alert-success' : message.includes('错误') ? 'alert-error' : 'alert-warning'}">
                <i class="fas ${message.includes('成功') ? 'fa-check-circle' : message.includes('错误') ? 'fa-exclamation-circle' : 'fa-info-circle'}"></i>
                ${escapeHtml(message)}
            </div>
        ` : ''}
        
        <div class="container">
            <div class="main-content">
                <div class="card">
                    <div class="card-header">
                        <h2><i class="fas fa-plus-circle"></i> 添加监控仓库</h2>
                    </div>
                    <form method="post">
                        <input type="hidden" name="action" value="add">
                        <div class="form-row">
                            <div class="form-group">
                                <label for="owner">仓库所有者</label>
                                <div class="form-input">
                                    <i class="fas fa-user"></i>
                                    <input type="text" id="owner" name="owner" placeholder="例如：microsoft" required>
                                </div>
                                <div class="help-text">GitHub用户名或组织名称</div>
                            </div>
                            <div class="form-group">
                                <label for="repo">仓库名称</label>
                                <div class="form-input">
                                    <i class="fas fa-project-diagram"></i>
                                    <input type="text" id="repo" name="repo" placeholder="例如：vscode" required>
                                </div>
                                <div class="help-text">GitHub仓库的名称</div>
                            </div>
                        </div>
                        <div class="form-group">
                            <label for="branch">分支名称</label>
                            <div class="form-input">
                                <i class="fas fa-code-branch"></i>
                                <input type="text" id="branch" name="branch" placeholder="例如：main（可选，默认为main）">
                            </div>
                            <div class="help-text">留空将默认为 main 分支</div>
                        </div>
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-plus"></i> 添加仓库
                        </button>
                    </form>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h2><i class="fas fa-sync-alt"></i> 添加同步配置</h2>
                    </div>
                    <form method="post">
                        <input type="hidden" name="action" value="add_sync">
                        <div class="form-section">
                            <div class="form-section-title">
                                <i class="fas fa-download"></i> 源仓库配置
                            </div>
                            <div class="form-row">
                                <div class="form-group">
                                    <label for="source_owner">源仓库所有者</label>
                                    <div class="form-input">
                                        <i class="fas fa-user"></i>
                                        <input type="text" id="source_owner" name="source_owner" placeholder="例如：microsoft" required>
                                    </div>
                                </div>
                                <div class="form-group">
                                    <label for="source_repo">源仓库名称</label>
                                    <div class="form-input">
                                        <i class="fas fa-project-diagram"></i>
                                        <input type="text" id="source_repo" name="source_repo" placeholder="例如：vscode" required>
                                    </div>
                                </div>
                            </div>
                            <div class="form-group">
                                <label for="source_branch">源分支名称</label>
                                <div class="form-input">
                                    <i class="fas fa-code-branch"></i>
                                    <input type="text" id="source_branch" name="source_branch" placeholder="例如：main（可选，默认为main）">
                                </div>
                            </div>
                        </div>
                        
                        <div class="form-section">
                            <div class="form-section-title">
                                <i class="fas fa-upload"></i> 目标仓库配置
                            </div>
                            <div class="form-row">
                                <div class="form-group">
                                    <label for="target_owner">目标仓库所有者</label>
                                    <div class="form-input">
                                        <i class="fas fa-user"></i>
                                        <input type="text" id="target_owner" name="target_owner" placeholder="例如：my-org" required>
                                    </div>
                                </div>
                                <div class="form-group">
                                    <label for="target_repo">目标仓库名称</label>
                                    <div class="form-input">
                                        <i class="fas fa-project-diagram"></i>
                                        <input type="text" id="target_repo" name="target_repo" placeholder="例如：vscode-fork" required>
                                    </div>
                                </div>
                            </div>
                            <div class="form-group">
                                <label for="target_branch">目标分支名称</label>
                                <div class="form-input">
                                    <i class="fas fa-code-branch"></i>
                                    <input type="text" id="target_branch" name="target_branch" placeholder="例如：main（可选，默认为main）">
                                </div>
                            </div>
                        </div>
                        
                        <div class="toggle-label">
                            <label class="toggle-switch">
                                <input type="checkbox" name="sync_enabled" checked>
                                <span class="toggle-slider"></span>
                            </label>
                            <span class="toggle-text">启用同步</span>
                        </div>
                        
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-plus"></i> 添加同步配置
                        </button>
                    </form>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h2><i class="fas fa-list"></i> 监控中的仓库</h2>
                        <div class="action-buttons">
                            <form method="post" class="inline-form">
                                <input type="hidden" name="action" value="check">
                                <button type="submit" class="btn btn-success btn-sm">
                                    <i class="fas fa-sync-alt"></i> 立即检查
                                </button>
                            </form>
                            <form method="post" class="inline-form">
                                <input type="hidden" name="action" value="clear">
                                <button type="submit" class="btn btn-danger btn-sm" onclick="return confirm('确定要清空所有仓库吗？此操作不可撤销！')">
                                    <i class="fas fa-trash"></i> 清空全部
                                </button>
                            </form>
                        </div>
                    </div>
                    
                    ${repoList.length > 0 ? `
                        <div class="repo-grid">
                            ${repoCards}
                        </div>
                    ` : `
                        <div class="empty-state">
                            <i class="fas fa-inbox"></i>
                            <h3>暂无监控仓库</h3>
                            <p>请在上方添加要监控的GitHub仓库</p>
                        </div>
                    `}
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h2><i class="fas fa-sync"></i> 同步配置列表</h2>
                    </div>
                    
                    ${syncConfigs.length > 0 ? `
                        <div class="repo-grid">
                            ${syncCards}
                        </div>
                    ` : `
                        <div class="empty-state">
                            <i class="fas fa-sync-alt"></i>
                            <h3>暂无同步配置</h3>
                            <p>请在上方添加同步配置</p>
                        </div>
                    `}
                </div>
            </div>
            
            <div class="sidebar">
                <div class="card">
                    <div class="card-header">
                        <h2><i class="fas fa-cog"></i> 系统设置</h2>
                    </div>
                    
                    <div class="tab-container">
                        <div class="tabs">
                            <button class="tab active" onclick="switchTab('api-tab')">API 配置</button>
                            <button class="tab" onclick="switchTab('security-tab')">安全设置</button>
                        </div>
                        
                        <div id="api-tab" class="tab-content active">
                            <form method="post" class="settings-form">
                                <input type="hidden" name="action" value="update_settings">
                                
                                <div class="form-section">
                                    <div class="form-section-title">
                                        <i class="fab fa-github"></i> GitHub API 配置
                                    </div>
                                    <div class="form-group">
                                        <label for="github_token">GitHub Token</label>
                                        <div class="form-input">
                                            <i class="fas fa-key"></i>
                                            <input type="text" id="github_token" name="github_token" 
                                                   value="${escapeHtml(settings.github_token || '')}" 
                                                   placeholder="输入GitHub Personal Access Token">
                                        </div>
                                        <div class="help-text">
                                            解决API限制问题，提高请求频率。创建Token时无需特殊权限。
                                        </div>
                                    </div>
                                    
                                    <div class="status-item">
                                        <div class="status-dot ${settings.github_token ? 'status-connected' : 'status-warning'}"></div>
                                        <span>${settings.github_token ? 'GitHub API 已认证' : 'GitHub API 未认证（请求频率受限）'}</span>
                                    </div>
                                </div>
                                
                                <div class="form-section">
                                    <div class="form-section-title">
                                        <i class="fab fa-telegram"></i> Telegram 通知配置
                                    </div>
                                    <div class="form-group">
                                        <label for="tg_bot_token">Telegram Bot Token</label>
                                        <div class="form-input">
                                            <i class="fas fa-robot"></i>
                                            <input type="text" id="tg_bot_token" name="tg_bot_token" 
                                                   value="${escapeHtml(settings.tg_bot_token || '')}" 
                                                   placeholder="输入Telegram Bot Token">
                                        </div>
                                    </div>
                                    <div class="form-group">
                                        <label for="tg_chat_id">Telegram Chat ID</label>
                                        <div class="form-input">
                                            <i class="fas fa-comment"></i>
                                            <input type="text" id="tg_chat_id" name="tg_chat_id" 
                                                   value="${escapeHtml(settings.tg_chat_id || '')}" 
                                                   placeholder="输入Telegram Chat ID">
                                        </div>
                                    </div>
                                    
                                    <div class="status-item">
                                        <div class="status-dot ${settings.tg_bot_token && settings.tg_chat_id ? 'status-connected' : 'status-disconnected'}"></div>
                                        <span>${settings.tg_bot_token && settings.tg_chat_id ? 'Telegram 已配置' : 'Telegram 未配置'}</span>
                                    </div>
                                    
                                    <!-- 新增：定时任务通知开关 -->
                                    <div class="toggle-label">
                                        <label class="toggle-switch">
                                            <input type="checkbox" name="cron_notification_enabled" ${settings.cron_notification_enabled ? 'checked' : ''}>
                                            <span class="toggle-slider"></span>
                                        </label>
                                        <span class="toggle-text">定时任务执行通知</span>
                                    </div>
                                    <div class="toggle-description">
                                        开启后，每次定时任务执行时都会发送执行结果通知到Telegram。<br>
                                        <strong>注意：</strong>此设置不影响仓库更新通知，仓库更新通知会正常发送。
                                    </div>
                                </div>
                                
                                <div class="form-actions">
                                    <button type="submit" class="btn btn-primary">
                                        <i class="fas fa-save"></i> 保存设置
                                    </button>
                                    <button type="submit" name="action" value="test_telegram" class="btn btn-info" 
                                            ${!settings.tg_bot_token || !settings.tg_chat_id ? 'disabled' : ''}>
                                        <i class="fas fa-paper-plane"></i> 测试通知
                                    </button>
                                    <button type="submit" name="action" value="test_github" class="btn btn-warning" 
                                            ${!settings.github_token ? 'disabled' : ''}>
                                        <i class="fab fa-github"></i> 测试GitHub
                                    </button>
                                </div>
                            </form>
                        </div>
                        
                        <div id="security-tab" class="tab-content">
                            <form method="post" class="settings-form">
                                <input type="hidden" name="action" value="change_password">
                                
                                <div class="form-section">
                                    <div class="form-section-title">
                                        <i class="fas fa-lock"></i> 修改密码
                                    </div>
                                    <div class="form-group">
                                        <label for="current_password">当前密码</label>
                                        <div class="form-input">
                                            <i class="fas fa-lock"></i>
                                            <input type="password" id="current_password" name="current_password" 
                                                   placeholder="请输入当前密码" required>
                                        </div>
                                    </div>
                                    
                                    <div class="form-group">
                                        <label for="new_password">新密码</label>
                                        <div class="form-input">
                                            <i class="fas fa-key"></i>
                                            <input type="password" id="new_password" name="new_password" 
                                                   placeholder="请输入新密码（至少6位）" minlength="6" required>
                                        </div>
                                    </div>
                                    
                                    <div class="form-group">
                                        <label for="confirm_password">确认新密码</label>
                                        <div class="form-input">
                                            <i class="fas fa-check-circle"></i>
                                            <input type="password" id="confirm_password" name="confirm_password" 
                                                   placeholder="请再次输入新密码" minlength="6" required>
                                        </div>
                                    </div>
                                </div>
                                
                                <button type="submit" class="btn btn-primary">
                                    <i class="fas fa-save"></i> 更新密码
                                </button>
                            </form>
                        </div>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h2><i class="fas fa-info-circle"></i> 系统信息</h2>
                    </div>
                    <div class="stats-grid">
                        <div class="stat-card">
                            <span class="stat-number">${repoList.length}</span>
                            <span class="stat-label">监控仓库</span>
                        </div>
                        <div class="stat-card">
                            <span class="stat-number">${syncConfigs.length}</span>
                            <span class="stat-label">同步配置</span>
                        </div>
                    </div>
                    <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--border);">
                        <p><strong>最后检查:</strong> ${escapeHtml(lastCheckTime)}</p>
                        <p><strong>通知状态:</strong> ${settings.tg_bot_token && settings.tg_chat_id ? '已启用' : '未配置'}</p>
                        <p><strong>GitHub状态:</strong> ${settings.github_token ? '已认证' : '未认证（受限）'}</p>
                        <p><strong>定时任务通知:</strong> ${settings.cron_notification_enabled ? '已开启' : '已关闭'}</p>
                        
                        ${lastCronLog ? `
                        <div class="cron-log">
                            <p class="cron-log-title">上次定时任务执行</p>
                            <p class="cron-log-detail"><strong>时间:</strong> ${escapeHtml(lastCronLog.startTime)}</p>
                            <p class="cron-log-detail"><strong>状态:</strong> ${lastCronLog.success ? '✅ 成功' : '❌ 失败'}</p>
                            <p class="cron-log-detail"><strong>时长:</strong> ${escapeHtml(lastCronLog.duration)}</p>
                            ${lastCronLog.result && lastCronLog.result.checkedCount !== undefined ? `
                            <p class="cron-log-detail"><strong>检查:</strong> ${lastCronLog.result.checkedCount} 仓库, ${lastCronLog.result.updatedCount} 更新, ${lastCronLog.result.errorCount} 错误, ${lastCronLog.result.syncCount} 同步</p>
                            ` : ''}
                        </div>
                        ` : ''}
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h2><i class="fas fa-question-circle"></i> 使用帮助</h2>
                    </div>
                    <div style="line-height: 1.7;">
                        <p><strong>GitHub Token配置:</strong></p>
                        <ol style="margin-left: 20px; margin-bottom: 16px;">
                            <li>访问 GitHub Settings → Developer settings → Personal access tokens</li>
                            <li>生成新的 token（无需选择任何权限）</li>
                            <li>将 token 粘贴到上方输入框中</li>
                        </ol>
                        
                        <p><strong>Telegram配置:</strong></p>
                        <ul style="margin-left: 20px;">
                            <li>通过 @BotFather 创建机器人获取Token</li>
                            <li>向机器人发送消息后获取Chat ID</li>
                            <li>点击"测试通知"验证配置</li>
                        </ul>
                        
                        <p><strong>同步功能说明:</strong></p>
                        <ul style="margin-left: 20px;">
                            <li>源仓库更新时自动同步到目标仓库</li>
                            <li>使用GitHub合并API实现</li>
                            <li>遇到合并冲突时会自动终止</li>
                            <li>需要目标仓库的写入权限</li>
                        </ul>
                        
                        <p><strong>定时任务通知:</strong></p>
                        <ul style="margin-left: 20px;">
                            <li>开启：每次定时任务执行都会发送执行结果</li>
                            <li>关闭：只发送仓库更新通知，不发送定时任务执行日志</li>
                        </ul>
                        
                        <p><strong>提交历史显示:</strong></p>
                        <ul style="margin-left: 20px;">
                            <li>检测到更新时，会显示从上次记录到最新的所有提交</li>
                            <li>最多显示100个提交（GitHub API限制）</li>
                            <li>如果提交历史很长，会提示可能不完整</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        function switchTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            document.getElementById(tabId).classList.add('active');
            event.target.classList.add('active');
        }
        
        setTimeout(() => {
            const alerts = document.querySelectorAll('.alert');
            alerts.forEach(alert => {
                if (alert.classList.contains('alert-success')) {
                    alert.style.transition = 'opacity 0.5s ease';
                    alert.style.opacity = '0';
                    setTimeout(() => alert.remove(), 500);
                }
            });
        }, 5000);
        
        document.addEventListener('DOMContentLoaded', function() {
            const forms = document.querySelectorAll('form');
            forms.forEach(form => {
                form.addEventListener('submit', function(e) {
                    const submitBtn = this.querySelector('button[type="submit"]');
                    if (submitBtn) {
                        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 处理中...';
                        submitBtn.disabled = true;
                    }
                });
            });
        });
    </script>
</body>
</html>`;
}