// 使用原生 Worker API
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url)
    const path = url.pathname

    // 处理根路径 - 显示管理面板
    if (path === '/') {
      return handleDashboard(request, env, url)
    }

    // 处理登录页面
    if (path === '/login') {
      return handleLogin(request, env, url)
    }

    // 处理登出
    if (path === '/logout') {
      return handleLogout(request, env)
    }

    // 处理API端点
    if (path === '/check-updates') {
      return handleCheckUpdates(env)
    }

    if (path === '/health') {
      return new Response(JSON.stringify({
        status: 'ok',
        timestamp: new Date().toISOString()
      }), {
        headers: { 'Content-Type': 'application/json' }
      })
    }

    return new Response('Not Found', { status: 404 })
  },

  async scheduled(event, env, ctx) {
    // 使用新的cron处理函数
    await handleCronExecution(event, env, ctx)
  }
}

// 存储键名常量
const STORAGE_KEYS = {
  PASSWORD_HASH: 'admin_password_hash',
  REPO_LIST: 'monitored_repositories',
  LAST_COMMITS: 'last_commit_',
  TG_BOT_TOKEN: 'telegram_bot_token',
  TG_CHAT_ID: 'telegram_chat_id',
  GITHUB_TOKEN: 'github_token',
  LAST_CHECK_TIME: 'last_check_time',
  LAST_CRON_LOG: 'last_cron_log' // 新增：存储上次cron执行日志
}

// 处理cron执行
async function handleCronExecution(event, env, ctx) {
  console.log('🕒 开始执行定时检查任务:', new Date().toISOString())
  
  const startTime = Date.now()
  let result
  let error = null
  
  try {
    // 修复：从 Response 对象中提取 JSON 数据
    const response = await handleCheckUpdates(env)
    result = await response.json()
    console.log('✅ 定时检查任务完成:', result)
  } catch (err) {
    console.error('❌ 定时检查任务失败:', err)
    error = err
    result = { success: false, error: err.message }
  }
  
  const endTime = Date.now()
  const duration = endTime - startTime
  
  // 构建cron执行日志
  const cronLog = {
    timestamp: new Date().toISOString(),
    startTime: new Date(startTime).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' }),
    endTime: new Date(endTime).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' }),
    duration: `${duration}ms`,
    success: !error,
    result: result,
    error: error ? error.message : null
  }
  
  // 保存日志到存储
  await env.STORAGE.put(STORAGE_KEYS.LAST_CRON_LOG, JSON.stringify(cronLog))
  
  // 发送Telegram通知
  await sendCronLogToTelegram(cronLog, env)
  
  return cronLog
}

// 发送cron日志到Telegram
async function sendCronLogToTelegram(cronLog, env) {
  try {
    const settings = await getSettings(env)
    
    if (!settings.tg_bot_token || !settings.tg_chat_id) {
      console.log('⚠️ Telegram未配置，跳过cron日志发送')
      return
    }
    
    const message = buildCronLogMessage(cronLog, env)
    await sendTelegramMessage(settings.tg_bot_token, settings.tg_chat_id, message)
    console.log('📨 Cron执行日志已发送到Telegram')
  } catch (error) {
    console.error('❌ 发送cron日志到Telegram失败:', error)
  }
}

// 构建格式化的cron日志消息
function buildCronLogMessage(cronLog, env) {
  const statusIcon = cronLog.success ? '✅' : '❌'
  const statusText = cronLog.success ? '执行成功' : '执行失败'
  const title = `${statusIcon} <b>GitHub Monitor 定时任务报告</b>`
  
  // 基础信息
  const basicInfo = `
📅 <b>执行时间:</b> ${cronLog.startTime}
⏱️ <b>执行时长:</b> ${cronLog.duration}
🔄 <b>执行状态:</b> ${statusText}
  `.trim()
  
  // 结果详情 - 修复数据访问
  let resultDetails = ''
  if (cronLog.success && cronLog.result) {
    const result = cronLog.result
    
    // 正确提取检查结果数据
    const checkedCount = (result.checkedCount !== undefined && result.checkedCount !== null) ? result.checkedCount : 0
    const updatedCount = (result.updatedCount !== undefined && result.updatedCount !== null) ? result.updatedCount : 0
    const errorCount = (result.errorCount !== undefined && result.errorCount !== null) ? result.errorCount : 0
    
    resultDetails = `
📊 <b>检查结果:</b>
   • 已检查仓库: ${checkedCount}
   • 发现更新: ${updatedCount}
   • 错误数量: ${errorCount}
💬 <b>总结:</b> ${result.message || '检查完成'}
    `.trim()
  } else if (cronLog.error) {
    resultDetails = `
🚨 <b>错误信息:</b>
<code>${cronLog.error}</code>
    `.trim()
  }
  
  // 系统状态
  const systemInfo = `
💻 <b>系统状态:</b> ${cronLog.success ? '正常运行' : '遇到问题'}
🔔 <b>通知渠道:</b> Telegram
  `.trim()
  
  // 组合所有部分
  const message = `
${title}

${basicInfo}

${resultDetails}

${systemInfo}

<i>此消息由GitHub Monitor定时任务自动发送</i>
  `.trim()
  
  return message
}

// 简化会话管理 - 使用简单的密码验证
async function checkAuth(request, env) {
  const cookieHeader = request.headers.get('Cookie')
  if (cookieHeader && cookieHeader.includes('authenticated=true')) {
    // 检查会话是否在合理时间内创建（24小时内）
    const cookies = cookieHeader.split(';').map(c => c.trim())
    const sessionCookie = cookies.find(c => c.startsWith('session_created='))
    if (sessionCookie) {
      const sessionTime = parseInt(sessionCookie.split('=')[1])
      if (Date.now() - sessionTime < 24 * 60 * 60 * 1000) { // 24小时
        return { authenticated: true }
      }
    }
  }
  return { authenticated: false }
}

// 初始化管理密码
async function initAdminPassword(env) {
  const existingHash = await env.STORAGE.get(STORAGE_KEYS.PASSWORD_HASH)
  if (!existingHash) {
    console.log('初始化默认管理员密码...')
    const defaultPassword = 'admin123'
    const encoder = new TextEncoder()
    const data = encoder.encode(defaultPassword)
    const hashBuffer = await crypto.subtle.digest('SHA-256', data)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
    await env.STORAGE.put(STORAGE_KEYS.PASSWORD_HASH, hashHex)
    console.log('默认密码已设置:', defaultPassword)
  }
}

// 验证密码
async function verifyPassword(password, env) {
  try {
    const storedHash = await env.STORAGE.get(STORAGE_KEYS.PASSWORD_HASH)
    if (!storedHash) {
      console.log('未找到存储的密码哈希')
      return false
    }
    
    const encoder = new TextEncoder()
    const data = encoder.encode(password)
    const hashBuffer = await crypto.subtle.digest('SHA-256', data)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
    
    const isValid = hashHex === storedHash
    console.log('密码验证结果:', isValid ? '成功' : '失败')
    return isValid
  } catch (error) {
    console.error('密码验证错误:', error)
    return false
  }
}

// 处理登录
async function handleLogin(request, env, url) {
  await initAdminPassword(env)

  // 如果已经登录，重定向到首页
  const auth = await checkAuth(request, env)
  if (auth.authenticated) {
    return Response.redirect(url.origin, 302)
  }

  // 处理 POST 登录请求
  if (request.method === 'POST') {
    try {
      const formData = await request.formData()
      const password = formData.get('password')
      
      console.log('收到登录请求，密码长度:', password ? password.length : 0)
      
      if (!password) {
        return showLoginPage('错误：请输入密码')
      }
      
      const isValid = await verifyPassword(password, env)
      if (isValid) {
        console.log('登录成功，设置认证cookie')
        // 创建响应并设置cookie
        const sessionTime = Date.now()
        const headers = new Headers()
        headers.set('Location', url.origin)
        headers.set('Set-Cookie', `authenticated=true; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400`)
        headers.append('Set-Cookie', `session_created=${sessionTime}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400`)
        return new Response(null, {
          status: 302,
          headers: headers
        })
      } else {
        console.log('密码验证失败')
        return showLoginPage('密码错误，请重试')
      }
    } catch (error) {
      console.error('登录处理错误:', error)
      return showLoginPage('登录时发生错误，请重试')
    }
  }

  // 显示登录页面
  return showLoginPage()
}

// 处理登出
async function handleLogout(request, env) {
  const headers = new Headers()
  headers.set('Location', new URL('/', request.url).toString())
  headers.set('Set-Cookie', 'authenticated=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0')
  headers.append('Set-Cookie', 'session_created=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0')
  
  return new Response(null, {
    status: 302,
    headers: headers
  })
}

// 显示登录页面
function showLoginPage(errorMessage = '') {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录 - GitHub Monitor</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary: #6366f1;
            --primary-light: #818cf8;
            --primary-dark: #4f46e5;
            --success: #10b981;
            --danger: #ef4444;
            --dark: #1e293b;
            --light: #f8fafc;
            --gray: #64748b;
            --border: #e2e8f0;
            --shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
            --shadow-lg: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
            --radius: 16px;
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
        
        .alert i {
            margin-right: 8px;
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
        
        .password-note {
            margin-top: 16px;
            padding: 12px;
            background: #f8fafc;
            border-radius: 8px;
            font-size: 0.875rem;
            color: var(--gray);
            text-align: left;
        }
        
        .password-note strong {
            color: var(--dark);
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
</html>`
  
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  })
}

// 处理仪表板
async function handleDashboard(request, env, url) {
  await initAdminPassword(env)

  // 检查认证
  const auth = await checkAuth(request, env)
  if (!auth.authenticated) {
    const headers = new Headers()
    headers.set('Location', new URL('/login', request.url).toString())
    return new Response(null, { status: 302, headers: headers })
  }

  // 处理 POST 请求
  if (request.method === 'POST') {
    try {
      const formData = await request.formData()
      const action = formData.get('action')

      if (action === 'add') {
        return handleAddRepo(formData, env)
      } else if (action === 'delete') {
        return handleDeleteRepo(formData, env)
      } else if (action === 'check') {
        return handleManualCheck(env)
      } else if (action === 'clear') {
        return handleClearRepos(env)
      } else if (action === 'update_settings') {
        return handleUpdateSettings(formData, env)
      } else if (action === 'test_telegram') {
        return handleTestTelegram(env)
      } else if (action === 'test_github') {
        return handleTestGithub(env)
      } else if (action === 'change_password') {
        return handleChangePassword(formData, env)
      }
    } catch (error) {
      console.error('处理POST请求错误:', error)
      return showDashboard(env, `处理请求时发生错误: ${error.message}`)
    }
  }

  // 显示仪表板
  return showDashboard(env)
}

// 修改密码处理
async function handleChangePassword(formData, env) {
  const currentPassword = formData.get('current_password')
  const newPassword = formData.get('new_password')
  const confirmPassword = formData.get('confirm_password')
  
  if (!currentPassword || !newPassword || !confirmPassword) {
    return showDashboard(env, '错误：请填写所有密码字段')
  }
  
  if (newPassword !== confirmPassword) {
    return showDashboard(env, '错误：新密码和确认密码不匹配')
  }
  
  if (newPassword.length < 6) {
    return showDashboard(env, '错误：新密码至少需要6个字符')
  }
  
  const isValid = await verifyPassword(currentPassword, env)
  if (!isValid) {
    return showDashboard(env, '错误：当前密码不正确')
  }
  
  // 更新密码
  try {
    const encoder = new TextEncoder()
    const data = encoder.encode(newPassword)
    const hashBuffer = await crypto.subtle.digest('SHA-256', data)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
    await env.STORAGE.put(STORAGE_KEYS.PASSWORD_HASH, hashHex)
    
    return showDashboard(env, '成功：密码已更新')
  } catch (error) {
    console.error('更新密码错误:', error)
    return showDashboard(env, `错误：更新密码失败 - ${error.message}`)
  }
}

// 获取最后检查时间
async function getLastCheckTime(env) {
  return await env.STORAGE.get(STORAGE_KEYS.LAST_CHECK_TIME) || '从未检查'
}

// 获取最后cron日志
async function getLastCronLog(env) {
  const logData = await env.STORAGE.get(STORAGE_KEYS.LAST_CRON_LOG)
  if (!logData) return null
  try {
    return JSON.parse(logData)
  } catch {
    return null
  }
}

// 显示仪表板
async function showDashboard(env, message = '') {
  const repoList = await getRepoList(env)
  const settings = await getSettings(env)
  const lastCheckTime = await getLastCheckTime(env)
  const lastCronLog = await getLastCronLog(env)
  const html = generateDashboardHTML(repoList, settings, message, lastCheckTime, lastCronLog)
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  })
}

// 生成仪表板 HTML
function generateDashboardHTML(repoList, settings, message, lastCheckTime, lastCronLog) {
  const repoCards = repoList.map(repo => `
    <div class="repo-card">
      <div class="repo-info">
        <div class="repo-icon">
          <i class="fab fa-github"></i>
        </div>
        <div class="repo-details">
          <h3>${repo.owner}/${repo.repo}</h3>
          <p class="repo-branch">
            <i class="fas fa-code-branch"></i>
            ${repo.branch}
          </p>
        </div>
      </div>
      <div class="repo-actions">
        <form method="post" class="inline-form">
          <input type="hidden" name="action" value="delete">
          <input type="hidden" name="owner" value="${repo.owner}">
          <input type="hidden" name="repo" value="${repo.repo}">
          <input type="hidden" name="branch" value="${repo.branch}">
          <button type="submit" class="btn btn-danger btn-sm" onclick="return confirm('确定要删除这个仓库吗？')">
            <i class="fas fa-trash"></i>
          </button>
        </form>
      </div>
    </div>
  `).join('')

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GitHub Monitor - 代码仓库监控系统</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary: #6366f1;
            --primary-light: #818cf8;
            --primary-dark: #4f46e5;
            --secondary: #f59e0b;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --info: #06b6d4;
            --dark: #1e293b;
            --darker: #0f172a;
            --light: #f8fafc;
            --gray: #64748b;
            --gray-light: #cbd5e1;
            --border: #e2e8f0;
            --shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
            --shadow-lg: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
            --radius: 16px;
            --radius-sm: 8px;
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
        
        .user-info {
            text-align: right;
        }
        
        .user-name {
            font-weight: 600;
            color: var(--darker);
        }
        
        .user-role {
            font-size: 0.875rem;
            color: var(--gray);
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
        
        .header-stats {
            display: flex;
            gap: 24px;
        }
        
        .stat {
            text-align: center;
        }
        
        .stat-number {
            display: block;
            font-size: 2.5rem;
            font-weight: 800;
            color: var(--primary);
            line-height: 1;
        }
        
        .stat-label {
            font-size: 0.875rem;
            color: var(--gray);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
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
        
        .btn-success:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(16, 185, 129, 0.3);
        }
        
        .btn-danger {
            background: linear-gradient(135deg, var(--danger), #dc2626);
            color: white;
        }
        
        .btn-danger:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(239, 68, 68, 0.3);
        }
        
        .btn-warning {
            background: linear-gradient(135deg, var(--warning), #d97706);
            color: white;
        }
        
        .btn-warning:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(245, 158, 11, 0.3);
        }
        
        .btn-info {
            background: linear-gradient(135deg, var(--info), #0891b2);
            color: white;
        }
        
        .btn-info:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(6, 182, 212, 0.3);
        }
        
        .btn-sm {
            padding: 10px 16px;
            font-size: 14px;
        }
        
        .btn-icon {
            padding: 10px;
            width: 40px;
            height: 40px;
            justify-content: center;
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
        
        .repo-actions {
            display: flex;
            gap: 8px;
        }
        
        .inline-form {
            display: inline;
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
        
        .stat-card .stat-label {
            color: rgba(255, 255, 255, 0.9);
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
            color: var(--gray-light);
        }
        
        .empty-state h3 {
            font-size: 1.5rem;
            margin-bottom: 12px;
            color: var(--gray);
        }
        
        .action-buttons {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }
        
        .settings-form {
            display: flex;
            flex-direction: column;
            gap: 20px;
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
        
        .form-section:last-child {
            border-bottom: none;
            margin-bottom: 0;
            padding-bottom: 0;
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
            
            .header-stats {
                justify-content: center;
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
            
            .form-actions {
                flex-direction: column;
            }
            
            .form-actions .btn {
                width: 100%;
                justify-content: center;
            }
            
            /* 移动端按钮优化 */
            .action-buttons {
                flex-direction: column;
                width: 100%;
            }
            
            .action-buttons .btn {
                width: 100%;
                justify-content: center;
            }
            
            .action-buttons .inline-form {
                width: 100%;
            }
            
            .card-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 16px;
            }
            
            .card-header .action-buttons {
                width: 100%;
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
                ${message}
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
                                                   value="${settings.github_token || ''}" 
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
                                                   value="${settings.tg_bot_token || ''}" 
                                                   placeholder="输入Telegram Bot Token">
                                        </div>
                                    </div>
                                    <div class="form-group">
                                        <label for="tg_chat_id">Telegram Chat ID</label>
                                        <div class="form-input">
                                            <i class="fas fa-comment"></i>
                                            <input type="text" id="tg_chat_id" name="tg_chat_id" 
                                                   value="${settings.tg_chat_id || ''}" 
                                                   placeholder="输入Telegram Chat ID">
                                        </div>
                                    </div>
                                    
                                    <div class="status-item">
                                        <div class="status-dot ${settings.tg_bot_token && settings.tg_chat_id ? 'status-connected' : 'status-disconnected'}"></div>
                                        <span>${settings.tg_bot_token && settings.tg_chat_id ? 'Telegram 已配置' : 'Telegram 未配置'}</span>
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
                            <span class="stat-number"><i class="fas fa-check"></i></span>
                            <span class="stat-label">运行中</span>
                        </div>
                    </div>
                    <div style="margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--border);">
                        <p><strong>最后检查:</strong> ${lastCheckTime}</p>
                        <p><strong>通知状态:</strong> ${settings.tg_bot_token && settings.tg_chat_id ? '已启用' : '未配置'}</p>
                        <p><strong>GitHub状态:</strong> ${settings.github_token ? '已认证' : '未认证（受限）'}</p>
                        
                        ${lastCronLog ? `
                        <div class="cron-log">
                            <p class="cron-log-title">上次定时任务执行</p>
                            <p class="cron-log-detail"><strong>时间:</strong> ${lastCronLog.startTime}</p>
                            <p class="cron-log-detail"><strong>状态:</strong> ${lastCronLog.success ? '✅ 成功' : '❌ 失败'}</p>
                            <p class="cron-log-detail"><strong>时长:</strong> ${lastCronLog.duration}</p>
                            ${lastCronLog.result && lastCronLog.result.checkedCount !== undefined ? `
                            <p class="cron-log-detail"><strong>检查:</strong> ${lastCronLog.result.checkedCount} 仓库, ${lastCronLog.result.updatedCount} 更新, ${lastCronLog.result.errorCount} 错误</p>
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
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        function switchTab(tabId) {
            // 隐藏所有标签内容
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // 取消所有标签的激活状态
            document.querySelectorAll('.tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // 显示选中的标签内容
            document.getElementById(tabId).classList.add('active');
            
            // 激活选中的标签
            event.target.classList.add('active');
        }
        
        // 自动隐藏成功消息
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
        
        // 表单验证增强
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
</html>`
}

// 获取设置
async function getSettings(env) {
  const tg_bot_token = await env.STORAGE.get(STORAGE_KEYS.TG_BOT_TOKEN)
  const tg_chat_id = await env.STORAGE.get(STORAGE_KEYS.TG_CHAT_ID)
  const github_token = await env.STORAGE.get(STORAGE_KEYS.GITHUB_TOKEN)
  
  return {
    tg_bot_token: tg_bot_token || '',
    tg_chat_id: tg_chat_id || '',
    github_token: github_token || ''
  }
}

// 保存设置
async function saveSettings(settings, env) {
  if (settings.tg_bot_token) {
    await env.STORAGE.put(STORAGE_KEYS.TG_BOT_TOKEN, settings.tg_bot_token)
  }
  if (settings.tg_chat_id) {
    await env.STORAGE.put(STORAGE_KEYS.TG_CHAT_ID, settings.tg_chat_id)
  }
  if (settings.github_token) {
    await env.STORAGE.put(STORAGE_KEYS.GITHUB_TOKEN, settings.github_token)
  }
}

// 更新设置处理
async function handleUpdateSettings(formData, env) {
  const tg_bot_token = formData.get('tg_bot_token')?.trim()
  const tg_chat_id = formData.get('tg_chat_id')?.trim()
  const github_token = formData.get('github_token')?.trim()
  
  const settings = {
    tg_bot_token,
    tg_chat_id,
    github_token
  }
  
  await saveSettings(settings, env)
  
  return showDashboard(env, '设置已保存成功')
}

// 测试Telegram通知
async function handleTestTelegram(env) {
  try {
    const settings = await getSettings(env)
    
    if (!settings.tg_bot_token || !settings.tg_chat_id) {
      return showDashboard(env, '错误：请先配置Telegram Bot Token和Chat ID')
    }
    
    const message = `
🔔 <b>测试通知</b>

✅ GitHub监控系统运行正常！
📊 系统已成功连接到Telegram
⏰ 测试时间: ${new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}

<i>这是一条测试消息，用于验证Telegram通知功能是否正常工作。</i>
    `.trim()
    
    await sendTelegramMessage(settings.tg_bot_token, settings.tg_chat_id, message)
    
    return showDashboard(env, '测试通知已发送，请检查Telegram是否收到消息')
  } catch (error) {
    return showDashboard(env, `错误：发送测试通知失败 - ${error.message}`)
  }
}

// 测试GitHub连接
async function handleTestGithub(env) {
  try {
    const settings = await getSettings(env)
    
    if (!settings.github_token) {
      return showDashboard(env, '错误：请先配置GitHub Token')
    }
    
    // 测试GitHub API连接
    const testRepo = { owner: 'github', repo: 'gitignore', branch: 'main' }
    const commit = await fetchLatestCommit(testRepo.owner, testRepo.repo, testRepo.branch, settings.github_token)
    
    if (commit && commit.sha) {
      return showDashboard(env, 'GitHub API连接测试成功！Token配置正确。')
    } else {
      return showDashboard(env, 'GitHub API连接测试失败，请检查Token是否正确。')
    }
  } catch (error) {
    return showDashboard(env, `GitHub API连接测试失败: ${error.message}`)
  }
}

// 添加仓库处理
async function handleAddRepo(formData, env) {
  const owner = formData.get('owner')?.trim()
  const repo = formData.get('repo')?.trim()
  let branch = formData.get('branch')?.trim()
  
  if (!owner || !repo) {
    return showDashboard(env, '错误：仓库所有者和仓库名称不能为空')
  }
  
  if (!branch) branch = 'main'
  
  try {
    const repoList = await getRepoList(env)
    const settings = await getSettings(env)
    
    // 检查是否已存在
    const exists = repoList.some(r => 
      r.owner === owner && r.repo === repo && r.branch === branch
    )
    
    if (exists) {
      return showDashboard(env, '错误：该仓库和分支组合已存在')
    }
    
    // 验证仓库是否存在
    await fetchLatestCommit(owner, repo, branch, settings.github_token)
    
    // 添加到列表
    repoList.push({ owner, repo, branch })
    await saveRepoList(repoList, env)
    
    return showDashboard(env, `成功：已添加仓库 ${owner}/${repo} (${branch})`)
  } catch (error) {
    return showDashboard(env, `错误：无法添加仓库 - ${error.message}`)
  }
}

// 删除仓库处理
async function handleDeleteRepo(formData, env) {
  const owner = formData.get('owner')
  const repo = formData.get('repo')
  const branch = formData.get('branch')
  
  const repoList = await getRepoList(env)
  const filteredList = repoList.filter(r => 
    !(r.owner === owner && r.repo === repo && r.branch === branch)
  )
  
  await saveRepoList(filteredList, env)
  
  // 删除对应的提交记录
  const commitKey = `${STORAGE_KEYS.LAST_COMMITS}${owner}:${repo}:${branch}`
  await env.STORAGE.delete(commitKey)
  
  return showDashboard(env, `成功：已删除仓库 ${owner}/${repo} (${branch})`)
}

// 手动检查处理
async function handleManualCheck(env) {
  const result = await checkAllRepos(env)
  if (result.success) {
    return showDashboard(env, result.message)
  } else {
    return showDashboard(env, `检查更新时出错: ${result.error}`)
  }
}

// 清空仓库处理
async function handleClearRepos(env) {
  await saveRepoList([], env)
  return showDashboard(env, '已清空所有监控的仓库')
}

// 获取仓库列表
async function getRepoList(env) {
  const repoList = await env.STORAGE.get(STORAGE_KEYS.REPO_LIST, 'json')
  return repoList || []
}

// 保存仓库列表
async function saveRepoList(repoList, env) {
  await env.STORAGE.put(STORAGE_KEYS.REPO_LIST, JSON.stringify(repoList))
}

// 获取上次提交的SHA
async function getLastCommit(owner, repo, branch, env) {
  const key = `${STORAGE_KEYS.LAST_COMMITS}${owner}:${repo}:${branch}`
  return await env.STORAGE.get(key)
}

// 保存上次提交的SHA
async function saveLastCommit(owner, repo, branch, sha, env) {
  const key = `${STORAGE_KEYS.LAST_COMMITS}${owner}:${repo}:${branch}`
  await env.STORAGE.put(key, sha)
}

// 从GitHub API获取最新提交
async function fetchLatestCommit(owner, repo, branch, githubToken = null) {
  const url = `https://api.github.com/repos/${owner}/${repo}/commits?sha=${branch}&per_page=1`
  
  const headers = {
    'User-Agent': 'GitHub-Monitor-Bot',
    'Accept': 'application/vnd.github.v3+json'
  }
  
  // 如果提供了GitHub Token，添加到请求头中
  if (githubToken) {
    headers['Authorization'] = `token ${githubToken}`
  }
  
  const response = await fetch(url, { headers })
  
  if (!response.ok) {
    if (response.status === 403) {
      if (githubToken) {
        throw new Error('GitHub API 频率限制（即使使用Token也达到限制），请稍后重试')
      } else {
        throw new Error('GitHub API 频率限制（未认证请求），请配置GitHub Token以提高限制')
      }
    } else if (response.status === 404) {
      throw new Error('仓库不存在或没有访问权限')
    } else {
      throw new Error(`GitHub API错误: ${response.status} ${response.statusText}`)
    }
  }
  
  // 检查剩余的API限制
  const remaining = response.headers.get('X-RateLimit-Remaining')
  const limit = response.headers.get('X-RateLimit-Limit')
  console.log(`GitHub API 限制: ${remaining}/${limit}`)
  
  const commits = await response.json()
  
  if (!commits || commits.length === 0) {
    throw new Error('该分支没有提交记录')
  }
  
  return commits[0]
}

// 构建Telegram消息
function buildTelegramMessage(repoInfo, commitData) {
  const commitUrl = commitData.html_url
  const repoUrl = `https://github.com/${repoInfo.owner}/${repoInfo.repo}`
  const shortSha = commitData.sha.substring(0, 7)
  const commitMessage = commitData.commit.message.split('\n')[0]
  
  // 修复：正确转换时间到北京时间
  const commitDate = new Date(commitData.commit.author.date)
  
  // 使用toLocaleString直接转换为北京时间，不需要手动加减
  const formattedTime = commitDate.toLocaleString('zh-CN', { 
    timeZone: 'Asia/Shanghai',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  })
  
  const message = `
🚀 <b>代码仓库已更新！</b>

📦 <b>仓库:</b> <a href="${repoUrl}">${repoInfo.owner}/${repoInfo.repo}</a>
🌿 <b>分支:</b> <code>${repoInfo.branch}</code>

📝 <b>最新提交:</b> <a href="${commitUrl}">${shortSha}</a>
👤 <b>作者:</b> ${commitData.commit.author.name}
💬 <b>提交信息:</b> ${commitMessage}
⏰ <b>时间:</b> ${formattedTime} (北京时间)

<a href="${repoUrl}/tree/${repoInfo.branch}">查看分支</a> | <a href="${repoUrl}/commits/${repoInfo.branch}">查看提交历史</a>
  `.trim()
  
  return message
}

// 发送Telegram消息
async function sendTelegramMessage(botToken, chatId, message) {
  const url = `https://api.telegram.org/bot${botToken}/sendMessage`
  
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
  })
  
  if (!response.ok) {
    const errorData = await response.json()
    throw new Error(`Telegram API错误: ${response.status} - ${errorData.description || '未知错误'}`)
  }
  
  return await response.json()
}

// 检查所有仓库的更新
async function checkAllRepos(env) {
  try {
    console.log('🔍 开始检查所有仓库更新...')
    
    // 记录检查开始时间
    const checkTime = new Date().toLocaleString('zh-CN', { 
      timeZone: 'Asia/Shanghai',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    })
    
    // 保存检查时间
    await env.STORAGE.put(STORAGE_KEYS.LAST_CHECK_TIME, checkTime)
    
    const repoList = await getRepoList(env)
    const settings = await getSettings(env)
    
    if (repoList.length === 0) {
      console.log('ℹ️ 没有监控的仓库需要检查')
      return { 
        success: true, 
        message: '没有监控的仓库需要检查',
        checkedCount: 0,
        updatedCount: 0,
        errorCount: 0
      }
    }
    
    console.log(`📊 共有 ${repoList.length} 个仓库需要检查`)
    
    // 检查Telegram配置
    const hasTelegramConfig = settings.tg_bot_token && settings.tg_chat_id
    if (!hasTelegramConfig) {
      console.log('⚠️ Telegram未配置，跳过通知发送')
    } else {
      console.log('✅ Telegram已配置，将发送通知')
    }
    
    let checkedCount = 0
    let updatedCount = 0
    let errorCount = 0
    
    for (const repo of repoList) {
      try {
        console.log(`🔎 检查仓库: ${repo.owner}/${repo.repo} (${repo.branch})`)
        
        const latestCommit = await fetchLatestCommit(repo.owner, repo.repo, repo.branch, settings.github_token)
        const lastKnownCommit = await getLastCommit(repo.owner, repo.repo, repo.branch, env)
        
        checkedCount++
        
        if (!lastKnownCommit) {
          console.log(`📝 首次检查，记录提交: ${latestCommit.sha}`)
          await saveLastCommit(repo.owner, repo.repo, repo.branch, latestCommit.sha, env)
          continue
        }
        
        if (latestCommit.sha !== lastKnownCommit) {
          console.log(`🆕 检测到新提交: ${latestCommit.sha}`)
          updatedCount++
          
          if (hasTelegramConfig) {
            console.log(`📨 发送Telegram通知...`)
            const message = buildTelegramMessage(repo, latestCommit)
            await sendTelegramMessage(settings.tg_bot_token, settings.tg_chat_id, message)
            console.log(`✅ Telegram通知发送成功`)
          }
          
          await saveLastCommit(repo.owner, repo.repo, repo.branch, latestCommit.sha, env)
        } else {
          console.log(`✅ 没有新提交`)
        }
      } catch (error) {
        console.error(`❌ 检查仓库 ${repo.owner}/${repo.repo} 时出错:`, error)
        errorCount++
        
        if (hasTelegramConfig) {
          const errorMessage = `❌ <b>监控错误</b>\n\n检查仓库 ${repo.owner}/${repo.repo} (${repo.branch}) 时出错:\n<code>${error.message}</code>`
          try {
            console.log(`📨 发送错误通知...`)
            await sendTelegramMessage(settings.tg_bot_token, settings.tg_chat_id, errorMessage)
          } catch (telegramError) {
            console.error('❌ 发送错误通知失败:', telegramError)
          }
        }
      }
      
      // 添加延迟以避免触发GitHub API限制
      const delay = settings.github_token ? 500 : 2000
      console.log(`⏳ 等待 ${delay}ms 后继续...`)
      await new Promise(resolve => setTimeout(resolve, delay))
    }
    
    const message = `检查完成: 已检查 ${checkedCount} 个仓库，发现 ${updatedCount} 个更新，${errorCount} 个错误`
    console.log(`✅ ${message}`)
    return { 
      success: true, 
      message,
      checkedCount: checkedCount || 0,
      updatedCount: updatedCount || 0,
      errorCount: errorCount || 0
    }
  } catch (error) {
    console.error('❌ 检查更新时出错:', error)
    return { 
      success: false, 
      error: error.message,
      checkedCount: 0,
      updatedCount: 0,
      errorCount: 1
    }
  }
}

// 处理检查更新端点
async function handleCheckUpdates(env) {
  console.log('🔄 手动触发检查更新...')
  const result = await checkAllRepos(env)
  console.log('📋 检查更新结果:', result)
  return new Response(JSON.stringify(result), {
    headers: { 'Content-Type': 'application/json' }
  })
}