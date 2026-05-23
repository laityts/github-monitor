export const KV = {
  // auth
  PASSWORD_HASH: 'auth:password-hash',
  MUST_CHANGE_PASSWORD: 'auth:must-change-password',
  HMAC_SECRET: 'auth:hmac-secret',
  sessionKey: (token: string) => `auth:session:${token}`,
  loginAttemptsKey: (ip: string) => `auth:login-attempts:${ip}`,

  // settings
  SETTINGS_TELEGRAM: 'settings:telegram',
  SETTINGS_GITHUB: 'settings:github',
  SETTINGS_NOTIFICATIONS: 'settings:notifications',

  // repos
  REPOS_LIST: 'repos:list',
  repoStateKey: (owner: string, repo: string, branch: string) =>
    `repos:state:${owner}:${repo}:${branch}`,

  // system
  SYSTEM_LAST_CHECK_TIME: 'system:last-check-time',
  SYSTEM_LAST_CRON_LOG: 'system:last-cron-log',

  // fork
  forkCacheKey: (owner: string, repo: string) => `fork:cache:${owner}:${repo}`,
  FORK_USER_FORKS_LIST: 'fork:user-forks-list',

  // migration
  MIGRATION_VERSION: 'migration:version',
} as const

// 旧键（仅供迁移使用）
export const LEGACY = {
  PASSWORD_HASH: 'admin_password_hash',
  REPO_LIST: 'monitored_repositories',
  LAST_COMMIT_PREFIX: 'last_commit_',
  TG_BOT_TOKEN: 'telegram_bot_token',
  TG_CHAT_ID: 'telegram_chat_id',
  GITHUB_TOKEN: 'github_token',
  LAST_CHECK_TIME: 'last_check_time',
  LAST_CRON_LOG: 'last_cron_log',
  CRON_NOTIFICATION_ENABLED: 'cron_notification_enabled',
} as const

export const MIGRATION_VERSION = '1'
