import type { Env } from '../env'
import { runCheck } from './checker'
import { type CronLog, setLastCronLog } from '../storage/cron-log'
import { getNotifications, getTelegram } from '../storage/settings'
import { TelegramClient, buildCronLogMessage } from './telegram'
import { formatShanghai } from '../lib/time'

export async function runCron(env: Env): Promise<CronLog> {
  console.log('🕒 开始执行定时检查任务')
  const startTime = Date.now()
  let result: CronLog['result']
  let errorMsg: string | null = null

  try {
    const r = await runCheck(env)
    result = r
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    errorMsg = msg
    result = { success: false, error: msg }
    console.error('❌ 定时任务失败:', err)
  }
  const endTime = Date.now()

  const log: CronLog = {
    timestamp: new Date().toISOString(),
    startTime: formatShanghai(new Date(startTime)),
    endTime: formatShanghai(new Date(endTime)),
    duration: `${endTime - startTime}ms`,
    success: errorMsg === null,
    result,
    error: errorMsg,
  }
  await setLastCronLog(env, log)
  await maybeSendCronLog(env, log)
  return log
}

async function maybeSendCronLog(env: Env, log: CronLog): Promise<void> {
  try {
    const tg = await getTelegram(env)
    const notif = await getNotifications(env)
    if (!tg?.botToken || !tg?.chatId) {
      console.log('⚠️ Telegram 未配置，跳过 cron 日志')
      return
    }
    if (!notif.cronEnabled) {
      console.log('🔇 cron 通知关闭，跳过')
      return
    }
    const client = new TelegramClient(tg.botToken, tg.chatId)
    await client.send(buildCronLogMessage(log))
    console.log('📨 cron 日志已推送')
  } catch (err) {
    console.error('cron 日志推送失败:', err)
  }
}
