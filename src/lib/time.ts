export function formatShanghai(date: Date): string {
  return date.toLocaleString('zh-CN', {
    timeZone: 'Asia/Shanghai',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

export function formatShanghaiShort(date: Date): string {
  return date.toLocaleString('zh-CN', {
    timeZone: 'Asia/Shanghai',
    hour: '2-digit', minute: '2-digit',
  })
}

export function relativeTime(from: Date, now: Date = new Date()): string {
  const sec = Math.floor((now.getTime() - from.getTime()) / 1000)
  if (sec < 60) return '刚刚'
  const min = Math.floor(sec / 60)
  if (min < 60) return `${min} 分钟前`
  const hr = Math.floor(min / 60)
  if (hr < 24) return `${hr} 小时前`
  const day = Math.floor(hr / 24)
  if (day < 30) return `${day} 天前`
  const mon = Math.floor(day / 30)
  if (mon < 12) return `${mon} 个月前`
  return `${Math.floor(mon / 12)} 年前`
}
