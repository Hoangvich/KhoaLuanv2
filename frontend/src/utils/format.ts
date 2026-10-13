import dayjs from 'dayjs'
import relativeTime from 'dayjs/plugin/relativeTime'
import 'dayjs/locale/vi'

dayjs.extend(relativeTime)
dayjs.locale('vi')

export const fmtTime = (s: string | null | undefined) => (s ? dayjs(s).format('HH:mm:ss DD/MM/YYYY') : '—')
export const fmtShort = (s: string | null | undefined) => (s ? dayjs(s).format('HH:mm:ss DD/MM') : '—')
export const fromNow = (s: string | null | undefined) => (s ? dayjs(s).fromNow() : '—')
export const fmtInt = (n: number | null | undefined) => (n == null ? '—' : n.toLocaleString('vi-VN'))
export const fmtPct = (x: number | null | undefined, digits = 1) =>
  x == null ? '—' : `${(x * 100).toLocaleString('vi-VN', { maximumFractionDigits: digits })}%`

export function fmtDuration(fromIso: string, toIso: string) {
  const s = Math.max(0, dayjs(toIso).diff(dayjs(fromIso), 'second'))
  if (s < 60) return `${s} giây`
  if (s < 3600) return `${Math.floor(s / 60)} phút ${s % 60} giây`
  return `${Math.floor(s / 3600)} giờ ${Math.floor((s % 3600) / 60)} phút`
}

export const PROTOCOLS: Record<number, string> = { 6: 'TCP', 17: 'UDP', 1: 'ICMP' }

export function target(ip: string | null, port: number | null) {
  if (!ip) return '—'
  return port ? `${ip}:${port}` : ip
}
