// Minimal API client: Bearer token from sessionStorage, 401 -> login page.
import { ElMessage } from 'element-plus'
import router from './router'
import { token } from './auth'
import { locale, t } from './i18n'

export class ApiError extends Error {
  constructor(message, status, data) {
    super(message)
    this.status = status
    this.data = data
  }
}

async function request(method, path, { body, query, silent = false } = {}) {
  const url = new URL(path, location.origin)
  Object.entries(query || {}).forEach(([k, v]) => v !== undefined && url.searchParams.set(k, v))
  // the agent translates its own messages (errors, warnings) from Accept-Language
  const headers = { Authorization: `Bearer ${token.get()}`, 'Accept-Language': locale.value }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  let res
  try {
    res = await fetch(url, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) })
  } catch (e) {
    if (!silent) ElMessage.error(t('api.unreachable'))
    throw new ApiError(t('api.unreachable'), 0)
  }
  const data = await res.json().catch(() => ({}))
  if (res.status === 401) {
    token.clear()
    if (router.currentRoute.value.name !== 'login') {
      router.push({ name: 'login', query: { redirect: router.currentRoute.value.fullPath } })
    }
    throw new ApiError(t('api.unauthorized'), 401, data)
  }
  if (!res.ok) {
    const msg = data.error || `HTTP ${res.status}`
    // multi-line errors (e.g. one blocker per line): plain text + pre-line, never HTML (may echo user data)
    if (!silent) ElMessage.error({ message: msg, customClass: 'msg-multiline' })
    throw new ApiError(msg, res.status, data)
  }
  return data
}

export const api = {
  get: (path, query, opts) => request('GET', path, { query, ...opts }),
  post: (path, body = {}, opts) => request('POST', path, { body, ...opts }),
}

export function fmtBytes(n, suffix = '') {
  if (n === null || n === undefined || isNaN(n)) return '-'
  const u = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  while (Math.abs(n) >= 1024 && i < u.length - 1) {
    n /= 1024
    i++
  }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}${suffix}`
}

export function fmtUptime(s) {
  s = Math.floor(s || 0)
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  const m = Math.floor((s % 3600) / 60)
  return [d ? t('time.d', { n: d }) : '', t('time.h', { n: h }), t('time.m', { n: m })].filter(Boolean).join(' ')
}

// coarse uptime for the overview card: days + hours only
export function fmtUptimeShort(s) {
  s = Math.floor(s || 0)
  const d = Math.floor(s / 86400)
  const h = Math.floor((s % 86400) / 3600)
  return [d ? t('time.d', { n: d }) : '', t('time.h', { n: h })].filter(Boolean).join(' ')
}
