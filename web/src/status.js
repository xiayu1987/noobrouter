// Shared /api/status poller (header badge, pending-rollback banner, overview page).
import { reactive } from 'vue'

export const status = reactive({})
let timer = null

async function tick(api) {
  try {
    Object.assign(status, await api.get('/api/status', undefined, { silent: true }))
  } catch {
    /* 401 is handled by api.js; network errors keep the last value */
  }
}

export function startStatus(api, ms = 3000) {
  if (timer) return
  tick(api)
  timer = setInterval(() => tick(api), ms)
}

export function stopStatus() {
  clearInterval(timer)
  timer = null
}

export function refreshStatus(api) {
  return tick(api)
}
