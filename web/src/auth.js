// Single source of truth for the agent token (sessionStorage: cleared when the tab closes).
const KEY = 'noobrouter_token'

export const token = {
  get: () => sessionStorage.getItem(KEY) || '',
  set: (t) => sessionStorage.setItem(KEY, t),
  clear: () => sessionStorage.removeItem(KEY),
}
