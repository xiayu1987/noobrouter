// UI language: zh-CN / en. Choice persists in localStorage; first visit follows the browser.
import { computed } from 'vue'
import { createI18n } from 'vue-i18n'
import epZh from 'element-plus/es/locale/lang/zh-cn'
import epEn from 'element-plus/es/locale/lang/en'
import zh from './locales/zh'
import en from './locales/en'

const KEY = 'noobrouter_lang'
export const LANGS = [{ value: 'zh-CN', label: '中文' }, { value: 'en', label: 'English' }]

function initial() {
  const saved = localStorage.getItem(KEY)
  if (LANGS.some((l) => l.value === saved)) return saved
  return (navigator.language || '').toLowerCase().startsWith('zh') ? 'zh-CN' : 'en'
}

export const i18n = createI18n({
  legacy: false,
  globalInjection: true,
  locale: initial(),
  fallbackLocale: 'zh-CN',
  messages: { 'zh-CN': zh, en },
})

export const t = (...a) => i18n.global.t(...a)
export const locale = computed(() => i18n.global.locale.value)
export const epLocale = computed(() => (locale.value === 'en' ? epEn : epZh))

export function setLocale(v) {
  i18n.global.locale.value = v
  localStorage.setItem(KEY, v)
  document.documentElement.lang = v
}
document.documentElement.lang = i18n.global.locale.value
