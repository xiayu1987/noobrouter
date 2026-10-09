import { createRouter, createWebHistory } from 'vue-router'
import { token } from './auth'
import { t } from './i18n'

// title is an i18n key under menu.*
export const menu = [
  { path: '/', name: 'overview', icon: 'Odometer', component: () => import('./views/Overview.vue') },
  { path: '/traffic', name: 'traffic', icon: 'TrendCharts', component: () => import('./views/Traffic.vue') },
  { path: '/devices', name: 'devices', icon: 'Monitor', component: () => import('./views/Devices.vue') },
  { path: '/interfaces', name: 'interfaces', icon: 'Connection', component: () => import('./views/Interfaces.vue') },
  { path: '/firewall', name: 'firewall', icon: 'Lock', component: () => import('./views/Firewall.vue') },
  { path: '/dhcp', name: 'dhcp', icon: 'Share', component: () => import('./views/Dhcp.vue') },
  { path: '/connections', name: 'connections', icon: 'Switch', component: () => import('./views/Connections.vue') },
  { path: '/system', name: 'system', icon: 'Document', component: () => import('./views/System.vue') },
  { path: '/diag', name: 'diag', icon: 'Aim', component: () => import('./views/Diag.vue') },
  { path: '/init', name: 'init', icon: 'MagicStick', component: () => import('./views/Init.vue') },
]

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', name: 'login', component: () => import('./views/Login.vue'), meta: { public: true } },
    ...menu.map(({ path, name, component }) => ({ path, name, component, meta: { title: `menu.${name}` } })),
    { path: '/:pathMatch(.*)*', redirect: '/' },
  ],
})

router.beforeEach((to) => {
  if (!to.meta.public && !token.get()) {
    return { name: 'login', query: { redirect: to.fullPath } }
  }
})

export function setTitle(route) {
  document.title = route.meta.title ? `${t(route.meta.title)} - NoobRouter` : 'NoobRouter'
}
router.afterEach(setTitle)

export default router
