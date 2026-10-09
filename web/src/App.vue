<template>
  <el-config-provider :locale="epLocale">
  <router-view v-if="route.meta.public" />
  <div v-else class="layout">
    <!-- desktop: fixed sidebar; mobile: drawer -->
    <aside v-if="!isMobile" class="aside" :class="{ collapsed }">
      <nav-menu :collapsed="collapsed" />
    </aside>
    <el-drawer v-else v-model="drawer" direction="ltr" size="232px" :with-header="false" class="nav-drawer">
      <nav-menu :collapsed="false" @navigate="drawer = false" />
    </el-drawer>

    <div class="main-col">
      <header class="header">
        <el-button v-if="isMobile" text class="hamburger" :aria-label="$t('app.openMenu')" @click="drawer = true">
          <span class="bars" aria-hidden="true"><i /><i /><i /></span>
        </el-button>
        <el-button v-else text :icon="collapsed ? 'Expand' : 'Fold'" :aria-label="collapsed ? $t('app.expandMenu') : $t('app.foldMenu')"
          @click="collapsed = !collapsed" />
        <span class="host"><el-icon><Monitor /></el-icon><span class="ellipsis">{{ st.hostname || '-' }}</span></span>
        <el-tag v-if="st.dry_run" type="warning" effect="dark" size="small">{{ isMobile ? 'DRY-RUN' : $t('app.dryRun') }}</el-tag>
        <span v-if="st.wan" class="wan" :class="st.wan.up ? 'up' : 'down'">
          <i class="dot" aria-hidden="true" /><span class="ellipsis">WAN {{ st.wan.up ? (st.wan.ipv4[0] || $t('app.wanUp')) : $t('app.wanDown') }}</span>
        </span>
        <span class="spacer" />
        <lang-switch />
        <el-tooltip :content="dark ? $t('app.toLight') : $t('app.toDark')" placement="bottom">
          <el-button text circle :icon="dark ? 'Sunny' : 'Moon'" :aria-label="dark ? $t('app.toLight') : $t('app.toDark')"
            :aria-pressed="dark" @click="dark = !dark" />
        </el-tooltip>
        <el-button text icon="SwitchButton" :aria-label="$t('app.logout')" @click="logout"><span v-if="!isMobile">{{ $t('app.logout') }}</span></el-button>
      </header>
      <el-alert v-if="st.pending" type="error" :closable="false" show-icon class="pending">
        <template #title>
          {{ $t('app.pending', { kind: st.pending.kind === 'init' ? $t('app.pendingInit') : $t('app.pendingFw'), n: st.pending.remaining }) }}
          <router-link :to="st.pending.kind === 'init' ? '/init' : '/firewall'">{{ $t('app.goConfirm') }}</router-link>
        </template>
      </el-alert>
      <!-- the scroll container spans the full width; only the inner .page is width-limited -->
      <main class="content">
        <div class="page"><router-view /></div>
      </main>
    </div>
  </div>
  </el-config-provider>
</template>

<script setup>
import { h, onBeforeUnmount, ref, resolveComponent, watch, watchEffect } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { menu, setTitle } from './router'
import { api } from './api'
import { token } from './auth'
import { isMobile } from './viewport'
import { status as st, startStatus, stopStatus } from './status'
import { epLocale, locale, t } from './i18n'
import LangSwitch from './components/LangSwitch.vue'

const route = useRoute()
const router = useRouter()
const collapsed = ref(false)
const drawer = ref(false)
// fall back to the pre-rename key once so the theme survives the softroute -> NoobRouter upgrade
const dark = ref((localStorage.getItem('noobrouter_dark') ?? localStorage.getItem('softroute_dark')) === '1')
localStorage.removeItem('softroute_dark')
watchEffect(() => {
  document.documentElement.classList.toggle('dark', dark.value)
  localStorage.setItem('noobrouter_dark', dark.value ? '1' : '0')
})
// Poll status only on a resolved, non-public route with a token. Firing on the
// initial START_LOCATION (before the guard runs) caused a 401 that pushed
// /login?redirect=/ and lost the deep link.
router.isReady().then(() => {
  watch(() => [route.meta.public, route.name],
    ([pub]) => (pub || !token.get() ? stopStatus() : startStatus(api)), { immediate: true })
})
watch(isMobile, (m) => { if (!m) drawer.value = false })
watch(locale, () => setTitle(route))
onBeforeUnmount(stopStatus)

// brand + menu, shared by sidebar and drawer
const NavMenu = (props, { emit }) => {
  const ElMenu = resolveComponent('el-menu'), ElMenuItem = resolveComponent('el-menu-item'), ElIcon = resolveComponent('el-icon')
  return h('div', { class: 'nav-wrap' }, [
    h('div', { class: 'brand' }, [
      h('span', { class: 'logo', 'aria-hidden': 'true' }, 'SR'),
      props.collapsed ? null : h('span', { class: 'brand-text' }, ['NoobRouter', h('small', 'Console')]),
    ]),
    h(ElMenu, {
      defaultActive: route.path, collapse: props.collapsed, router: true, class: 'nav',
      backgroundColor: 'transparent', textColor: '#cbd5e1', activeTextColor: '#ffffff',
      onSelect: () => emit('navigate'),
    }, () => menu.map((m) => h(ElMenuItem, { key: m.path, index: m.path }, {
      default: () => h(ElIcon, null, () => h(resolveComponent(m.icon))),
      title: () => t(`menu.${m.name}`),
    }))),
  ])
}
NavMenu.props = ['collapsed']
NavMenu.emits = ['navigate']

function logout() {
  token.clear()
  router.push({ name: 'login' })
}
</script>
