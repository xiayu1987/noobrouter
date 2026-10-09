<template>
  <div>
    <h3 class="page-title">{{ $t('init.title') }}</h3>

    <el-alert v-if="pend" type="error" :closable="false" show-icon class="mb">
      <template #title>{{ $t('init.pendTitle', { n: pend.remaining, s: pend.summary || pend.txid }) }}</template>
      <p>{{ $t('init.pendTip') }}</p>
      <el-button type="success" :loading="busy" @click="act('/api/init/confirm', $t('init.confirmed'))">{{ $t('init.keep') }}</el-button>
      <el-button type="danger" :loading="busy" @click="act('/api/init/rollback', $t('init.rolledBack'))">{{ $t('init.rollbackNow') }}</el-button>
    </el-alert>
    <el-alert v-else-if="status.pending" type="warning" :closable="false" show-icon class="mb">
      <template #title>{{ $t('init.fwPending') }}<router-link to="/firewall">{{ $t('init.goFw') }}</router-link></template>
    </el-alert>

    <el-alert v-if="st.last_rollback?.kind === 'init'" type="warning" show-icon class="mb"
      :title="$t('init.lastRollback', { tx: st.last_rollback.txid, reason: st.last_rollback.reason, at: new Date(st.last_rollback.at * 1000).toLocaleString() })" />
    <el-alert v-if="st.initialized" type="success" show-icon :closable="false" class="mb"
      :title="$t('init.initialized', { wt: st.initialized.plan.wan.type, wi: st.initialized.plan.wan.if, li: st.initialized.plan.lan.if, la: st.initialized.plan.lan.address })" />
    <el-alert v-if="d.dry_run" type="info" show-icon :closable="false" class="mb"
      :title="$t('init.dryRun')" />

    <el-card shadow="never" :header="$t('init.probe')" class="mb">
      <el-descriptions :column="isMobile ? 1 : 2" border size="small">
        <el-descriptions-item :label="$t('init.os')">{{ p.os || '-' }}<el-tag v-if="p.os && !p.debian" type="warning" size="small" class="ml-xs">{{ $t('init.notDebian') }}</el-tag></el-descriptions-item>
        <el-descriptions-item :label="$t('init.ipFwd')">{{ p.ip_forward ? $t('init.on') : $t('init.off') }}</el-descriptions-item>
        <el-descriptions-item :label="$t('init.pppPlugin')">{{ p.ppp_plugin || $t('init.notFound') }}</el-descriptions-item>
        <el-descriptions-item label="NetworkManager">{{ p.network_manager ? $t('init.running') : $t('init.stopped') }}</el-descriptions-item>
        <el-descriptions-item :label="$t('init.packages')" :span="isMobile ? 1 : 2">
          <el-tag v-for="(ok, name) in p.packages" :key="name" :type="ok ? 'success' : 'danger'" size="small" class="tag">{{ name }}</el-tag>
        </el-descriptions-item>
      </el-descriptions>
      <el-table :data="p.nics" size="small" class="mt">
        <el-table-column prop="name" :label="$t('init.nic')" min-width="90" />
        <el-table-column prop="mac" label="MAC" min-width="150" class-name="mono nowrap" />
        <el-table-column :label="$t('init.cable')" min-width="80"><template #default="{ row }"><el-tag :type="row.carrier ? 'success' : 'info'" size="small">{{ row.carrier ? $t('init.plugged') : $t('init.unplugged') }}</el-tag></template></el-table-column>
        <el-table-column prop="speed" :label="$t('init.speed')" min-width="100" />
      </el-table>
    </el-card>

    <el-card shadow="never" :header="$t('init.plan')" class="mb">
      <el-alert v-if="det && (det.wan || det.lan || fwds.length)" type="info" show-icon :closable="false" class="mb">
        <template #title>{{ $t('init.prefilled') }}</template>
        <p v-if="det.wan">{{ $t('init.detWan', { user: det.wan.user, nic: det.wan.if, src: det.wan.source }) }}{{ det.wan.password ? $t('init.pwdRead') : $t('init.pwdMissing') }}</p>
        <p v-if="det.lan">{{ $t('init.detLan', { nic: det.lan.if, addr: det.lan.address, src: det.lan.source }) }}</p>
        <p v-if="fwds.length">{{ $t('init.detFwd', { n: fwds.length }) }}<router-link to="/firewall">{{ $t('init.detFwdLink') }}</router-link>{{ $t('init.detFwdEnd') }}</p>
      </el-alert>
      <el-table v-if="fwds.length" :data="fwds" size="small" class="mb">
        <el-table-column prop="proto" :label="$t('common.proto')" width="80" />
        <el-table-column prop="ext" :label="$t('init.extPort')" min-width="110" />
        <el-table-column :label="$t('init.intAddr')" min-width="180"><template #default="{ row }"><span class="mono">{{ row.ip }}:{{ row.int }}</span></template></el-table-column>
        <el-table-column :label="$t('common.enabled')" width="70"><template #default="{ row }">{{ row.enabled ? $t('common.yes') : $t('common.no') }}</template></el-table-column>
      </el-table>
      <el-form :model="f" label-width="120px" class="form-wide">
        <el-divider content-position="left">WAN</el-divider>
        <el-form-item :label="$t('init.wanType')">
          <el-radio-group v-model="f.wan.type">
            <el-radio-button value="pppoe">{{ $t('init.pppoe') }}</el-radio-button>
            <el-radio-button value="dhcp">{{ $t('init.dhcpWan') }}</el-radio-button>
            <el-radio-button value="static">{{ $t('init.staticWan') }}</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item :label="$t('init.wanNic')"><nic-select v-model="f.wan.if" :nics="p.nics" /></el-form-item>
        <template v-if="f.wan.type === 'pppoe'">
          <el-form-item :label="$t('init.user')"><el-input v-model="f.wan.user" autocomplete="off" /></el-form-item>
          <el-form-item :label="$t('init.password')"><el-input v-model="f.wan.password" type="password" show-password autocomplete="new-password" /></el-form-item>
          <el-form-item label="MTU"><el-input-number v-model="f.wan.mtu" :min="576" :max="1500" /></el-form-item>
        </template>
        <template v-if="f.wan.type === 'static'">
          <el-form-item :label="$t('init.wanAddr')"><el-input v-model="f.wan.address" placeholder="203.0.113.2/24" /></el-form-item>
          <el-form-item :label="$t('common.gateway')"><el-input v-model="f.wan.gateway" placeholder="203.0.113.1" /></el-form-item>
        </template>

        <el-divider content-position="left">LAN</el-divider>
        <el-form-item :label="$t('init.lanNic')"><nic-select v-model="f.lan.if" :nics="p.nics" /></el-form-item>
        <el-form-item :label="$t('init.lanAddr')"><el-input v-model="f.lan.address" placeholder="192.168.50.1/24" /></el-form-item>
        <el-form-item :label="$t('init.dhcpSrv')"><el-switch v-model="f.dhcp.enabled" /></el-form-item>
        <template v-if="f.dhcp.enabled">
          <el-form-item :label="$t('init.pool')">
            <el-input v-model="f.dhcp.start" class="w-sm" :aria-label="$t('init.poolStart')" /> <span class="range-sep">{{ $t('init.to') }}</span>
            <el-input v-model="f.dhcp.end" class="w-sm" :aria-label="$t('init.poolEnd')" />
          </el-form-item>
          <el-form-item :label="$t('init.lease')"><el-input v-model="f.dhcp.lease" class="w-sm" placeholder="12h" /></el-form-item>
        </template>
        <el-form-item :label="$t('init.upstream')"><el-input v-model="dnsText" placeholder="223.5.5.5, 119.29.29.29" /></el-form-item>
        <el-form-item label="IPv6"><el-switch v-model="f.ipv6.enabled" /></el-form-item>
        <el-form-item :label="$t('init.sshPort')"><el-input-number v-model="f.ssh_port" :min="1" :max="65535" /></el-form-item>
      </el-form>
    </el-card>

    <el-card shadow="never" class="mb">
      <template #header><b>{{ $t('init.tuning') }}</b><span class="opt-sub ml-xs">{{ $t('init.tuningTip') }}</span></template>
      <div v-for="g in tuningGroups" :key="g.name" class="opt-group">
        <div class="opt-group-title">{{ g.name }}</div>
        <div class="opt-grid">
          <el-checkbox v-for="o in g.items" :key="o.key" class="opt-item" :class="{ locked: o.mandatory }"
            :model-value="o.mandatory || !!f.tuning[o.key]" :disabled="o.mandatory"
            @change="(v) => { f.tuning[o.key] = v }">
            <span class="opt-body">
              <span class="opt-label"><span v-if="o.mandatory" class="opt-badge">{{ $t('init.required') }}</span>{{ o.label }}</span>
              <span class="opt-desc">{{ o.desc }}</span>
              <span class="opt-desc mono">{{ o.sysctl.join('  ') }}</span>
            </span>
          </el-checkbox>
        </div>
      </div>
    </el-card>

    <div class="toolbar">
      <span class="spacer" />
      <el-button @click="load">{{ $t('init.reprobe') }}</el-button>
      <el-button type="primary" :loading="busy" @click="preview">{{ $t('init.previewCheck') }}</el-button>
      <el-button type="danger" :loading="busy" :disabled="!!status.pending || d.dry_run" @click="apply">{{ $t('init.applyRb') }}</el-button>
    </div>

    <el-dialog v-model="pv.show" :title="$t('init.pvTitle')" class="sr-dialog">
      <el-alert v-for="(m, i) in pv.blockers" :key="'b' + i" type="error" :title="m" show-icon :closable="false" class="mb" />
      <el-alert v-for="(m, i) in pv.warnings" :key="'w' + i" type="warning" :title="m" show-icon :closable="false" class="mb" />
      <el-alert v-if="!pv.blockers?.length" type="success" :title="$t('init.noBlockers')" show-icon :closable="false" class="mb" />
      <el-tabs>
        <el-tab-pane v-for="x in pv.files" :key="x.path" :label="x.path.split('/').pop()">
          <div class="mono mb-xs">{{ x.path }}{{ $t('init.mode', { m: x.mode }) }}</div>
          <pre class="pre mono">{{ x.content }}</pre>
        </el-tab-pane>
        <el-tab-pane :label="$t('init.fwV4')"><pre class="pre mono">{{ pv.v4 }}</pre></el-tab-pane>
        <el-tab-pane :label="$t('init.steps')"><pre class="pre mono">{{ (pv.post || []).map((c) => c.join(' ')).join('\n') }}</pre></el-tab-pane>
      </el-tabs>
      <template #footer>
        <el-button @click="pv.show = false">{{ $t('common.close') }}</el-button>
        <el-button type="danger" :loading="busy" :disabled="!!pv.blockers?.length || !!status.pending || d.dry_run"
          @click="pv.show = false; apply()">{{ $t('init.applyRb') }}</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { computed, h, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox, ElOption, ElSelect } from 'element-plus'
import { api } from '../api'
import { t } from '../i18n'
import { refreshStatus, status } from '../status'
import { isMobile } from '../viewport'

// NIC picker: probed names + free text (a NIC may be renamed or not plugged yet)
const NicSelect = (props, { emit }) => h(ElSelect, {
  modelValue: props.modelValue, filterable: true, allowCreate: true, class: 'w-md',
  'onUpdate:modelValue': (v) => emit('update:modelValue', v),
}, () => (props.nics || []).map((n) => h(ElOption, { key: n.name, value: n.name, label: `${n.name}${n.carrier ? t('init.nicPlugged') : ''}` })))
NicSelect.props = ['modelValue', 'nics']
NicSelect.emits = ['update:modelValue']

const d = ref({})
const p = computed(() => d.value.probe || {})
const st = computed(() => d.value.state || {})
const pend = computed(() => (status.pending?.kind === 'init' ? status.pending : null))
const busy = ref(false)
const pv = reactive({ show: false })
const f = reactive({
  wan: { type: 'pppoe', if: '', user: '', password: '', mtu: 1492, address: '', gateway: '' },
  lan: { if: '', address: '192.168.50.1/24' },
  dhcp: { enabled: true, start: '192.168.50.100', end: '192.168.50.200', lease: '12h' },
  ipv6: { enabled: true }, ssh_port: 22, tuning: {},
})
const dnsText = ref('223.5.5.5, 119.29.29.29')
// hand-built router (never initialised here): what it already runs, used once to pre-fill the plan
const prefilled = ref(false)
const det = computed(() => (st.value.initialized ? null : p.value.detected))
const fwds = computed(() => d.value.forwards || [])
const plan = () => ({ ...f, dns: { upstream: dnsText.value.split(/[\s,，]+/).filter(Boolean) } })

// tuning catalogue comes from the agent (bootstrap.TUNING) - single source of truth for keys/labels
const tuningGroups = computed(() => {
  const out = []
  for (const o of d.value.tuning || []) {
    let g = out.find((x) => x.name === o.group)
    if (!g) out.push((g = { name: o.group, items: [] }))
    g.items.push(o)
  }
  return out
})

async function load() {
  d.value = await api.get('/api/init')
  const done = d.value.state?.initialized?.plan
  const opt = (d.value.tuning || []).filter((o) => !o.mandatory)
  // fresh machine: recommended defaults; confirmed plan: exactly what was applied (old plans: none)
  // only on first load: "重新探测" must not reset what the user just ticked
  if (!Object.keys(f.tuning).length) {
    f.tuning = Object.fromEntries(opt.map((o) => [o.key, done ? !!done.tuning?.[o.key] : !!o.default]))
  }
  const found = d.value.probe?.detected
  if (!done && found && !prefilled.value) {
    prefilled.value = true
    if (found.wan) Object.assign(f.wan, { type: found.wan.type, if: found.wan.if, user: found.wan.user, mtu: found.wan.mtu,
      password: found.wan.password || '' })
    if (found.lan) Object.assign(f.lan, { if: found.lan.if, address: found.lan.address })
  }
  if (done) { // pre-fill from the confirmed plan (password is never returned)
    Object.assign(f.wan, done.wan, { password: '' })
    Object.assign(f.lan, { if: done.lan.if, address: done.lan.address })
    Object.assign(f.dhcp, done.dhcp)
    Object.assign(f.ipv6, done.ipv6)
    f.ssh_port = done.ssh_port
    dnsText.value = done.dns.upstream.join(', ')
  }
}

async function run(fn) {
  busy.value = true
  try { return await fn() } catch { /* message already shown / cancelled */ } finally { busy.value = false }
}

const preview = () => run(async () => {
  Object.assign(pv, await api.post('/api/init/preview', { plan: plan() }), { show: true })
})

const apply = () => run(async () => {
  await ElMessageBox.confirm(
    t('init.applyMsg', { addr: f.lan.address }),
    t('init.applyTitle'), { type: 'warning', confirmButtonText: t('common.apply') })
  let r = await api.post('/api/init/apply', { plan: plan() })
  if (!r.applied && r.warnings?.length) {
    await ElMessageBox.confirm(r.warnings.join('\n\n'), t('init.warnTitle'), { type: 'warning' })
    r = await api.post('/api/init/apply', { plan: plan(), force: true })
  }
  await refreshStatus(api)
  ElMessage.warning(t('init.applied'))
  await load()
})

const act = (path, msg) => run(async () => {
  const r = await api.post(path)
  if (r?.restart && r.listen) {
    // agent rebinds on the new LAN IP a moment after replying: follow it there
    const url = `${location.protocol}//${r.listen}:${location.port || 8090}/`
    const tunneled = ['127.0.0.1', 'localhost'].includes(location.hostname)
    ElMessage.success({ message: tunneled
      ? t('init.tunneled', { msg, ip: r.listen, port: location.port || 8090 })
      : t('init.redirect', { msg, url }), duration: 10000 })
    if (!tunneled) setTimeout(() => { location.href = url }, 3000)
    return
  }
  if (r?.listen && r.restart === false && r.listen !== location.hostname) {
    ElMessage.warning({ message: t('init.afterRestart', { msg, ip: r.listen }), duration: 8000 })
  }
  await refreshStatus(api)
  ElMessage.success(msg)
  await load()
})

onMounted(load)
</script>

<style scoped>
.tag { margin: 2px 4px 2px 0; }
</style>
