<template>
  <div>
    <h3 class="page-title">{{ $t('menu.firewall') }}</h3>

    <el-alert v-if="pend" type="error" :closable="false" show-icon class="mb">
      <template #title>{{ $t('fw.pendTitle', { n: pend.remaining, s: pend.summary || pend.txid }) }}</template>
      <p>{{ $t('fw.pendTip') }}</p>
      <el-button type="success" :loading="busy" @click="act('/api/firewall/confirm', $t('fw.confirmed'))">{{ $t('fw.keep') }}</el-button>
      <el-button type="danger" :loading="busy" @click="act('/api/firewall/rollback', $t('fw.rolledBack'))">{{ $t('fw.rollbackNow') }}</el-button>
    </el-alert>
    <el-alert v-else-if="status.pending" type="warning" :closable="false" show-icon class="mb">
      <template #title>{{ $t('fw.initPending') }}<router-link to="/init">{{ $t('fw.goInit') }}</router-link></template>
    </el-alert>

    <el-alert v-if="d.last_rollback" type="info" show-icon class="mb"
      :title="$t('fw.lastRollback', { tx: d.last_rollback.txid, reason: d.last_rollback.reason, at: new Date(d.last_rollback.at * 1000).toLocaleString() })" />

    <el-alert v-if="d.import && !d.import.acknowledged" type="error" :closable="false" show-icon class="mb">
      <template #title>{{ $t('fw.importTitle', { n: d.import.skipped.length }) }}</template>
      <pre class="pre mt">{{ d.import.skipped.join('\n') }}</pre>
      <el-button type="warning" @click="ackImport">{{ $t('fw.ackBtn') }}</el-button>
    </el-alert>

    <el-collapse v-if="d.lint?.length" class="mb">
      <el-collapse-item :title="$t('fw.lint', { n: d.lint.length })">
        <el-alert v-for="(x, i) in d.lint" :key="i" :type="x.level" :title="x.msg" show-icon :closable="false" class="mb" />
      </el-collapse-item>
    </el-collapse>

    <el-card shadow="never" class="mb">
      <template #header>
        <div class="toolbar m0">
          <b>{{ $t('fw.forwards') }}</b><span class="opt-sub ml-xs">{{ $t('fw.count', { n: m.forwards.length }) }}</span><span class="spacer" />
          <el-button size="small" icon="Plus" @click="editFwd(-1)">{{ $t('common.add') }}</el-button>
        </div>
      </template>
      <el-table :data="m.forwards" size="small" :empty-text="$t('fw.noForwards')">
        <el-table-column :label="$t('common.enabled')" width="70">
          <template #default="{ row }"><el-switch v-model="row.enabled" size="small" :aria-label="$t('fw.enableX', { x: fwdName(row) })" @change="dirty = true" /></template>
        </el-table-column>
        <el-table-column :label="$t('common.name')">
          <template #default="{ row }"><span v-if="row.name">{{ row.name }}</span><span v-else class="opt-sub">{{ $t('common.unnamed') }}</span></template>
        </el-table-column>
        <el-table-column prop="proto" :label="$t('common.proto')" width="80" />
        <el-table-column prop="ext" :label="$t('fw.ext')" width="110" />
        <el-table-column :label="$t('fw.internal')"><template #default="{ row }"><span class="mono">{{ row.ip }}:{{ row.int }}</span></template></el-table-column>
        <el-table-column :label="$t('common.action')" width="120">
          <template #default="{ $index }">
            <el-button link type="primary" @click="editFwd($index)">{{ $t('common.edit') }}</el-button>
            <el-button link type="danger" @click="remove('forwards', $index)">{{ $t('common.delete') }}</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card shadow="never" class="mb">
      <template #header>
        <div class="toolbar m0">
          <b>{{ $t('fw.open') }}</b><span class="spacer" />
          <el-button size="small" icon="Plus" @click="editOpen(-1)">{{ $t('common.add') }}</el-button>
        </div>
      </template>
      <el-table :data="m.wan_open" size="small" :empty-text="$t('fw.noOpen')">
        <el-table-column prop="proto" :label="$t('common.proto')" width="100" />
        <el-table-column prop="port" :label="$t('fw.port')" width="140" />
        <el-table-column :label="$t('fw.scope')" min-width="160">
          <template #default="{ row }"><span class="mono">{{ scopeOf(row) }}</span></template>
        </el-table-column>
        <el-table-column prop="comment" :label="$t('common.remark')" />
        <el-table-column :label="$t('common.action')" width="120">
          <template #default="{ $index }">
            <el-button link type="primary" @click="editOpen($index)">{{ $t('common.edit') }}</el-button>
            <el-button link type="danger" @click="remove('wan_open', $index)">{{ $t('common.delete') }}</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-card shadow="never" class="mb">
      <template #header><b>{{ $t('fw.options') }}</b><span class="opt-sub ml-xs">{{ $t('fw.optionsTip') }}</span></template>
      <div v-for="g in groups" :key="g.name" class="opt-group">
        <div class="opt-group-title">{{ g.name }}</div>
        <div class="opt-grid">
          <el-checkbox v-for="o in g.items" :key="o.key" class="opt-item" :class="{ locked: o.mandatory }"
            :model-value="o.mandatory || !!m[o.key]" :disabled="o.mandatory" @change="(v) => setOpt(o.key, v)">
            <span class="opt-body">
              <span class="opt-label"><span v-if="o.mandatory" class="opt-badge">{{ $t('fw.mandatory') }}</span><span class="opt-label-text">{{ splitNote(o.label)[0] }}<span v-if="splitNote(o.label)[1]" class="nowrap">{{ splitNote(o.label)[1] }}</span></span></span>
              <span class="opt-desc">{{ splitNote(descOf(o))[0] }}<span v-if="splitNote(descOf(o))[1]" class="nowrap">{{ splitNote(descOf(o))[1] }}</span></span>
            </span>
          </el-checkbox>
        </div>
      </div>
      <div v-if="d.unsupported?.length" class="opt-group">
        <div class="opt-group-title">{{ $t('fw.unsupported') }}</div>
        <div class="opt-grid">
          <el-checkbox v-for="o in d.unsupported" :key="o.key" class="opt-item unsupported"
            :model-value="false" disabled>
            <span class="opt-body">
              <span class="opt-label"><span class="opt-badge muted-badge">{{ $t('fw.unsupported') }}</span>{{ o.label }}</span>
              <span class="opt-desc">{{ o.desc }}</span>
            </span>
          </el-checkbox>
        </div>
      </div>
    </el-card>

    <div class="toolbar action-bar">
      <el-tag v-if="dirty" type="warning">{{ $t('fw.dirty') }}</el-tag>
      <span class="spacer" />
      <el-button @click="load">{{ $t('dhcp.discard') }}</el-button>
      <el-button :loading="busy" @click="save">{{ $t('fw.saveOnly') }}</el-button>
      <el-button type="primary" :loading="busy" @click="preview">{{ $t('fw.previewCheck') }}</el-button>
      <el-button type="danger" :loading="busy" :disabled="!!status.pending" @click="apply">{{ $t('fw.applyRb') }}</el-button>
    </div>

    <el-dialog v-model="pv.show" :title="$t('fw.pvTitle')" class="sr-dialog">
      <el-tabs>
        <el-tab-pane :label="$t('fw.pvV4')"><pre class="pre mono">{{ pv.v4 }}</pre></el-tab-pane>
        <el-tab-pane :label="$t('fw.pvV6')"><pre class="pre mono">{{ pv.v6 }}</pre></el-tab-pane>
        <el-tab-pane :label="$t('fw.pvLive')"><pre class="pre mono">{{ pv.live_v4 }}</pre></el-tab-pane>
      </el-tabs>
    </el-dialog>

    <rule-dialog v-model="dlg" @done="onDialogDone" />
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api'
import { refreshStatus, status } from '../status'
import { t } from '../i18n'
import RuleDialog from '../components/RuleDialog.vue'

const d = ref({})
const m = ref({ forwards: [], wan_open: [] })
const dirty = ref(false)
const busy = ref(false)
const pv = reactive({ show: false, v4: '', v6: '', live_v4: '' })
const dlg = ref(null) // {kind, index, row}
const pend = computed(() => ((status.pending?.kind || 'firewall') === 'firewall' ? status.pending : null))

// option catalogue comes from the agent (firewall.OPTIONS) - single source of truth for keys/labels
const groups = computed(() => {
  const out = []
  for (const o of d.value.options || []) {
    let g = out.find((x) => x.name === o.group)
    if (!g) out.push((g = { name: o.group, items: [] }))
    g.items.push(o)
  }
  return out
})
function setOpt(key, v) {
  m.value[key] = !!v
  dirty.value = true
}
// keep a short trailing parenthetical (full- or half-width) on one line so it never leaves an orphan word;
// long ones (English notes) wrap normally, otherwise nowrap overflows the card
const splitNote = (s) => {
  const m2 = /\s?[（(][^（()）]*[）)]$/.exec(s)
  return m2 && m2.index > 0 && m2[0].length <= 16 ? [s.slice(0, m2.index), s.slice(m2.index)] : [s, '']
}
const descOf = (o) => {
  const g = d.value.guard
  if (o.key !== 'guard_rules' || !g) return o.desc
  const lan = m.value.lan_accept_all ? t('fw.guardLanAll', { lan: g.lan_if })
    : t('fw.guardLan', { lan: g.lan_if, ssh: g.ssh_port, console: g.console_port })
  return t('fw.guardDesc', { desc: o.desc, lan, wan: m.value.ssh_wan ? t('fw.guardWan', { ssh: g.ssh_port }) : '' })
}
const scopeOf = (r) => [r.iface ? t('fw.scopeIf', { x: r.iface }) : '', r.src ? t('fw.scopeSrc', { x: r.src }) : '']
  .filter(Boolean).join(t('fw.scopeSep')) || t('fw.scopeAll')
const fwdName = (r) => `${r.proto}/${r.ext} → ${r.ip}:${r.int}`

async function load() {
  // clone the plain response, not d.value (a reactive Proxy -> structuredClone throws DataCloneError)
  const r = await api.get('/api/firewall')
  d.value = r
  m.value = structuredClone(r.model)
  dirty.value = false
}

const blank = { forwards: { name: '', proto: 'tcp', ext: '', ip: '', int: '', enabled: true }, wan_open: { proto: 'tcp', port: '', comment: '', iface: '', src: '' } }
const editFwd = (i) => (dlg.value = { kind: 'forwards', index: i, row: { ...(i < 0 ? blank.forwards : m.value.forwards[i]) } })
const editOpen = (i) => (dlg.value = { kind: 'wan_open', index: i, row: { ...(i < 0 ? blank.wan_open : m.value.wan_open[i]) } })
function onDialogDone({ kind, index, row }) {
  index < 0 ? m.value[kind].push(row) : (m.value[kind][index] = row)
  dirty.value = true
}
function remove(kind, i) {
  m.value[kind].splice(i, 1)
  dirty.value = true
}

// 409 "will wipe all forwards" -> ask once, then retry with allow_empty
async function withEmptyGuard(fn) {
  try {
    return await fn({})
  } catch (e) {
    if (e.status !== 409 || e.data?.code !== 'allow_empty') throw e
    await ElMessageBox.confirm(e.message, t('dhcp.confirmEmpty'), { type: 'warning' })
    return fn({ allow_empty: true })
  }
}

async function run(fn) {
  busy.value = true
  try { return await fn() } catch { /* message already shown */ } finally { busy.value = false }
}

const save = () => run(async () => {
  await withEmptyGuard((x) => api.post('/api/firewall/save', { model: m.value, ...x }))
  ElMessage.success(t('fw.saved'))
  await load()
})

const preview = () => run(async () => {
  Object.assign(pv, await withEmptyGuard((x) => api.post('/api/firewall/preview', { model: m.value, ...x })), { show: true })
})

const apply = () => run(async () => {
  await ElMessageBox.confirm(
    t('fw.applyMsg', { n: d.value.guard?.rollback_seconds }),
    t('fw.applyTitle'), { type: 'warning', confirmButtonText: t('common.apply') })
  const summary = t('fw.summary', { f: m.value.forwards.length, o: m.value.wan_open.length })
  await withEmptyGuard((x) => api.post('/api/firewall/apply', { model: m.value, summary, ...x }))
  await refreshStatus(api)
  ElMessage.warning(t('fw.appliedWait'))
  await load()
})

const act = (path, msg) => run(async () => {
  await api.post(path)
  await refreshStatus(api)
  ElMessage.success(msg)
  await load()
})

const ackImport = () => run(async () => {
  await ElMessageBox.confirm(t('fw.ackMsg'), t('common.confirm'), { type: 'warning' })
  await api.post('/api/firewall/ack-import')
  await load()
})

onMounted(load)
</script>
