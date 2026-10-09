<template>
  <div>
    <h3 class="page-title">DHCP / DNS</h3>
    <el-alert type="info" :closable="false" class="mb" :title="$t('dhcp.intro')" />

    <el-row :gutter="16">
      <el-col :md="14">
        <el-card shadow="never" class="mb">
          <template #header>
            <div class="toolbar m0"><b>{{ $t('dhcp.static') }}</b><span class="spacer" />
              <el-button size="small" icon="Plus" @click="m.static.push({ mac: '', ip: '', name: '' })">{{ $t('common.add') }}</el-button></div>
          </template>
          <el-table :data="m.static" size="small">
            <el-table-column label="MAC"><template #default="{ row }"><el-input v-model="row.mac" size="small" placeholder="aa:bb:cc:dd:ee:ff" aria-label="MAC" /></template></el-table-column>
            <el-table-column label="IP" width="150"><template #default="{ row }"><el-input v-model="row.ip" size="small" aria-label="IP" /></template></el-table-column>
            <el-table-column :label="$t('common.hostname')" width="140"><template #default="{ row }"><el-input v-model="row.name" size="small" :aria-label="$t('common.hostname')" /></template></el-table-column>
            <el-table-column width="60"><template #default="{ $index }"><el-button link type="danger" icon="Delete" :aria-label="$t('common.delete')" @click="m.static.splice($index, 1)" /></template></el-table-column>
          </el-table>
        </el-card>

        <el-card shadow="never" class="mb">
          <template #header>
            <div class="toolbar m0"><b>{{ $t('dhcp.hosts') }}</b><span class="spacer" />
              <el-button size="small" icon="Plus" @click="m.records.push({ domain: '', ip: '' })">{{ $t('common.add') }}</el-button></div>
          </template>
          <el-table :data="m.records" size="small">
            <el-table-column :label="$t('dhcp.domain')"><template #default="{ row }"><el-input v-model="row.domain" size="small" placeholder="nas.lan" :aria-label="$t('dhcp.domain')" /></template></el-table-column>
            <el-table-column label="IP" width="200"><template #default="{ row }"><el-input v-model="row.ip" size="small" aria-label="IP" /></template></el-table-column>
            <el-table-column width="60"><template #default="{ $index }"><el-button link type="danger" icon="Delete" :aria-label="$t('common.delete')" @click="m.records.splice($index, 1)" /></template></el-table-column>
          </el-table>
        </el-card>

        <el-card shadow="never" :header="$t('dhcp.upstream')" class="mb">
          <el-select v-model="m.upstream" multiple filterable allow-create default-first-option class="w-full"
            :placeholder="$t('dhcp.upstreamPh', { cur: mainUpstream })" :aria-label="$t('dhcp.upstream')">
            <el-option v-for="u in presets" :key="u.ip" :label="`${u.ip}  ${u.key ? $t(u.key) : u.name}`" :value="u.ip" />
          </el-select>
          <p class="stat-label mt">{{ $t('dhcp.upstreamTip') }}</p>
        </el-card>

        <div class="toolbar">
          <span class="spacer" />
          <el-button @click="load">{{ $t('dhcp.discard') }}</el-button>
          <el-button :loading="busy" @click="submit({ preview: true })">{{ $t('common.preview') }}</el-button>
          <el-button type="primary" :loading="busy" @click="submit({})">{{ $t('common.apply') }}</el-button>
        </div>
      </el-col>

      <el-col :md="10">
        <el-card shadow="never" :header="$t('dhcp.main')" class="mb">
          <el-empty v-if="!mainHasData" :image-size="48" :description="$t('dhcp.mainEmpty')" />
          <el-descriptions v-else :column="1" border size="small">
            <el-descriptions-item label="interface">{{ (d.main?.interface || []).join(', ') }}</el-descriptions-item>
            <el-descriptions-item label="dhcp-range"><div v-for="x in d.main?.dhcp_range" :key="x" class="mono">{{ x }}</div></el-descriptions-item>
            <el-descriptions-item label="dhcp-option"><div v-for="x in d.main?.dhcp_option" :key="x" class="mono">{{ x }}</div></el-descriptions-item>
          </el-descriptions>
        </el-card>
        <el-card shadow="never" :header="$t('dhcp.rendered')" class="mb"><pre class="pre mono">{{ rendered }}</pre></el-card>
        <el-card shadow="never" :header="$t('dhcp.leases', { n: (d.leases || []).length })">
          <el-table :data="d.leases" size="small" max-height="320">
            <el-table-column prop="ip" label="IP" width="130" />
            <el-table-column prop="mac" label="MAC"><template #default="{ row }"><span class="mono">{{ row.mac }}</span></template></el-table-column>
            <el-table-column prop="hostname" :label="$t('common.hostname')" />
          </el-table>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api'
import { t } from '../i18n'

const route = useRoute()
const d = ref({})
const m = ref({ static: [], records: [], upstream: [] })
const rendered = ref('')
const busy = ref(false)
const presets = [
  { ip: '223.5.5.5', key: 'dhcp.aliyun' }, { ip: '119.29.29.29', key: 'dhcp.dnspod' },
  { ip: '114.114.114.114', name: '114' }, { ip: '1.1.1.1', name: 'Cloudflare' }, { ip: '8.8.8.8', name: 'Google' },
]
// main config: empty state when none of the three shown keys is set (config lives in dnsmasq.d only)
const mainHasData = computed(() => {
  const mm = d.value.main || {}
  return [mm.interface, mm.dhcp_range, mm.dhcp_option].some((v) => (v || []).length)
})
// upstream currently used when the list is empty: server= lines of the main config, else resolv.conf
const mainUpstream = computed(() => {
  const s = (d.value.main?.other || []).filter((l) => l.startsWith('server=')).map((l) => l.slice(7))
  return s.length ? s.join(' / ') : t('dhcp.resolvConf')
})

async function load() {
  // clone the plain response, not d.value (a reactive Proxy -> structuredClone throws DataCloneError)
  const r = await api.get('/api/dhcp')
  d.value = r
  m.value = { static: [], records: [], upstream: [], ...structuredClone(r.model) }
  rendered.value = r.render
  // prefill from the Devices page "make static" button
  const { mac, ip, name } = route.query
  if (mac && !m.value.static.some((s) => s.mac === mac)) {
    m.value.static.push({ mac, ip: ip || '', name: (name || '').replace(/[^A-Za-z0-9-]/g, '') })
    ElMessage.info(t('dhcp.prefilled'))
  }
}

async function submit(extra) {
  busy.value = true
  const body = { model: m.value, ...extra }
  try {
    let r
    try {
      r = await api.post('/api/dhcp/apply', body, { silent: true })
    } catch (e) {
      if (e.status !== 409 || e.data?.code !== 'allow_empty') throw e
      await ElMessageBox.confirm(e.message, t('dhcp.confirmEmpty'), { type: 'warning' })
      body.allow_empty = true
      r = await api.post('/api/dhcp/apply', body)
    }
    if (!r.applied && r.warnings?.length && !body.force) {
      await ElMessageBox.confirm(r.warnings.join('\n'), t('dhcp.conflict'), { type: 'warning' })
      body.force = true
      r = await api.post('/api/dhcp/apply', body)
    }
    if (r.render) rendered.value = r.render
    if (r.applied) {
      ElMessage.success(t('dhcp.applied'))
      await load()
    } else if (r.dry_run) {
      ElMessage.warning(t('dhcp.dryRun'))
    } else {
      ElMessage.info(t('dhcp.previewed'))
    }
  } catch (e) {
    if (e !== 'cancel' && e?.message) ElMessage.error(e.message)
  } finally {
    busy.value = false
  }
}

onMounted(load)
</script>
