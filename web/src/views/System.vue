<template>
  <div>
    <h3 class="page-title">{{ $t('menu.system') }}</h3>
    <el-card shadow="never" :header="$t('system.services')" class="mb">
      <el-space wrap>
        <el-tag v-for="s in services" :key="s.name" :type="s.state === 'active' ? 'success' : s.state === 'inactive' ? 'info' : 'danger'" size="large">
          {{ s.name }}：{{ s.state }}
        </el-tag>
      </el-space>
    </el-card>
    <el-card shadow="never">
      <div class="toolbar">
        <el-radio-group v-model="unit" @change="loadLogs">
          <el-radio-button v-for="u in units" :key="u.value" :value="u.value">{{ u.label }}</el-radio-button>
        </el-radio-group>
        <el-input-number v-model="lines" :min="50" :max="2000" :step="50" :aria-label="$t('system.lines')" />
        <el-input v-model="kw" :placeholder="$t('system.kwPh')" clearable class="w-md" :aria-label="$t('common.filter')" />
        <span class="spacer" />
        <el-checkbox v-model="auto">{{ $t('system.auto') }}</el-checkbox>
        <el-button icon="Refresh" :loading="loading" @click="loadLogs">{{ $t('common.refresh') }}</el-button>
      </div>
      <pre class="pre mono tall">{{ shown }}</pre>
    </el-card>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { api } from '../api'
import { t } from '../i18n'

const units = computed(() => [
  { value: 'dnsmasq', label: 'DNS/DHCP' }, { value: 'pppd', label: 'PPPoE' }, { value: 'kernel', label: t('system.kernel') },
  { value: 'ssh', label: 'SSH' }, { value: 'agent', label: 'Agent' },
])
const services = ref([])
const unit = ref('dnsmasq')
const lines = ref(200)
const kw = ref('')
const log = ref([])
const loading = ref(false)
const auto = ref(false)
let timer = null

const shown = computed(() => {
  const k = kw.value.trim().toLowerCase()
  return (k ? log.value.filter((l) => l.toLowerCase().includes(k)) : log.value).join('\n') || t('common.noLog')
})

async function loadLogs() {
  loading.value = true
  try { log.value = (await api.get('/api/logs', { unit: unit.value, lines: lines.value })).lines } finally { loading.value = false }
}

watch(auto, (v) => {
  clearInterval(timer)
  timer = v ? setInterval(loadLogs, 5000) : null
})
onMounted(async () => {
  loadLogs()
  services.value = await api.get('/api/services')
})
onBeforeUnmount(() => clearInterval(timer))
</script>
