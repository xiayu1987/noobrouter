<template>
  <div>
    <h3 class="page-title">{{ $t('menu.devices') }}</h3>
    <div class="toolbar">
      <el-input v-model="kw" :placeholder="$t('devices.searchPh')" clearable class="w-lg" :aria-label="$t('common.search')" />
      <el-checkbox v-model="onlineOnly">{{ $t('devices.onlineOnly') }}</el-checkbox>
      <span class="spacer" />
      <el-button icon="Refresh" @click="load">{{ $t('common.refresh') }}</el-button>
    </div>
    <el-table v-loading="loading" :data="rows" size="small" stripe>
      <el-table-column :label="$t('common.status')" width="80">
        <template #default="{ row }"><el-tag size="small" :type="row.online ? 'success' : 'info'">{{ row.online ? $t('common.online') : $t('common.offline') }}</el-tag></template>
      </el-table-column>
      <el-table-column prop="ip" label="IP" width="150" sortable />
      <el-table-column prop="mac" label="MAC" width="170"><template #default="{ row }"><span class="mono">{{ row.mac }}</span></template></el-table-column>
      <el-table-column prop="hostname" :label="$t('common.hostname')" />
      <el-table-column :label="$t('devices.type')" width="110">
        <template #default="{ row }"><el-tag v-if="row.static" size="small">{{ $t('devices.static') }}</el-tag><span v-else>{{ $t('devices.dynamic') }}</span></template>
      </el-table-column>
      <el-table-column :label="$t('devices.leaseLeft')" width="120">
        <template #default="{ row }">{{ row.lease_left == null ? '-' : fmtUptime(row.lease_left) }}</template>
      </el-table-column>
      <el-table-column :label="$t('common.action')" width="110">
        <template #default="{ row }">
          <el-button v-if="!row.static" link type="primary" @click="bind(row)">{{ $t('devices.bind') }}</el-button>
        </template>
      </el-table-column>
    </el-table>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { api, fmtUptime } from '../api'

const router = useRouter()
const list = ref([])
const kw = ref('')
const onlineOnly = ref(false)
const loading = ref(false)

const rows = computed(() => {
  const k = kw.value.trim().toLowerCase()
  return list.value.filter((d) => (!onlineOnly.value || d.online) &&
    (!k || [d.ip, d.mac, d.hostname].some((v) => (v || '').toLowerCase().includes(k))))
})

async function load() {
  loading.value = true
  try { list.value = await api.get('/api/devices') } finally { loading.value = false }
}

function bind(row) {
  router.push({ name: 'dhcp', query: { mac: row.mac, ip: row.ip, name: row.hostname } })
}

onMounted(load)
</script>
