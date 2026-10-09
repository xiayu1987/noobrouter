<template>
  <div>
    <h3 class="page-title">{{ $t('menu.interfaces') }}</h3>
    <el-card shadow="never" class="mb">
      <el-table v-loading="loading" :data="data.interfaces" size="small">
        <el-table-column prop="name" :label="$t('common.iface')" width="110" />
        <el-table-column :label="$t('common.status')" width="90">
          <template #default="{ row }"><el-tag size="small" :type="tagType(row.state)">{{ row.state }}</el-tag></template>
        </el-table-column>
        <el-table-column :label="$t('interfaces.addrs')"><template #default="{ row }"><div v-for="a in row.addrs" :key="a" class="mono">{{ a }}</div></template></el-table-column>
        <el-table-column prop="mac" label="MAC" width="160"><template #default="{ row }"><span class="mono">{{ row.mac }}</span></template></el-table-column>
        <el-table-column prop="mtu" label="MTU" width="70" />
        <el-table-column :label="$t('interfaces.rxtx')" width="170"><template #default="{ row }">{{ fmtBytes(row.rx_bytes) }} / {{ fmtBytes(row.tx_bytes) }}</template></el-table-column>
        <el-table-column :label="$t('interfaces.rxDrop')" width="100">
          <template #default="{ row }"><span :style="{ color: row.rx_drop > 1000 ? 'var(--el-color-warning)' : '' }">{{ row.rx_drop }}</span></template>
        </el-table-column>
      </el-table>
    </el-card>
    <el-card shadow="never" :header="$t('interfaces.routes')">
      <el-tabs>
        <el-tab-pane label="IPv4"><route-table :rows="data.routes?.v4" /></el-tab-pane>
        <el-tab-pane label="IPv6"><route-table :rows="data.routes?.v6" /></el-tab-pane>
      </el-tabs>
    </el-card>
  </div>
</template>

<script setup>
import { h, onMounted, ref } from 'vue'
import { ElTable, ElTableColumn } from 'element-plus'
import { api, fmtBytes } from '../api'
import { t } from '../i18n'

const data = ref({ interfaces: [], routes: {} })
const loading = ref(false)
const tagType = (s) => (s === 'UP' ? 'success' : s === 'UNKNOWN' ? 'warning' : 'info')

const RouteTable = (props) => h(ElTable, { data: props.rows || [], size: 'small' }, () => [
  h(ElTableColumn, { prop: 'dst', label: t('common.target') }),
  h(ElTableColumn, { prop: 'gateway', label: t('common.gateway') }),
  h(ElTableColumn, { prop: 'dev', label: t('common.iface') }),
  h(ElTableColumn, { prop: 'protocol', label: t('common.source') }),
  h(ElTableColumn, { prop: 'metric', label: 'Metric' }),
])
RouteTable.props = ['rows']

onMounted(async () => {
  loading.value = true
  try { data.value = await api.get('/api/interfaces') } finally { loading.value = false }
})
</script>
