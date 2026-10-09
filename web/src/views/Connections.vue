<template>
  <div>
    <h3 class="page-title">{{ $t('menu.connections') }}</h3>
    <div class="toolbar">
      <el-input v-model="kw" :placeholder="$t('connections.filterPh')" clearable class="w-md" :aria-label="$t('common.filter')" />
      <el-select v-model="proto" clearable :placeholder="$t('common.proto')" class="w-xs" :aria-label="$t('common.proto')">
        <el-option v-for="p in ['tcp', 'udp', 'icmp']" :key="p" :label="p" :value="p" />
      </el-select>
      <span class="spacer" />
      <span class="stat-label m0">{{ $t('connections.showTop', { n: limit }) }}</span>
      <el-button icon="Refresh" :loading="loading" @click="load">{{ $t('common.refresh') }}</el-button>
    </div>
    <el-row :gutter="16">
      <el-col :md="17">
        <el-table :data="rows" size="small" stripe max-height="70vh" v-loading="loading">
          <el-table-column prop="proto" :label="$t('common.proto')" width="70" />
          <el-table-column prop="state" :label="$t('common.status')" width="120" />
          <el-table-column :label="$t('connections.src')"><template #default="{ row }"><span class="mono">{{ row.src }}:{{ row.sport }}</span></template></el-table-column>
          <el-table-column :label="$t('common.target')"><template #default="{ row }"><span class="mono">{{ row.dst }}:{{ row.dport }}</span></template></el-table-column>
        </el-table>
      </el-col>
      <el-col :md="7">
        <el-card shadow="never" :header="$t('connections.top')">
          <div v-for="t in data.top_sources" :key="t.ip" class="mb">
            <div class="toolbar m0"><span class="mono">{{ t.ip }}</span><span class="spacer" />{{ t.count }}</div>
            <el-progress :percentage="Math.round((100 * t.count) / (data.top_sources[0]?.count || 1))" :show-text="false" />
          </div>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { api } from '../api'

const limit = 1000
const data = ref({ items: [], top_sources: [] })
const kw = ref('')
const proto = ref('')
const loading = ref(false)

const rows = computed(() => {
  const k = kw.value.trim()
  return data.value.items.filter((c) => (!proto.value || c.proto === proto.value) &&
    (!k || [c.src, c.dst, c.sport, c.dport].some((v) => String(v).includes(k))))
})

async function load() {
  loading.value = true
  try { data.value = await api.get('/api/connections', { limit }) } finally { loading.value = false }
}
onMounted(load)
</script>
