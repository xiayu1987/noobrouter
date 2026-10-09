<template>
  <div>
    <h3 class="page-title">{{ $t('menu.diag') }}</h3>
    <el-card shadow="never">
      <el-form inline @submit.prevent="run">
        <el-form-item :label="$t('diag.tool')">
          <el-radio-group v-model="tool">
            <el-radio-button value="ping">Ping</el-radio-button>
            <el-radio-button value="traceroute">Traceroute</el-radio-button>
            <el-radio-button value="nslookup">NSLookup</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item :label="$t('common.target')">
          <el-input v-model="host" :placeholder="$t('diag.hostPh')" class="w-md" :aria-label="$t('common.target')" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" native-type="submit" :loading="loading">{{ $t('diag.run') }}</el-button>
        </el-form-item>
      </el-form>
      <div class="toolbar">
        <span class="stat-label m0">{{ $t('diag.quick') }}</span>
        <el-button v-for="q in quick" :key="q" size="small" @click="host = q">{{ q }}</el-button>
      </div>
      <pre class="pre mono">{{ output || $t('diag.placeholder') }}</pre>
    </el-card>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'
import { t } from '../i18n'

const tool = ref('ping')
const host = ref('223.5.5.5')
const output = ref('')
const loading = ref(false)
const quick = ['223.5.5.5', 'www.baidu.com', '192.168.50.1', '8.8.8.8']
const HOST = /^[A-Za-z0-9.-]{1,253}$/

async function run() {
  if (!HOST.test(host.value) || host.value.startsWith('-')) return ElMessage.error(t('diag.badHost'))
  loading.value = true
  output.value = ''
  try {
    output.value = (await api.post('/api/diag', { tool: tool.value, host: host.value })).output || t('diag.empty')
  } finally {
    loading.value = false
  }
}
</script>
